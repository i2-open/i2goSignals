package test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/i2-open/i2goSignals/pkg/authSupport"
	"github.com/i2-open/i2goSignals/pkg/goSetValidate"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// evPollReport is one RFC8936 poll request's acknowledgement payload, as observed
// by the fake transmitter. The receiver batches acks/setErrs and sends them on the
// FOLLOWING poll, so the assertions accumulate across requests.
type evPollReport struct {
	Acks    []string                        `json:"ack"`
	SetErrs map[string]evPollSetErrTypeJson `json:"setErrs"`
}

type evPollSetErrTypeJson struct {
	Error       string `json:"err"`
	Description string `json:"description"`
}

// evFakeTransmitter serves one batch of SETs on the first poll and empty
// responses afterwards, recording every acknowledgement payload it is sent.
type evFakeTransmitter struct {
	mu      sync.Mutex
	served  bool
	acked   map[string]bool
	setErrs map[string]evPollSetErrTypeJson
	url     string
}

func newEvFakeTransmitter(t *testing.T, batch map[string]string) *evFakeTransmitter {
	t.Helper()
	tx := &evFakeTransmitter{
		acked:   map[string]bool{},
		setErrs: map[string]evPollSetErrTypeJson{},
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var report evPollReport
		_ = json.NewDecoder(r.Body).Decode(&report)

		tx.mu.Lock()
		for _, jti := range report.Acks {
			tx.acked[jti] = true
		}
		for jti, setErr := range report.SetErrs {
			tx.setErrs[jti] = setErr
		}
		// Only claim the one-shot batch once the test has finished filling it: the
		// SETs carry the stream id in sub_id, so they cannot be built until the
		// stream exists, by which time the receive loop may already be polling.
		sets := map[string]string{}
		if !tx.served && len(batch) > 0 {
			tx.served = true
			for jti, token := range batch {
				sets[jti] = token
			}
		}
		tx.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"sets": sets})
	}))
	t.Cleanup(server.Close)
	tx.url = server.URL
	return tx
}

func (tx *evFakeTransmitter) snapshot() (map[string]bool, map[string]evPollSetErrTypeJson) {
	tx.mu.Lock()
	defer tx.mu.Unlock()
	acked := make(map[string]bool, len(tx.acked))
	for k, v := range tx.acked {
		acked[k] = v
	}
	setErrs := make(map[string]evPollSetErrTypeJson, len(tx.setErrs))
	for k, v := range tx.setErrs {
		setErrs[k] = v
	}
	return acked, setErrs
}

// createEvPollReceiver creates an RFC8936 poll receiver stream with the given
// event_validation mode and starts its receive loop.
func createEvPollReceiver(t *testing.T, instance *ssfInstance, jwksUrl, endpointUrl string, mode model.EventValidationMode) model.StreamConfiguration {
	t.Helper()
	atx := &authSupport.AuthContext{ProjectId: instance.projectId}
	ctx := context.WithValue(context.Background(), authSupport.AuthContextKey, atx)

	created, err := instance.streamSvc().CreateStream(ctx, model.StreamStateRecord{
		StreamConfiguration: model.StreamConfiguration{
			Iss:             evIssuer,
			Aud:             []string{evAudience},
			IssuerJWKSUrl:   jwksUrl,
			EventsRequested: []string{"*"},
			RouteMode:       model.RouteModeImport,
			Delivery: &model.OneOfStreamConfigurationDelivery{
				PollReceiveMethod: &model.PollReceiveMethod{
					Method:      model.ReceivePoll,
					EndpointUrl: endpointUrl,
					PollConfig:  &model.PollParameters{ReturnImmediately: true},
				},
			},
		},
		EventValidation: mode,
	}, instance.projectId, nil)
	require.NoError(t, err)

	state, err := instance.GetStreamState(created.Id)
	require.NoError(t, err)
	require.Equal(t, mode, state.EventValidation, "the per-stream mode must persist")

	ps := instance.app.HandleReceiver(state)
	require.NotNil(t, ps)
	t.Cleanup(func() { instance.app.CloseReceiver(created.Id) })
	return created
}

// TestPollEventValidationModeMatrix is the thin per-transport integration pass
// over the #247 matrix on RFC8936 poll. The observable is the acknowledgement
// payload of the FOLLOWING poll: a rejected jti lands in setErrs with
// invalid_request and is never acked, while the rest of the same batch acks
// normally.
func TestPollEventValidationModeMatrix(t *testing.T) {
	instance, err := createServer(t, "poll_event_validation_test", true)
	require.NoError(t, err)
	defer func() {
		if instance.ts != nil {
			instance.ts.Close()
		}
		instance.app.Shutdown()
	}()

	signingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	jwksUrl := evJwksServer(t, signingKey)

	cases := []struct {
		mode model.EventValidationMode
		// which SET shapes end up in setErrs instead of being acked
		rejectMalformed   bool
		rejectUnsupported bool
	}{
		{model.EventValidationNone, false, false},
		{model.EventValidationWarn, false, false},
		{model.EventValidationEnforce, true, false},
		{model.EventValidationStrict, true, true},
	}

	for _, tc := range cases {
		t.Run(string(tc.mode), func(t *testing.T) {
			// The SETs must carry the stream id in their sub_id, so the batch can
			// only be built once the stream exists — and the stream needs the
			// transmitter's URL. The transmitter therefore reads a map the test
			// fills in afterwards, and holds the batch back until it is non-empty.
			batch := map[string]string{}
			tx := newEvFakeTransmitter(t, batch)
			stream := createEvPollReceiver(t, instance, jwksUrl, tx.url, tc.mode)

			validJti, validToken := evSignedSet(t, signingKey, stream.Id, evValidPayload)
			malformedJti, malformedToken := evSignedSet(t, signingKey, stream.Id, evMalformedPayload)
			unsupportedJti, unsupportedToken := evSignedSet(t, signingKey, stream.Id, evUnsupportedPayload)

			tx.mu.Lock()
			batch[validJti] = validToken
			batch[malformedJti] = malformedToken
			batch[unsupportedJti] = unsupportedToken
			tx.mu.Unlock()

			// Wait until the receiver has disposed of every jti one way or the
			// other — acks and setErrs both ride the FOLLOWING poll, so nothing
			// below is meaningful before that second request lands.
			require.Eventually(t, func() bool {
				acked, setErrs := tx.snapshot()
				for _, jti := range []string{validJti, malformedJti, unsupportedJti} {
					if !acked[jti] {
						if _, reported := setErrs[jti]; !reported {
							return false
						}
					}
				}
				return true
			}, 10*time.Second, 50*time.Millisecond,
				"the receiver must ack or report every jti in the batch")

			acked, setErrs := tx.snapshot()

			// A well-formed SSF verification event is Valid in every mode, and is
			// always in contract even on a narrowly scoped STRICT stream.
			assert.True(t, acked[validJti], "a valid SET acks under %s", tc.mode)
			assert.NotContains(t, setErrs, validJti)

			assertDisposition := func(jti, shape string, reject bool) {
				if reject {
					require.Contains(t, setErrs, jti, "%s must be reported in setErrs under %s", shape, tc.mode)
					assert.Equal(t, "invalid_request", setErrs[jti].Error)
					assert.NotEmpty(t, setErrs[jti].Description)
					assert.False(t, acked[jti], "a rejected jti must not be acked")
				} else {
					assert.True(t, acked[jti], "%s acks under %s", shape, tc.mode)
					assert.NotContains(t, setErrs, jti)
				}
			}
			assertDisposition(malformedJti, "a malformed payload", tc.rejectMalformed)
			assertDisposition(unsupportedJti, "an out-of-contract URI", tc.rejectUnsupported)

			if tc.rejectMalformed {
				assert.Contains(t, setErrs[malformedJti].Description, goSetValidate.SsfStreamUpdatedEventUri,
					"the setErrs description names the offending event URI")
				assert.Contains(t, setErrs[malformedJti].Description, "status",
					"the setErrs description names the failing claim")
			}
			if tc.rejectUnsupported {
				assert.Contains(t, setErrs[unsupportedJti].Description, evRiscUri)
			}
		})
	}

	stats := instance.app.Stats
	require.NotNil(t, stats)
	assert.Positive(t, testutil.ToFloat64(
		stats.EventValidations.WithLabelValues("malformed", "WARN", "poll")),
		"WARN acks the malformed SET on the wire but must still count it")
	assert.Positive(t, testutil.ToFloat64(
		stats.EventValidations.WithLabelValues("malformed", "ENFORCE", "poll")))
	assert.Positive(t, testutil.ToFloat64(
		stats.EventValidations.WithLabelValues("unsupported", "STRICT", "poll")))
	assert.Equal(t, 0.0, testutil.ToFloat64(
		stats.EventValidations.WithLabelValues("valid", "NONE", "poll")),
		"NONE engages no validators, so it records nothing")
}

// TestPollEventValidationDefaultIsUnchanged pins the AC that an unset mode leaves
// the poll receiver on exactly its pre-#247 behavior: a SET that ENFORCE would
// report in setErrs is acked instead.
func TestPollEventValidationDefaultIsUnchanged(t *testing.T) {
	instance, err := createServer(t, "poll_event_validation_default_test", true)
	require.NoError(t, err)
	defer func() {
		if instance.ts != nil {
			instance.ts.Close()
		}
		instance.app.Shutdown()
	}()

	signingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	jwksUrl := evJwksServer(t, signingKey)

	batch := map[string]string{}
	tx := newEvFakeTransmitter(t, batch)
	stream := createEvPollReceiver(t, instance, jwksUrl, tx.url, model.EventValidationUnset)

	malformedJti, malformedToken := evSignedSet(t, signingKey, stream.Id, evMalformedPayload)
	tx.mu.Lock()
	batch[malformedJti] = malformedToken
	tx.mu.Unlock()

	require.Eventually(t, func() bool {
		acked, _ := tx.snapshot()
		return acked[malformedJti]
	}, 10*time.Second, 50*time.Millisecond,
		"an unset event_validation mode must not change poll receive behavior")

	_, setErrs := tx.snapshot()
	assert.NotContains(t, setErrs, malformedJti)
}
