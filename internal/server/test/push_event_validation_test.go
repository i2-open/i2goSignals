package test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/i2-open/i2goSignals/pkg/authSupport"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/goSetValidate"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	evKid      = "event-validation-kid"
	evIssuer   = "https://ev-transmitter.example.com"
	evRiscUri  = "https://schemas.openid.net/secevent/risc/event-type/account-disabled"
	evAudience = "https://ev-receiver.example.com"
)

// evJwksServer stands up a JWKS endpoint for the public half of key, under evKid.
func evJwksServer(t *testing.T, key *rsa.PrivateKey) string {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(signingOnlyJWKSBytes(t, evKid, &key.PublicKey))
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server.URL + "/jwks.json"
}

// evSignedSet signs a SET carrying the SSF stream-management envelope (top-level
// opaque sub_id = streamId) plus whatever payloads addPayloads attaches.
func evSignedSet(t *testing.T, key *rsa.PrivateKey, streamId string, addPayloads func(*goSet.SecurityEventToken)) (string, string) {
	t.Helper()
	set := goSet.CreateSet(nil, evIssuer, []string{evAudience})
	set.Kid = evKid
	set.SubjectId = &goSet.SubjectIdentifier{
		Format:           "opaque",
		OpaqueIdentifier: goSet.OpaqueIdentifier{Id: streamId},
	}
	addPayloads(&set)
	signed, err := set.JWS(jwt.SigningMethodRS256, key)
	require.NoError(t, err)
	return set.ID, signed
}

// The four SET shapes that make up one row each of the #247 mode × disposition
// matrix. The engaged validators here are the two SSF stream-management ones,
// which NewValidatorSet always engages.
func evValidPayload(s *goSet.SecurityEventToken) {
	s.AddEventPayload(goSetValidate.SsfVerificationEventUri, map[string]any{"state": "ev-state"})
}

func evMalformedPayload(s *goSet.SecurityEventToken) {
	// "status" is REQUIRED and must be one of the SSF §8.1.2 values.
	s.AddEventPayload(goSetValidate.SsfStreamUpdatedEventUri, map[string]any{"status": "not-a-status"})
}

func evUnsupportedPayload(s *goSet.SecurityEventToken) {
	s.AddEventPayload(evRiscUri, map[string]any{"reason": "event-validation matrix"})
}

func evMixedPayload(s *goSet.SecurityEventToken) {
	evValidPayload(s)
	evUnsupportedPayload(s)
}

// createEvPushReceiver creates a signing-only RFC8935 push receiver stream with
// the given event_validation mode. Signing-only means the SET's JWS is the trust
// gate, so the matrix can be driven with no bearer token.
func createEvPushReceiver(t *testing.T, instance *ssfInstance, jwksUrl string, mode model.EventValidationMode) model.StreamConfiguration {
	t.Helper()
	atx := &authSupport.AuthContext{ProjectId: instance.projectId}
	ctx := context.WithValue(context.Background(), authSupport.AuthContextKey, atx)

	// CreateStream is called directly rather than through POST /stream because
	// event_validation is a goSignals operator knob on StreamStateRecord and is
	// deliberately absent from the SSF wire-format StreamConfiguration.
	created, err := instance.streamSvc().CreateStream(ctx, model.StreamStateRecord{
		StreamConfiguration: model.StreamConfiguration{
			Iss:             evIssuer,
			Aud:             []string{evAudience},
			IssuerJWKSUrl:   jwksUrl,
			SigningOnly:     true,
			EventsRequested: []string{"*"},
			RouteMode:       model.RouteModeImport,
			Delivery: &model.OneOfStreamConfigurationDelivery{
				PushReceiveMethod: &model.PushReceiveMethod{Method: model.ReceivePush},
			},
		},
		EventValidation: mode,
	}, instance.projectId, nil)
	require.NoError(t, err)

	state, err := instance.GetStreamState(created.Id)
	require.NoError(t, err)
	require.Equal(t, mode, state.EventValidation, "the per-stream mode must persist")
	require.NotEmpty(t, created.Delivery.PushReceiveMethod.EndpointUrl)
	return created
}

// TestPushEventValidationModeMatrix is the thin per-transport integration pass
// over the #247 matrix on RFC8935 push: exactly the wire outcomes, with the
// combinatorial claim coverage left in the pkg/goSetValidate and
// internal/server unit seams.
func TestPushEventValidationModeMatrix(t *testing.T) {
	instance, err := createServer(t, "push_event_validation_test", true)
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

	// postSet delivers a SET to a signing-only push endpoint with no bearer.
	postSet := func(t *testing.T, endpoint, token string) (int, string) {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(token))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/secevent+jwt")
		resp, err := instance.client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(body)
	}

	cases := []struct {
		mode model.EventValidationMode
		// wantStatus keyed by SET shape.
		valid, malformed, unsupported, mixed int
	}{
		// NONE — behaviorally identical to today's forwarding.
		{model.EventValidationNone, http.StatusAccepted, http.StatusAccepted, http.StatusAccepted, http.StatusAccepted},
		// WARN — wire-invisible; malformed is logged and still accepted.
		{model.EventValidationWarn, http.StatusAccepted, http.StatusAccepted, http.StatusAccepted, http.StatusAccepted},
		// ENFORCE — recognized-but-malformed rejects; unsupported forwards.
		{model.EventValidationEnforce, http.StatusAccepted, http.StatusBadRequest, http.StatusAccepted, http.StatusAccepted},
		// STRICT — firewall: unsupported rejects too, and the mixed SET whole.
		{model.EventValidationStrict, http.StatusAccepted, http.StatusBadRequest, http.StatusBadRequest, http.StatusBadRequest},
	}

	for _, tc := range cases {
		t.Run(string(tc.mode), func(t *testing.T) {
			stream := createEvPushReceiver(t, instance, jwksUrl, tc.mode)
			endpoint := stream.Delivery.PushReceiveMethod.EndpointUrl

			shapes := []struct {
				name       string
				payload    func(*goSet.SecurityEventToken)
				wantStatus int
			}{
				{"valid", evValidPayload, tc.valid},
				{"malformed", evMalformedPayload, tc.malformed},
				{"unsupported", evUnsupportedPayload, tc.unsupported},
				{"mixed", evMixedPayload, tc.mixed},
			}

			for _, shape := range shapes {
				t.Run(shape.name, func(t *testing.T) {
					_, token := evSignedSet(t, signingKey, stream.Id, shape.payload)
					status, body := postSet(t, endpoint, token)
					require.Equal(t, shape.wantStatus, status, "body: %s", body)

					if status != http.StatusBadRequest {
						return
					}

					// A rejected SET must carry the RFC8935 §2.4 invalid_request
					// code. Reaching this branch is also how we know the SET never
					// reached the event router: the only other post-parse 400 on
					// this handler is HandleEvent's "Unexpected error:" body, and
					// a routed SET answers 202.
					var deliveryErr struct {
						Err         string `json:"err"`
						Description string `json:"description"`
					}
					require.NoError(t, json.Unmarshal([]byte(body), &deliveryErr))
					assert.Equal(t, "invalid_request", deliveryErr.Err)

					switch shape.name {
					case "malformed":
						assert.Contains(t, deliveryErr.Description, goSetValidate.SsfStreamUpdatedEventUri,
							"the description names the offending event URI")
						assert.Contains(t, deliveryErr.Description, "status",
							"the description names the failing claim")
					default:
						assert.Contains(t, deliveryErr.Description, evRiscUri,
							"the description names the out-of-contract event URI")
					}
				})
			}
		})
	}

	// The counter is labeled disposition × mode × transport and is the only
	// machine-readable signal a WARN rollout produces.
	stats := instance.app.Stats
	require.NotNil(t, stats)
	require.NotNil(t, stats.EventValidations)
	assert.Equal(t, 1.0, testutil.ToFloat64(
		stats.EventValidations.WithLabelValues("malformed", "WARN", "push")),
		"WARN accepted the malformed SET on the wire but must still count it")
	assert.Equal(t, 1.0, testutil.ToFloat64(
		stats.EventValidations.WithLabelValues("malformed", "ENFORCE", "push")))
	assert.Equal(t, 2.0, testutil.ToFloat64(
		stats.EventValidations.WithLabelValues("unsupported", "STRICT", "push")),
		"STRICT saw the unsupported SET and the mixed SET (worst disposition wins)")
	assert.Equal(t, 0.0, testutil.ToFloat64(
		stats.EventValidations.WithLabelValues("valid", "NONE", "push")),
		"NONE engages no validators, so it records nothing")
}

// TestPushEventValidationDefaultIsUnchanged pins the AC that an unset mode leaves
// the push receiver on exactly its pre-#247 behavior: no validation runs, so a SET
// that ENFORCE would reject is still accepted.
func TestPushEventValidationDefaultIsUnchanged(t *testing.T) {
	instance, err := createServer(t, "push_event_validation_default_test", true)
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

	stream := createEvPushReceiver(t, instance, jwksUrl, model.EventValidationUnset)
	assert.Equal(t, model.EventValidationNone,
		instance.streamSvc().EventValidationDefault(),
		"the server default is NONE unless I2SIG_STREAM_EVENT_VALIDATION says otherwise")

	_, token := evSignedSet(t, signingKey, stream.Id, evMalformedPayload)
	req, err := http.NewRequest(http.MethodPost,
		stream.Delivery.PushReceiveMethod.EndpointUrl, strings.NewReader(token))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/secevent+jwt")
	resp, err := instance.client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusAccepted, resp.StatusCode,
		"an unset event_validation mode must not change push receive behavior")
}
