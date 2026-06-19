package test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/i2-open/i2goSignals/pkg/authSupport"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPollReceiverRequestsVerificationOnce pins down the behaviour added by
// commit 0dbcec2 ("SSF receiver: request stream verification from the
// transmitter on POLL"): once a POLL receiver's stream is confirmed enabled,
// the SUT must POST exactly one verification request to the transmitter's
// verification_endpoint (SSF 1.0 §8.1.4.2) for the life of the poll
// goroutine. Reverting that commit lets the polling loop run without ever
// asking the transmitter to verify — this test would then fail to observe a
// single verification call within the deadline.
func TestPollReceiverRequestsVerificationOnce(t *testing.T) {
	// Opt the polling receiver into requesting verification on stream
	// establishment. Defaults to off (services.RcvVerifyOnEstablishEnabled).
	t.Setenv("I2SIG_RCV_VERIFY_ON_ESTABLISH", "true")

	var (
		mu           sync.Mutex
		verifyCount  int
		verifyBodies [][]byte
		statusCount  int32
		pollCount    int32
	)

	// tsURL is captured after the test server is constructed so the
	// well-known response can advertise absolute endpoint URLs that resolve
	// back to this same mock transmitter.
	var tsURL string

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/.well-known/ssf-configuration":
			cfg := model.TransmitterConfiguration{
				Issuer:                "transmitter.example.com",
				JwksUri:               tsURL + "/jwks",
				ConfigurationEndpoint: tsURL + "/streams",
				StatusEndpoint:        tsURL + "/status",
				VerificationEndpoint:  tsURL + "/verify",
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(cfg)

		case r.URL.Path == "/jwks":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"keys":[]}`))

		case r.URL.Path == "/status" && r.Method == http.MethodGet:
			atomic.AddInt32(&statusCount, 1)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(model.StreamStatus{
				Status: model.StreamStateEnabled,
			})

		case r.URL.Path == "/verify" && r.Method == http.MethodPost:
			body, _ := io.ReadAll(r.Body)
			mu.Lock()
			verifyCount++
			verifyBodies = append(verifyBodies, body)
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)

		case strings.HasPrefix(r.URL.Path, "/poll") && r.Method == http.MethodPost:
			atomic.AddInt32(&pollCount, 1)
			// Slow the loop down enough that the verify count has plenty of
			// opportunity to climb past one if the one-shot guard breaks.
			time.Sleep(40 * time.Millisecond)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(model.PollResponse{Sets: map[string]string{}})

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	ts := httptest.NewServer(handler)
	defer ts.Close()
	tsURL = ts.URL

	instance, err := createServer(t, "rcv_poll_verify_once", true)
	require.NoError(t, err)
	defer instance.app.Shutdown()

	txWellKnown := ts.URL + "/.well-known/ssf-configuration"
	streamConfig := model.StreamConfiguration{
		Iss:            "transmitter.example.com",
		IssuerJWKSUrl:  ts.URL + "/jwks",
		TxWellKnownUrl: &txWellKnown,
		Delivery: &model.OneOfStreamConfigurationDelivery{
			PollReceiveMethod: &model.PollReceiveMethod{
				Method:      model.ReceivePoll,
				EndpointUrl: ts.URL + "/poll",
				PollConfig:  &model.PollParameters{ReturnImmediately: true},
			},
		},
	}

	createdConfig, err := instance.CreateStream(streamConfig, authSupport.ConvertProject(instance.projectId))
	require.NoError(t, err)
	defer func() { _ = instance.DeleteStream(createdConfig.Id) }()

	state, err := instance.GetStreamState(createdConfig.Id)
	require.NoError(t, err)
	ps := instance.app.HandleReceiver(state)
	require.NotNil(t, ps)

	// The poll goroutine fires the verification POST once it has observed a
	// status check returning ENABLED. Wait for the verify endpoint to be hit.
	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return verifyCount >= 1
	}, 3*time.Second, 25*time.Millisecond, "expected at least one POST to verification_endpoint")

	// Let the poll loop iterate several more times to confirm the one-shot
	// guard holds: even after many additional polls, verifyCount must stay 1.
	require.Eventually(t, func() bool {
		return atomic.LoadInt32(&pollCount) >= 5
	}, 3*time.Second, 25*time.Millisecond, "poll loop did not iterate enough to prove one-shot")

	mu.Lock()
	finalVerify := verifyCount
	finalBody := []byte(nil)
	if len(verifyBodies) > 0 {
		finalBody = verifyBodies[0]
	}
	mu.Unlock()
	assert.Equal(t, 1, finalVerify, "verification_endpoint must be called exactly once per poll goroutine")

	// SSF 1.0 §8.1.4.2 requires the verification request body to carry
	// stream_id so the transmitter can identify which stream to verify.
	// Reverting the same commit would also drop this field.
	if len(finalBody) > 0 {
		var params model.VerificationParameters
		if err := json.Unmarshal(finalBody, &params); err == nil {
			assert.NotEmpty(t, params.StreamId,
				"verification request body must include stream_id (SSF §8.1.4.2)")
		}
	}
}

// TestPollReceiverFallsBackToRegistrationToken pins down the fallback added
// by commit 53a218c ("SSF receiver: retain registration token when
// transmitter omits poll auth header"): when the transmitter's stream
// registration response does NOT carry authorization_header on the poll
// delivery (which RFC 8936 explicitly permits), the receiver must keep using
// the credential it registered with for all subsequent status, poll and
// delete-cascade calls — instead of blanking out the token and silently
// losing access. Reverting that commit causes the outbound Authorization
// header to drop the registration token, failing the per-call assertions
// below.
func TestPollReceiverFallsBackToRegistrationToken(t *testing.T) {
	const registrationToken = "reg-token-xyz"
	const expectedAuth = "Bearer " + registrationToken

	var (
		mu                sync.Mutex
		registrationCount int
		statusAuths       []string
		pollAuths         []string
		deleteAuths       []string
		remoteStreamID    string
	)

	var tsURL string

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/.well-known/ssf-configuration":
			cfg := model.TransmitterConfiguration{
				Issuer:                "transmitter.example.com",
				JwksUri:               tsURL + "/jwks",
				ConfigurationEndpoint: tsURL + "/streams",
				StatusEndpoint:        tsURL + "/status",
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(cfg)

		case r.URL.Path == "/jwks":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"keys":[]}`))

		case r.URL.Path == "/streams" && r.Method == http.MethodPost:
			// Registration must already carry the credential the caller is
			// registering with — RFC 8936 §2.1.
			assert.Equal(t, expectedAuth, r.Header.Get("Authorization"),
				"registration must carry the caller's bearer token")
			var req model.StreamConfiguration
			_ = json.NewDecoder(r.Body).Decode(&req)
			mu.Lock()
			registrationCount++
			// Synthesise a transmitter-side stream id distinct from the
			// receiver's local id so the cascade DELETE clearly targets the
			// remote id (SSF §8.1.1.5).
			remoteStreamID = "tx-stream-id-1"
			mu.Unlock()
			// Echo back a complete poll-transmit delivery — but deliberately
			// OMIT authorization_header. This is the scenario the fix covers
			// (RFC 8936 permits an empty AuthorizationHeader; the receiver
			// must keep using its registration credential).
			resp := model.StreamConfiguration{
				Id:              remoteStreamID,
				Iss:             "transmitter.example.com",
				Aud:             []string{"https://receiver.example.com"},
				EventsRequested: req.EventsRequested,
				EventsDelivered: req.EventsRequested,
				Delivery: &model.OneOfStreamConfigurationDelivery{
					PollTransmitMethod: &model.PollTransmitMethod{
						Method:      model.DeliveryPoll,
						EndpointUrl: tsURL + "/poll",
						// AuthorizationHeader intentionally left empty.
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(resp)

		case r.URL.Path == "/status" && r.Method == http.MethodGet:
			mu.Lock()
			statusAuths = append(statusAuths, r.Header.Get("Authorization"))
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(model.StreamStatus{
				Status: model.StreamStateEnabled,
			})

		case strings.HasPrefix(r.URL.Path, "/poll") && r.Method == http.MethodPost:
			mu.Lock()
			pollAuths = append(pollAuths, r.Header.Get("Authorization"))
			mu.Unlock()
			time.Sleep(40 * time.Millisecond)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(model.PollResponse{Sets: map[string]string{}})

		case r.URL.Path == "/streams" && r.Method == http.MethodDelete:
			mu.Lock()
			deleteAuths = append(deleteAuths, r.Header.Get("Authorization"))
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	ts := httptest.NewServer(handler)
	defer ts.Close()
	tsURL = ts.URL

	instance, err := createServer(t, "rcv_poll_token_fallback", true)
	require.NoError(t, err)
	defer instance.app.Shutdown()

	// Trigger the auto-registration path: TxWellKnownUrl + TxToken set in
	// the request causes StreamService.CreateStream to POST to the
	// transmitter's configuration_endpoint. That is exactly the response-
	// handling branch where the fix lives.
	txWellKnown := ts.URL + "/.well-known/ssf-configuration"
	txToken := registrationToken
	streamConfig := model.StreamConfiguration{
		Iss:             "transmitter.example.com",
		Aud:             []string{"https://receiver.example.com"},
		IssuerJWKSUrl:   ts.URL + "/jwks",
		EventsRequested: []string{"*"},
		TxWellKnownUrl:  &txWellKnown,
		TxToken:         &txToken,
		Delivery: &model.OneOfStreamConfigurationDelivery{
			PollReceiveMethod: &model.PollReceiveMethod{
				Method:     model.ReceivePoll,
				PollConfig: &model.PollParameters{ReturnImmediately: true},
			},
		},
	}

	createdConfig, err := instance.CreateStream(streamConfig, authSupport.ConvertProject(instance.projectId))
	require.NoError(t, err, "auto-registration against the mock transmitter must succeed")

	mu.Lock()
	require.Equal(t, 1, registrationCount, "transmitter must have observed exactly one registration POST")
	mu.Unlock()

	// The receiver should be polling now. Drive the runtime loop.
	state, err := instance.GetStreamState(createdConfig.Id)
	require.NoError(t, err)
	require.NotNil(t, state.StreamConfiguration.RemoteStreamId,
		"RemoteStreamId must be persisted from the transmitter's response so the cascade delete can target it")

	ps := instance.app.HandleReceiver(state)
	require.NotNil(t, ps)

	// Wait for a successful status GET and at least one poll POST.
	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(statusAuths) >= 1 && len(pollAuths) >= 1
	}, 3*time.Second, 25*time.Millisecond, "expected at least one status GET and one poll POST against the mock transmitter")

	// Now trigger the cascade DELETE through the management API. The handler
	// calls CascadeReceiverStreamDelete before tearing down the local stream
	// (api_stream_management.go:327).
	delReq, err := http.NewRequest(http.MethodDelete,
		instance.ts.URL+"/stream?stream_id="+createdConfig.Id, nil)
	require.NoError(t, err)
	delReq.Header.Set("Authorization", "Bearer "+instance.streamMgmtToken)
	delResp, err := instance.client.Do(delReq)
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, delResp.Body)
	_ = delResp.Body.Close()
	require.Equal(t, http.StatusNoContent, delResp.StatusCode,
		"DELETE /stream must succeed locally; cascade is best-effort")

	// The cascade DELETE goes to the transmitter's configuration_endpoint
	// (/streams) with stream_id of the REMOTE stream. Wait for it.
	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(deleteAuths) >= 1
	}, 3*time.Second, 25*time.Millisecond, "expected at least one cascade DELETE against the mock transmitter")

	mu.Lock()
	statusCopy := append([]string(nil), statusAuths...)
	pollCopy := append([]string(nil), pollAuths...)
	deleteCopy := append([]string(nil), deleteAuths...)
	mu.Unlock()

	// Every outbound call must carry the original registration credential.
	// Reverting the fix blanks out config.TxToken; the static-token client
	// then either omits Authorization entirely or sends "Bearer " with no
	// token — either way the asserted equality fails.
	for i, auth := range statusCopy {
		assert.Equal(t, expectedAuth, auth,
			"status GET #%d must carry the registration token", i)
	}
	for i, auth := range pollCopy {
		assert.Equal(t, expectedAuth, auth,
			"poll POST #%d must carry the registration token", i)
	}
	for i, auth := range deleteCopy {
		assert.Equal(t, expectedAuth, auth,
			"cascade DELETE #%d must carry the registration token", i)
	}
}
