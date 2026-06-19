package test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/i2-open/i2goSignals/pkg/authSupport"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestReceiverResolvesTransmitterEndpointsViaWellKnown locks down the receiver's
// endpoint-resolution contract (commit 5a26e2e). The transmitter's status,
// verify, and delete URLs MUST come from its /.well-known/ssf-configuration
// document — not from URLs hard-coded around the goSignals layout — and each
// SUT-initiated call MUST identify the stream by the transmitter's stream_id
// (remote_stream_id), not by the receiver's local id.
//
// Before the fix the receiver fetched the well-known URL with the literal-form
// Fetch helper (no /.well-known insertion) and addressed remote calls with the
// LOCAL stream_id, so any transmitter whose endpoint layout differed from
// goSignals' own — including the OpenID SSF conformance suite — silently
// reported "stream not found" and broke discovery.
func TestReceiverResolvesTransmitterEndpointsViaWellKnown(t *testing.T) {
	// Enable the receiver-initiated management exercise so a single
	// synchronous call drives the read (GET configuration_endpoint) and
	// status update (POST status_endpoint) we want to observe.
	t.Setenv("I2SIG_RCV_MANAGEMENT_EXERCISE", "true")
	// Enable verify-on-establish so HandleReceiver fires a /verify against
	// the well-known-declared verification_endpoint as soon as the poll
	// receiver's runPollLoop starts (RemoteStreamId is set up front).
	t.Setenv("I2SIG_RCV_VERIFY_ON_ESTABLISH", "true")

	type captured struct {
		method   string
		path     string
		rawQuery string
		body     []byte
	}

	var mu sync.Mutex
	hits := map[string][]captured{}

	record := func(label string, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()
		mu.Lock()
		hits[label] = append(hits[label], captured{
			method:   r.Method,
			path:     r.URL.Path,
			rawQuery: r.URL.RawQuery,
			body:     body,
		})
		mu.Unlock()
	}

	// Non-default endpoint paths — deliberately unlike goSignals' own
	// /stream, /status, /verify layout — so a fallback that hard-codes paths
	// would miss them.
	const (
		configPath = "/tx-configuration-ep"
		statusPath = "/tx-status-ep"
		verifyPath = "/tx-verify-ep"
		jwksPath   = "/tx-jwks-ep"
	)

	var ts *httptest.Server
	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/.well-known/ssf-configuration"):
			// Spec discovery via RFC 8615 / SSF §7.2 insertion form. The
			// resolver under test must request this path — Fetch's literal
			// form would request the bare TxWellKnownUrl instead and never
			// reach this handler.
			record("well-known", r)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(model.TransmitterConfiguration{
				Issuer:                "https://tx.example.test",
				JwksUri:               ts.URL + jwksPath,
				ConfigurationEndpoint: ts.URL + configPath,
				StatusEndpoint:        ts.URL + statusPath,
				VerificationEndpoint:  ts.URL + verifyPath,
			})
		case r.URL.Path == configPath:
			record("config", r)
			// Respond 204 to all management-exercise verbs so each request
			// resolves without follow-up.
			w.WriteHeader(http.StatusNoContent)
		case r.URL.Path == statusPath:
			record("status", r)
			if r.Method == http.MethodGet {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(model.StreamStatus{Status: model.StreamStateEnabled})
				return
			}
			w.WriteHeader(http.StatusNoContent)
		case r.URL.Path == verifyPath:
			record("verify", r)
			w.WriteHeader(http.StatusNoContent)
		case r.URL.Path == jwksPath:
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"keys":[]}`))
		case r.URL.Path == "/poll":
			// Drain the receiver's poll loop with an empty response so it
			// doesn't error-storm against an unexpected path.
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(model.PollResponse{Sets: make(map[string]string)})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	instance, err := createServer(t, "receiver_endpoint_resolution_test", true)
	require.NoError(t, err)
	defer instance.app.Shutdown()

	wellKnownURL := ts.URL // bare host — the resolver must INSERT the
	// /.well-known/ssf-configuration component itself per RFC 8615.
	remoteId := "TX-REMOTE-STREAM-ID-9999"
	token := "tx-static-token"
	streamConfig := model.StreamConfiguration{
		Iss:             "https://tx.example.test",
		Aud:             []string{"https://receiver.example.test"},
		EventsRequested: []string{"*"},
		IssuerJWKSUrl:   ts.URL + jwksPath,
		TxWellKnownUrl:  &wellKnownURL,
		TxToken:         &token,
		// Distinct from the local id the SUT will assign — the test pins the
		// contract that remote calls quote THIS id, not the local one.
		// Setting RemoteStreamId on a ReceivePoll create also suppresses the
		// auto-registration POST so the test drives only the discovery /
		// status / verify / delete flows under test.
		RemoteStreamId: &remoteId,
		Delivery: &model.OneOfStreamConfigurationDelivery{
			PollReceiveMethod: &model.PollReceiveMethod{
				Method:      model.ReceivePoll,
				EndpointUrl: ts.URL + "/poll",
				PollConfig:  &model.PollParameters{ReturnImmediately: true},
			},
		},
	}

	created, err := instance.CreateStream(streamConfig, authSupport.ConvertProject(instance.projectId))
	require.NoError(t, err)
	require.NotEqual(t, remoteId, created.Id,
		"the SUT must assign its own local stream id; the test pins remote_stream_id != local id")
	require.NotNil(t, created.RemoteStreamId)
	require.Equal(t, remoteId, *created.RemoteStreamId,
		"RemoteStreamId must round-trip onto the persisted stream — every remote call below depends on it")

	state, err := instance.GetStreamState(created.Id)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Drive status read + verification by starting the poll receiver: its
	// runPollLoop performs a GET status_endpoint then POSTs to
	// verification_endpoint (verify-on-establish) before opening any poll.
	// Both calls resolve their URLs via well-known and identify the stream
	// by remote_stream_id under the contract under test.
	ps := instance.app.HandleReceiver(state)
	require.NotNil(t, ps)
	t.Cleanup(func() { instance.app.CloseReceiver(created.Id) })

	// Wait for the status GET and verify POST to land before driving the
	// synchronous callers. Without the wait the poll loop's pre-poll calls
	// race the assertions below.
	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(hits["status"]) > 0 && len(hits["verify"]) > 0
	}, 5*time.Second, 25*time.Millisecond,
		"poll receiver must drive a status GET and a verify POST against the well-known-declared endpoints")

	// Drive the management exercise (read/update/replace/status-update).
	// runPollLoop also calls this once per goroutine, but invoking it here
	// synchronously makes the test deterministic regardless of goroutine
	// scheduling.
	instance.app.ExerciseReceiverManagement(ctx, state)

	// Cascade DELETE on local deletion (SSF §8.1.1.5) hits the
	// configuration_endpoint with remote_stream_id as the query param.
	instance.app.CascadeReceiverStreamDelete(ctx, state)

	mu.Lock()
	defer mu.Unlock()

	// Well-known discovery must have been called — the resolver MUST use
	// FetchSSFConfiguration (insertion form) so a bare TxWellKnownUrl resolves
	// to /.well-known/ssf-configuration. Fetch's literal-URL form would have
	// requested the bare host instead.
	require.NotEmpty(t, hits["well-known"],
		"resolver must request /.well-known/ssf-configuration via the insertion-form helper")

	// configuration_endpoint should be hit at least twice: a GET read from
	// ExerciseReceiverManagement and a DELETE from the cascade. Every hit
	// must carry the REMOTE stream_id (in the query for GET/DELETE).
	configHits := hits["config"]
	require.NotEmpty(t, configHits,
		"configuration_endpoint discovered from /.well-known/ssf-configuration must receive at least one call")

	var sawGet, sawDelete bool
	for _, h := range configHits {
		// The local stream id must never leak — every call to the
		// configuration_endpoint identifies the stream by its remote id,
		// whether the id is carried in the URL query (GET / DELETE per
		// §8.1.1.2 / §8.1.1.5) or in the JSON body (PATCH / PUT per
		// §8.1.1.3 / §8.1.1.4).
		assert.NotContains(t, h.rawQuery, "stream_id="+created.Id,
			"%s %s must NOT quote the LOCAL stream_id in the query string", h.method, h.path)
		assert.NotContains(t, string(h.body), "\"stream_id\":\""+created.Id+"\"",
			"%s %s must NOT carry the LOCAL stream_id in the request body", h.method, h.path)
		switch h.method {
		case http.MethodGet, http.MethodDelete:
			// SSF §8.1.1.2 (read) and §8.1.1.5 (delete) identify the
			// stream by query param.
			assert.Contains(t, h.rawQuery, "stream_id="+remoteId,
				"%s %s must quote the REMOTE stream_id in the query string", h.method, h.path)
			if h.method == http.MethodGet {
				sawGet = true
			} else {
				sawDelete = true
			}
		case http.MethodPatch, http.MethodPut:
			// SSF §8.1.1.3 / §8.1.1.4 identify the stream in the body.
			assert.Contains(t, string(h.body), "\"stream_id\":\""+remoteId+"\"",
				"%s %s must carry the REMOTE stream_id in the request body", h.method, h.path)
		}
	}
	assert.True(t, sawGet,
		"receiver management exercise must read the stream config from the well-known configuration_endpoint")
	assert.True(t, sawDelete,
		"cascade DELETE (SSF §8.1.1.5) must target the well-known configuration_endpoint")

	// status_endpoint must receive both a GET (status read from
	// runPollLoop's handleTransmitterStatus) and a POST (status update from
	// the management exercise). The remote stream_id appears in the query
	// for GET and in the JSON body for POST.
	statusHits := hits["status"]
	require.NotEmpty(t, statusHits,
		"status_endpoint discovered from /.well-known/ssf-configuration must receive at least one call")
	var sawStatusGet, sawStatusPost bool
	for _, h := range statusHits {
		assert.NotContains(t, h.rawQuery, "stream_id="+created.Id,
			"%s %s must NOT quote the LOCAL stream_id in the query string", h.method, h.path)
		assert.NotContains(t, string(h.body), "\"stream_id\":\""+created.Id+"\"",
			"%s %s must NOT carry the LOCAL stream_id in the request body", h.method, h.path)
		switch h.method {
		case http.MethodGet:
			assert.Contains(t, h.rawQuery, "stream_id="+remoteId,
				"GET status_endpoint must quote the REMOTE stream_id in the query string")
			sawStatusGet = true
		case http.MethodPost:
			assert.Contains(t, string(h.body), "\"stream_id\":\""+remoteId+"\"",
				"POST status_endpoint body must carry the REMOTE stream_id")
			sawStatusPost = true
		}
	}
	assert.True(t, sawStatusGet,
		"poll receiver must read transmitter status via GET status_endpoint")
	assert.True(t, sawStatusPost,
		"management exercise must POST a status update to the well-known status_endpoint")

	// verification_endpoint receives the verify-on-establish POST. The
	// remote stream_id is carried in the JSON body (SSF §8.1.4.2 — verify
	// does NOT take stream_id as a query param).
	verifyHits := hits["verify"]
	require.NotEmpty(t, verifyHits,
		"verification_endpoint discovered from /.well-known/ssf-configuration must receive the verify-on-establish POST")
	for _, h := range verifyHits {
		assert.Equal(t, http.MethodPost, h.method,
			"verification endpoint is exercised by POST per SSF §8.1.4.2")
		assert.Contains(t, string(h.body), "\"stream_id\":\""+remoteId+"\"",
			"POST verification_endpoint body must carry the REMOTE stream_id")
		assert.NotContains(t, string(h.body), "\"stream_id\":\""+created.Id+"\"",
			"POST verification_endpoint body must NOT carry the LOCAL stream_id")
	}
}
