package goSsfUtils

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetStreamConfig(t *testing.T) {
	expectedConfig := &model.StreamConfiguration{
		Iss: "test-iss",
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/config", r.URL.Path)
		assert.Equal(t, "stream123", r.URL.Query().Get("stream_id"))
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(expectedConfig)
	}))
	defer ts.Close()

	server := &model.Server{
		ServerConfiguration: &model.TransmitterConfiguration{
			ConfigurationEndpoint: ts.URL + "/config",
		},
	}

	config, err := GetStreamConfig(context.Background(), ts.Client(), server, "stream123")
	assert.NoError(t, err)
	assert.Equal(t, expectedConfig.Iss, config.Iss)
}

func TestGetStreamStatus(t *testing.T) {
	expectedStatus := &model.StreamStatus{
		Status: "enabled",
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/status", r.URL.Path)
		assert.Equal(t, "stream123", r.URL.Query().Get("stream_id"))
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(expectedStatus)
	}))
	defer ts.Close()

	server := &model.Server{
		ServerConfiguration: &model.TransmitterConfiguration{
			StatusEndpoint: ts.URL + "/status",
		},
	}

	status, err := GetStreamStatus(context.Background(), ts.Client(), server, "stream123")
	assert.NoError(t, err)
	assert.Equal(t, expectedStatus.Status, status.Status)
}

func TestGetVerificationEndpoint(t *testing.T) {
	expectedEndpoint := "https://example.com/verify"
	server := &model.Server{
		ServerConfiguration: &model.TransmitterConfiguration{
			VerificationEndpoint: expectedEndpoint,
		},
	}

	endpoint, err := GetVerificationEndpoint(context.Background(), http.DefaultClient, server)
	assert.NoError(t, err)
	assert.Equal(t, expectedEndpoint, endpoint)
}

func TestPostVerification(t *testing.T) {
	params := model.VerificationParameters{
		State: "test-state",
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/verify", r.URL.Path)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		var receivedParams model.VerificationParameters
		err := json.NewDecoder(r.Body).Decode(&receivedParams)
		assert.NoError(t, err)
		assert.Equal(t, params.State, receivedParams.State)

		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()

	err := PostVerification(context.Background(), ts.Client(), ts.URL+"/verify", params)
	assert.NoError(t, err)
}

func TestPostVerificationUnauthorized(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer ts.Close()

	err := PostVerification(context.Background(), ts.Client(), ts.URL+"/verify", model.VerificationParameters{})
	assert.Error(t, err)
	assert.Equal(t, "unauthorized", err.Error())
}

// TestCreateSstpPair_BootstrapPostsToStreamEndpoint pins Seam 4 (PRD #49 slice
// 3): CreateSstpPair marshals the SstpPairBootstrap and POSTs it to the peer's
// configuration endpoint (POST /stream); the server discriminates the body via
// model.IsSstpBootstrapBody and dispatches to createSstpPairHandler. The
// httptest peer asserts each on-wire property: method, path, discrimination
// signal in the body, then returns a 201 with a bidirectional
// StreamStateRecord (PairId, SstpInbound, SstpMethod) that the caller decodes
// verbatim.
func TestCreateSstpPair_BootstrapPostsToStreamEndpoint(t *testing.T) {
	const (
		pairId   = "pair-abc"
		txSid    = "tx-abc"
		rxSid    = "rx-abc"
		endpoint = "https://peer.example/sstp/pair-abc"
	)

	bootstrap := model.SstpPairBootstrap{
		Role:            model.SstpRoleInitiator,
		PeerServerAlias: "peer-1",
		Primary: model.SstpDirection{
			Iss: "https://local.example",
			Aud: []string{"https://peer.example"},
		},
		Inbound: model.SstpDirection{
			Iss: "https://peer.example",
			Aud: []string{"https://local.example"},
		},
	}

	returnRecord := model.StreamStateRecord{
		StreamConfiguration: model.StreamConfiguration{Id: txSid},
		PairId:              pairId,
		SstpInbound:         &model.StreamConfiguration{Id: rxSid},
		SstpMethod: &model.SstpMethod{
			Role:                model.SstpRoleInitiator,
			EndpointUrl:         endpoint,
			AuthorizationHeader: "Bearer pair-bearer",
		},
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method, "CreateSstpPair must POST")
		assert.Equal(t, "/stream", r.URL.Path,
			"CreateSstpPair must POST to the peer's configuration endpoint (POST /stream)")
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"),
			"CreateSstpPair must set Content-Type: application/json")

		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		assert.True(t, model.IsSstpBootstrapBody(body),
			"POST body must satisfy IsSstpBootstrapBody so the server dispatches to createSstpPairHandler")

		var decoded model.SstpPairBootstrap
		require.NoError(t, json.Unmarshal(body, &decoded))
		assert.Equal(t, bootstrap.PeerServerAlias, decoded.PeerServerAlias,
			"the peer must receive PeerServerAlias verbatim so it can resolve TLS/OAuth transport posture")
		assert.Equal(t, bootstrap.Primary.Iss, decoded.Primary.Iss)
		assert.Equal(t, bootstrap.Inbound.Iss, decoded.Inbound.Iss)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(returnRecord)
	}))
	defer ts.Close()

	server := &model.Server{
		ServerConfiguration: &model.TransmitterConfiguration{
			ConfigurationEndpoint: ts.URL + "/stream",
		},
	}

	rec, err := CreateSstpPair(context.Background(), ts.Client(), server, bootstrap)
	require.NoError(t, err)
	require.NotNil(t, rec)
	assert.Equal(t, pairId, rec.PairId, "returned StreamStateRecord carries the PairId")
	require.NotNil(t, rec.SstpInbound)
	assert.Equal(t, rxSid, rec.SstpInbound.Id, "returned SstpInbound carries the rx-side SID")
	require.NotNil(t, rec.SstpMethod)
	assert.Equal(t, endpoint, rec.SstpMethod.EndpointUrl,
		"returned SstpMethod carries the derived EndpointUrl the caller (and cascading peer) can dial")
}

// TestCreateSstpPair_PropagatesPeerErrorStatus: a peer 4xx/5xx must not be
// silently swallowed — the caller sees the status and the body snippet so an
// operator can diagnose an unauthorized-cascade, a schema-error, or a bad
// PeerServerAlias without a second round-trip.
func TestCreateSstpPair_PropagatesPeerErrorStatus(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("cascade denied: caller lacks admin scope"))
	}))
	defer ts.Close()

	server := &model.Server{
		ServerConfiguration: &model.TransmitterConfiguration{
			ConfigurationEndpoint: ts.URL + "/stream",
		},
	}

	_, err := CreateSstpPair(context.Background(), ts.Client(), server, model.SstpPairBootstrap{
		Role:    model.SstpRoleInitiator,
		Primary: model.SstpDirection{Iss: "https://local.example"},
		Inbound: model.SstpDirection{Iss: "https://peer.example"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "403", "error must carry the peer's status")
	assert.Contains(t, err.Error(), "cascade denied", "error must include a snippet of the peer's body for operator diagnosis")
}

// TestCreateSstpPair_NilClient rejects a nil HTTP client — the caller must
// resolve the credential chain (OAuth / per-pair bearer) BEFORE calling
// CreateSstpPair; a nil client cannot carry the pair-create authorization.
func TestCreateSstpPair_NilClient(t *testing.T) {
	_, err := CreateSstpPair(context.Background(), nil, &model.Server{}, model.SstpPairBootstrap{})
	require.Error(t, err)
	assert.Contains(t, strings.ToLower(err.Error()), "nil")
}

// TestGetStreamStatus_TwoCallsCoverBothPairDirections pins Seam 4 AC 6: NO new
// per-direction status helper is added — the two existing GetStreamStatus calls
// (txSid == rec.PairId, rxSid == rec.SstpInbound.Id) satisfy the surface, and
// the per-pair bearer covers BOTH SIDs by construction
// (IssueSstpPairToken(pairId, inboundSid, …)). This test exercises that shape:
// one client (representing the per-pair bearer's transport) drives two
// GetStreamStatus calls and both succeed.
func TestGetStreamStatus_TwoCallsCoverBothPairDirections(t *testing.T) {
	const (
		pairId = "pair-two"
		rxSid  = "rx-two"
		bearer = "Bearer per-pair-token"
	)

	var authSeen atomic.Int32
	statusByStreamId := map[string]*model.StreamStatus{
		pairId: {Status: "enabled"},        // tx side
		rxSid:  {Status: "enabled"},        // rx side
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/status", r.URL.Path)
		assert.Equal(t, bearer, r.Header.Get("Authorization"),
			"the per-pair bearer must reach BOTH direction reads on the same transport")
		authSeen.Add(1)

		streamId := r.URL.Query().Get("stream_id")
		status, ok := statusByStreamId[streamId]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(status)
	}))
	defer ts.Close()

	// A single HTTP client whose RoundTripper stamps the per-pair bearer — the
	// production credential chain (2b) resolves exactly this shape when a
	// pair's AuthorizationHeader is set. Both direction reads go through this
	// one client, proving one bearer covers both SIDs.
	client := &http.Client{
		Transport: bearerRoundTripper{next: ts.Client().Transport, header: bearer},
	}
	server := &model.Server{
		ServerConfiguration: &model.TransmitterConfiguration{
			StatusEndpoint: ts.URL + "/status",
		},
	}

	// AC 6: per-direction state = existing GetStreamStatus called TWICE.
	tx, err := GetStreamStatus(context.Background(), client, server, pairId)
	require.NoError(t, err)
	assert.Equal(t, "enabled", tx.Status, "tx-side status via GetStreamStatus(pairId)")

	rx, err := GetStreamStatus(context.Background(), client, server, rxSid)
	require.NoError(t, err)
	assert.Equal(t, "enabled", rx.Status, "rx-side status via GetStreamStatus(SstpInbound.Id)")

	assert.Equal(t, int32(2), authSeen.Load(),
		"exactly two status requests — one per direction — and both carried the per-pair bearer")
}

// bearerRoundTripper is a minimal http.RoundTripper that adds a fixed
// Authorization header to each request before delegating. It stands in for the
// production credential-chain-resolved client whose transport carries a
// per-pair bearer.
type bearerRoundTripper struct {
	next   http.RoundTripper
	header string
}

func (b bearerRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.Header.Set("Authorization", b.header)
	next := b.next
	if next == nil {
		next = http.DefaultTransport
	}
	return next.RoundTrip(req)
}

func TestAddStreamIdToUrl(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		streamId string
		expected string
	}{
		{
			name:     "no query",
			endpoint: "https://example.com/status",
			streamId: "stream1",
			expected: "https://example.com/status?stream_id=stream1",
		},
		{
			name:     "existing query, no stream_id",
			endpoint: "https://example.com/status?foo=bar",
			streamId: "stream1",
			expected: "https://example.com/status?foo=bar&stream_id=stream1",
		},
		{
			name:     "existing stream_id",
			endpoint: "https://example.com/status?stream_id=stream2",
			streamId: "stream1",
			expected: "https://example.com/status?stream_id=stream2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, AddStreamIdToUrl(tt.endpoint, tt.streamId))
		})
	}
}
