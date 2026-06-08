package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/i2-open/i2goSignals/internal/eventRouter"
	"github.com/i2-open/i2goSignals/pkg/authSupport"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/goSetSstp"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recordingRouter is a minimal eventRouter.EventRouter test double that records
// the SSTP wake-up calls dispatched by the /_cluster/wake-sstp-* handlers. All
// other interface methods are no-ops — the handler tests only assert on the wake
// dispatch, auth, and idempotency behavior.
type recordingRouter struct {
	mu          sync.Mutex
	clientWakes []string
	serverWakes []string
}

func (rr *recordingRouter) WakeSstpClient(pairId string) {
	rr.mu.Lock()
	defer rr.mu.Unlock()
	rr.clientWakes = append(rr.clientWakes, pairId)
}

func (rr *recordingRouter) WakeSstpServer(txSid string) {
	rr.mu.Lock()
	defer rr.mu.Unlock()
	rr.serverWakes = append(rr.serverWakes, txSid)
}

func (rr *recordingRouter) clientWakeCount() int {
	rr.mu.Lock()
	defer rr.mu.Unlock()
	return len(rr.clientWakes)
}

func (rr *recordingRouter) serverWakeCount() int {
	rr.mu.Lock()
	defer rr.mu.Unlock()
	return len(rr.serverWakes)
}

// --- no-op remainder of the EventRouter interface ---
func (rr *recordingRouter) UpdateStreamState(*model.StreamStateRecord) {}
func (rr *recordingRouter) RemoveStream(string)                        {}
func (rr *recordingRouter) HandleEvent(*goSet.SecurityEventToken, string, string) error {
	return nil
}
func (rr *recordingRouter) SubmitOperationalEvent(string, *goSet.SecurityEventToken, string) (*model.AgEventRecord, error) {
	return nil, nil
}
func (rr *recordingRouter) GenerateVerifyEvent(string, string) (*model.AgEventRecord, error) {
	return nil, nil
}
func (rr *recordingRouter) PollStreamHandler(string, model.PollParameters) (map[string]string, bool, int) {
	return nil, false, http.StatusOK
}
func (rr *recordingRouter) SstpServerHandler(context.Context, string, goSetSstp.Message, []eventRouter.SstpInboundSet) (goSetSstp.Message, int) {
	return goSetSstp.Message{}, http.StatusOK
}
func (rr *recordingRouter) Shutdown()                                                      {}
func (rr *recordingRouter) SetEventCounter(*prometheus.CounterVec, *prometheus.CounterVec) {}
func (rr *recordingRouter) PreInitializeCounter(*model.StreamStateRecord)                  {}
func (rr *recordingRouter) GetPushStreamCnt() float64                                      { return 0 }
func (rr *recordingRouter) GetPollStreamCnt() float64                                      { return 0 }
func (rr *recordingRouter) IncrementCounter(*model.StreamStateRecord, *goSet.SecurityEventToken, bool) {
}
func (rr *recordingRouter) SetStatsHandler(interface{})      {}
func (rr *recordingRouter) ResetStream(string)               {}
func (rr *recordingRouter) WakeTransmitter(string, string)   {}
func (rr *recordingRouter) NotifySubjectFilterChange(string) {}

var _ eventRouter.EventRouter = (*recordingRouter)(nil)

// wakeSstpReq builds an HMAC-authenticated /_cluster/wake-sstp-* request for the
// given path, sid, and mode using the shared cluster secret.
func wakeSstpReq(path, secret, sid, mode string) *http.Request {
	body, _ := json.Marshal(map[string]string{"sid": sid, "mode": mode})
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+authSupport.GenerateClusterToken(secret, sid, mode))
	req.Header.Set("Content-Type", "application/json")
	return req
}

// TestWakeSstpClient_AuthenticatedWakesOwner verifies that an authenticated
// /_cluster/wake-sstp-client call wakes the local SSTP-client buffer for the pair
// (PRD #154 Q11.2, issue #167 AC: wake-sstp-client triggers the lease owner to
// drain a pending event).
func TestWakeSstpClient_AuthenticatedWakesOwner(t *testing.T) {
	t.Setenv("I2SIG_CLUSTER_INTERNAL_TOKEN", "test-secret")
	rr := &recordingRouter{}
	sa := &SignalsApplication{EventRouter: rr}

	req := wakeSstpReq("/_cluster/wake-sstp-client", "test-secret", "pair-1", "sstp-client")
	w := httptest.NewRecorder()
	sa.WakeSstpClient(w, req)

	assert.Equal(t, http.StatusAccepted, w.Code)
	require.Equal(t, 1, rr.clientWakeCount(), "an authenticated wake must wake the client buffer")
	assert.Equal(t, "pair-1", rr.clientWakes[0])
}

// TestWakeSstpClient_RejectsUnauthenticated verifies that a wake-sstp-client call
// with no/invalid cluster token is rejected with 401 and no wake is dispatched
// (issue #167 AC: unauthenticated requests rejected).
func TestWakeSstpClient_RejectsUnauthenticated(t *testing.T) {
	t.Setenv("I2SIG_CLUSTER_INTERNAL_TOKEN", "test-secret")
	rr := &recordingRouter{}
	sa := &SignalsApplication{EventRouter: rr}

	body, _ := json.Marshal(map[string]string{"sid": "pair-1", "mode": "sstp-client"})
	req := httptest.NewRequest(http.MethodPost, "/_cluster/wake-sstp-client", bytes.NewReader(body))
	// No Authorization header.
	w := httptest.NewRecorder()
	sa.WakeSstpClient(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Equal(t, 0, rr.clientWakeCount(), "an unauthenticated wake must not reach the router")
}

// TestWakeSstpServer_AuthenticatedWakesLongPoll verifies that an authenticated
// /_cluster/wake-sstp-server call wakes the local SSTP-server long-poll buffer for
// the pair's tx-side SID so a held long-poll returns the event immediately (PRD
// #154 Q11.1).
func TestWakeSstpServer_AuthenticatedWakesLongPoll(t *testing.T) {
	t.Setenv("I2SIG_CLUSTER_INTERNAL_TOKEN", "test-secret")
	rr := &recordingRouter{}
	sa := &SignalsApplication{EventRouter: rr}

	req := wakeSstpReq("/_cluster/wake-sstp-server", "test-secret", "sstp-tx-1", "sstp-server")
	w := httptest.NewRecorder()
	sa.WakeSstpServer(w, req)

	assert.Equal(t, http.StatusAccepted, w.Code)
	require.Equal(t, 1, rr.serverWakeCount(), "an authenticated wake must wake the server long-poll buffer")
	assert.Equal(t, "sstp-tx-1", rr.serverWakes[0])
}

// TestWakeSstpServer_RejectsUnauthenticated verifies the wake-sstp-server route
// rejects an unauthenticated request with 401 and dispatches no wake.
func TestWakeSstpServer_RejectsUnauthenticated(t *testing.T) {
	t.Setenv("I2SIG_CLUSTER_INTERNAL_TOKEN", "test-secret")
	rr := &recordingRouter{}
	sa := &SignalsApplication{EventRouter: rr}

	body, _ := json.Marshal(map[string]string{"sid": "sstp-tx-1", "mode": "sstp-server"})
	req := httptest.NewRequest(http.MethodPost, "/_cluster/wake-sstp-server", bytes.NewReader(body))
	w := httptest.NewRecorder()
	sa.WakeSstpServer(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Equal(t, 0, rr.serverWakeCount(), "an unauthenticated wake must not reach the router")
}

// TestWakeSstpClient_DuplicateIsNoOp verifies issue #167 idempotency: a second
// wake-sstp-client for the same pair inside the coalescing window is accepted with
// 202 but does NOT re-dispatch a wake to the router.
func TestWakeSstpClient_DuplicateIsNoOp(t *testing.T) {
	t.Setenv("I2SIG_CLUSTER_INTERNAL_TOKEN", "test-secret")
	// Isolate the shared coalescing map from any neighbouring test's residue.
	recentWakesMu.Lock()
	delete(recentWakes, "pair-dup:"+sstpWakeClientMode)
	recentWakesMu.Unlock()

	rr := &recordingRouter{}
	sa := &SignalsApplication{EventRouter: rr}

	for i := 0; i < 2; i++ {
		req := wakeSstpReq("/_cluster/wake-sstp-client", "test-secret", "pair-dup", "sstp-client")
		w := httptest.NewRecorder()
		sa.WakeSstpClient(w, req)
		assert.Equal(t, http.StatusAccepted, w.Code, "both wake-ups are accepted")
	}

	assert.Equal(t, 1, rr.clientWakeCount(),
		"a duplicate wake-up inside the coalescing window must be a no-op")
}

// nonSpiffeLeafCert returns a self-signed leaf certificate carrying no SPIFFE URI
// SAN — a stand-in for a TLS peer that presents a cert which is not a valid
// cluster SVID.
func nonSpiffeLeafCert(t *testing.T) *x509.Certificate {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "not-a-spiffe-peer"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// TestWakeSstp_SpiffePathRejectsNonClusterCert verifies the SPIFFE branch of the
// SSTP wake-up auth (PRD #154 Q11.1/Q11.2 AC: SPIFFE mTLS path validated when
// configured): when the TLS connection carries a peer certificate that is not a
// valid cluster SVID, the request is rejected with 401 and no HMAC fallback is
// attempted, on both SSTP wake routes.
func TestWakeSstp_SpiffePathRejectsNonClusterCert(t *testing.T) {
	t.Setenv("I2SIG_CLUSTER_INTERNAL_TOKEN", "test-secret")
	leaf := nonSpiffeLeafCert(t)

	for _, tc := range []struct {
		name    string
		path    string
		mode    string
		handler func(*SignalsApplication, http.ResponseWriter, *http.Request)
	}{
		{"client", "/_cluster/wake-sstp-client", sstpWakeClientMode,
			func(sa *SignalsApplication, w http.ResponseWriter, r *http.Request) { sa.WakeSstpClient(w, r) }},
		{"server", "/_cluster/wake-sstp-server", sstpWakeServerMode,
			func(sa *SignalsApplication, w http.ResponseWriter, r *http.Request) { sa.WakeSstpServer(w, r) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rr := &recordingRouter{}
			sa := &SignalsApplication{EventRouter: rr}

			// A valid HMAC token IS supplied — but because a (bogus) peer cert is
			// presented, the SPIFFE branch is taken and the HMAC is never consulted.
			body, _ := json.Marshal(map[string]string{"sid": "id-1", "mode": tc.mode})
			req := httptest.NewRequest(http.MethodPost, tc.path, bytes.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+authSupport.GenerateClusterToken("test-secret", "id-1", tc.mode))
			req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}

			w := httptest.NewRecorder()
			tc.handler(sa, w, req)

			assert.Equal(t, http.StatusUnauthorized, w.Code,
				"a non-cluster SVID peer cert must be rejected via the SPIFFE branch")
		})
	}
}
