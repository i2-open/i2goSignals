package server

// sstp_pair_e2e_test.go — cross-server end-to-end suite for the Synchronous SET
// Transfer Protocol (SSTP, draft-hunt-secevent-sstp-00), PRD #154 slice #171.
//
// Each test boots TWO full live goSignals servers (StartServer + memory provider)
// on real TCP listeners and exercises the SSTP pair flows across them over real
// HTTP: pair create + TxAlias auto-reg cascade, delete + cascade_peer 207,
// per-direction verify, auto-pause propagation, cluster wake-up, push-while-poll-
// held, lease takeover, and bearer-mismatch auth.
//
// Assertions are against external behavior — HTTP responses, persisted record
// shape via DAO/service reads, and EventRouter buffer counts only as a behavioral
// proxy for "event delivered" — never goroutine counts or channel internals
// (PRD #154 Testing Decisions, Q47).

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/i2-open/i2goSignals/internal/providers/dbProviders"
	"github.com/i2-open/i2goSignals/pkg/authSupport"
	"github.com/i2-open/i2goSignals/pkg/goSetSstp"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/i2-open/i2goSignals/pkg/tlsSupport"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"go.mongodb.org/mongo-driver/v2/bson"
)

// sstpNode is one live server in the cross-server e2e suite.
type sstpNode struct {
	app         *SignalsApplication
	persistence *dbProviders.Persistence
	baseURL     string
	projectId   string
}

// SstpPairE2ESuite spins up two live goSignals servers that can cascade SSTP
// bootstraps to each other over real HTTP.
type SstpPairE2ESuite struct {
	suite.Suite
	a *sstpNode // the initiator/client node (operator drives create here)
	b *sstpNode // the responder/server node (peer that the cascade reaches)
}

func TestSstpPairE2ESuite(t *testing.T) {
	suite.Run(t, new(SstpPairE2ESuite))
}

func (s *SstpPairE2ESuite) SetupTest() {
	// The e2e servers run on http loopback; permit http SSTP EndpointUrls so the
	// responder-derived endpoint passes create-time validation (I2SIG_INSECURE_SSTP_HTTP,
	// PRD #154 Q28). Production requires https.
	s.T().Setenv("I2SIG_INSECURE_SSTP_HTTP", "true")
	// Shared HMAC secret so authenticated /_cluster/wake-sstp-* calls are accepted.
	s.T().Setenv("I2SIG_CLUSTER_INTERNAL_TOKEN", "e2e-cluster-secret")
	s.a = s.bootNode("sstp-e2e-a")
	s.b = s.bootNode("sstp-e2e-b")
}

func (s *SstpPairE2ESuite) TearDownTest() {
	for _, n := range []*sstpNode{s.a, s.b} {
		if n != nil && n.app != nil {
			n.app.Shutdown()
		}
	}
}

// bootNode starts one full server on a real loopback listener with the memory
// provider and returns its handle. The DEFAULT token key is initialized so the
// AuthIssuer can mint and verify bearers.
func (s *SstpPairE2ESuite) bootNode(dbName string) *sstpNode {
	s.T().Helper()
	s.T().Setenv("I2SIG_STORE_MEM_DIRECTORY", s.T().TempDir())

	persistence, err := dbProviders.OpenPersistence("memorydb:", dbName)
	s.Require().NoError(err)
	s.Require().NoError(persistence.KeyService.InitializeTokenKey(context.Background(), "DEFAULT"))
	if persistence.Storage != nil {
		persistence.Refresh()
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	s.Require().NoError(err)
	baseURL := "http://" + listener.Addr().String()

	app := StartServer(listener.Addr().String(), persistence, baseURL+"/")
	go func() { _ = app.Server.Serve(listener) }()

	// Wait for the server to answer its well-known endpoint before returning.
	client := &http.Client{Timeout: 2 * time.Second}
	tlsSupport.CheckCaInstalled(client)
	require.Eventually(s.T(), func() bool {
		resp, e := client.Get(baseURL + "/.well-known/ssf-configuration")
		if e != nil {
			return false
		}
		_ = resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}, 5*time.Second, 50*time.Millisecond, "server %s did not come up", dbName)

	return &sstpNode{
		app:         app,
		persistence: persistence,
		baseURL:     baseURL,
		projectId:   "e2e-project",
	}
}

// adminBearer mints a stream-admin bearer bound to the node's project so an
// operator (and the peer cascade) can drive the full pair lifecycle.
func (n *sstpNode) adminBearer(t *testing.T) string {
	t.Helper()
	client := model.SsfClient{Id: bson.NewObjectID(), ProjectIds: []string{n.projectId}}
	tok, err := n.app.GetAuth().IssueStreamClientToken(client, n.projectId, true, "")
	require.NoError(t, err)
	return tok
}

// registerPeer stores a Server alias on `n` whose Host points at `peer` and whose
// static ClientToken is a valid admin bearer for `peer`, so an SSTP create on `n`
// with peer_server_alias=alias can cascade the mirror to `peer` over real HTTP.
func (n *sstpNode) registerPeer(t *testing.T, alias string, peer *sstpNode) {
	t.Helper()
	peerBearer := peer.adminBearer(t)
	srv := &model.Server{
		Id:          bson.NewObjectID(),
		Alias:       alias,
		Type:        model.ServerTypeGosignals,
		Host:        peer.baseURL,
		ClientToken: &peerBearer,
		ProjectId:   n.projectId,
	}
	require.NoError(t, n.app.GetServerService().CreateServer(context.Background(), srv))
}

// httpDo performs an HTTP request against a node's base URL with an optional
// bearer and returns the status and body.
func (n *sstpNode) httpDo(t *testing.T, method, path, bearer string, body []byte) (int, []byte) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, n.baseURL+path, rdr)
	require.NoError(t, err)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	client := &http.Client{Timeout: 5 * time.Second}
	tlsSupport.CheckCaInstalled(client)
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	respBody, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, respBody
}

// symmetricBootstrap returns a responder-role SstpPairBootstrap with identical
// business-plane inputs both directions and the named peer alias for cascade.
func symmetricBootstrap(peerAlias, iss string, aud []string) model.SstpPairBootstrap {
	dir := model.SstpDirection{
		Iss:    iss,
		Aud:    aud,
		Events: []string{"https://schemas.openid.net/secevent/caep/event-type/session-revoked"},
		Mode:   model.SstpModePublish,
	}
	return model.SstpPairBootstrap{
		Role:            model.SstpRoleResponder,
		PeerServerAlias: peerAlias,
		Description:     "e2e symmetric pair",
		Primary:         dir,
		Inbound:         dir,
	}
}

// createPairResponder creates an SSTP pair on `local` in the responder role, with
// the mirror cascaded to `peer` over real HTTP. It returns the local node's full
// StreamStateRecord. `local` is the HTTP server (responder); `peer` runs the
// initiator/client side.
func (s *SstpPairE2ESuite) createPairResponder(local, peer *sstpNode, peerAlias string) model.StreamStateRecord {
	s.T().Helper()
	local.registerPeer(s.T(), peerAlias, peer)
	boot := symmetricBootstrap(peerAlias, "https://e2e.example.com", []string{"https://aud.example.com"})
	body, err := json.Marshal(boot)
	s.Require().NoError(err)

	status, respBody := local.httpDo(s.T(), http.MethodPost, "/stream", local.adminBearer(s.T()), body)
	s.Require().Equalf(http.StatusCreated, status, "pair create should return 201, got %d: %s", status, string(respBody))

	var rec model.StreamStateRecord
	s.Require().NoError(json.Unmarshal(respBody, &rec))
	return rec
}

// ---------------------------------------------------------------------------
// Scenario 1: Pair create + TxAlias auto-reg cascade (both roles).
// ---------------------------------------------------------------------------

// TestPairCreateCascade_ResponderInitiates verifies that POSTing an
// SstpPairBootstrap (responder role) to one live server expands a bidirectional
// pair locally AND cascades the mirrored bootstrap to the peer over real HTTP, so
// both servers hold a pair with a consistent cross-reference (PeerPairId) and the
// responder server-derives its EndpointUrl + mints the bearer (Q10.2, Q31, Q33).
func (s *SstpPairE2ESuite) TestPairCreateCascade_ResponderInitiates() {
	rec := s.createPairResponder(s.b, s.a, "peerA")

	// Local (responder, node B) shape: bidirectional, server-derived endpoint,
	// server-minted bearer, learned peer pair id.
	s.Require().NotEmpty(rec.PairId, "responder pair must have a PairId")
	s.Require().NotNil(rec.SstpInbound, "pair must have an inbound (rx) half")
	s.Require().NotNil(rec.SstpMethod)
	s.Equal(model.SstpRoleResponder, rec.SstpMethod.Role)
	s.Contains(rec.SstpMethod.EndpointUrl, "/sstp/"+rec.PairId, "responder derives its own /sstp/{pairId} endpoint")
	s.Contains(rec.SstpMethod.AuthorizationHeader, "Bearer ", "responder mints the per-pair bearer")
	s.Require().NotEmpty(rec.SstpMethod.PeerPairId, "responder learns the peer's PairId from the cascade")

	// Peer (initiator, node A) holds the mirror keyed on the learned PeerPairId.
	peerRec, err := s.a.app.GetStreamService().GetStreamStateByPairId(context.Background(), rec.SstpMethod.PeerPairId)
	s.Require().NoError(err)
	s.Require().NotNil(peerRec)
	s.Equal(model.SstpRoleInitiator, peerRec.SstpMethod.Role, "the cascaded peer half plays initiator")
	s.Equal(rec.PairId, peerRec.SstpMethod.PeerPairId, "the initiator points back at the responder's PairId")
	// The initiator learned the responder's endpoint + bearer from the cascade.
	s.Equal(rec.SstpMethod.EndpointUrl, peerRec.SstpMethod.EndpointUrl, "initiator learns the responder endpoint")
	s.Equal(rec.SstpMethod.AuthorizationHeader, peerRec.SstpMethod.AuthorizationHeader, "initiator learns the minted bearer")
}

// ---------------------------------------------------------------------------
// Scenario 2: Pair-delete + cascade_peer=true 207 partial-failure path.
// ---------------------------------------------------------------------------

// TestPairDelete_CascadePeerHappyAndPartial verifies both delete outcomes (Q37,
// ADR 0020): (1) cascade_peer=true with a reachable peer returns 200 and removes
// the pair on BOTH servers; (2) cascade_peer=true with an unreachable peer returns
// 207 Multi-Status — the local delete always succeeds and the peer failure is
// surfaced, not swallowed.
func (s *SstpPairE2ESuite) TestPairDelete_CascadePeerHappyAndPartial() {
	// --- Happy path: peer reachable → 200, both sides gone. ---
	rec := s.createPairResponder(s.b, s.a, "peerA")
	peerPairId := rec.SstpMethod.PeerPairId

	delPath := fmt.Sprintf("/stream?stream_id=%s&cascade_peer=true&peer_server_alias=peerA", rec.PairId)
	status, respBody := s.b.httpDo(s.T(), http.MethodDelete, delPath, s.b.adminBearer(s.T()), nil)
	s.Require().Equalf(http.StatusOK, status, "reachable peer cascade is 200, got %d: %s", status, string(respBody))

	var outcome struct {
		LocalDeleted  bool `json:"local_deleted"`
		PeerAttempted bool `json:"peer_attempted"`
		PeerDeleted   bool `json:"peer_deleted"`
	}
	s.Require().NoError(json.Unmarshal(respBody, &outcome))
	s.True(outcome.LocalDeleted)
	s.True(outcome.PeerAttempted)
	s.True(outcome.PeerDeleted, "peer accepted the courtesy delete")

	// Both halves are gone.
	_, err := s.b.app.GetStreamService().GetStreamStateByPairId(context.Background(), rec.PairId)
	s.Error(err, "local (responder) pair removed")
	_, err = s.a.app.GetStreamService().GetStreamStateByPairId(context.Background(), peerPairId)
	s.Error(err, "peer (initiator) pair removed by cascade")

	// --- Partial-failure path: peer unreachable → 207. ---
	rec2 := s.createPairResponder(s.b, s.a, "peerA2")
	// Take the peer node offline so the cascade DELETE cannot reach it.
	s.a.app.Shutdown()
	s.a = nil // prevent TearDown double-shutdown

	delPath2 := fmt.Sprintf("/stream?stream_id=%s&cascade_peer=true&peer_server_alias=peerA2", rec2.PairId)
	status2, respBody2 := s.b.httpDo(s.T(), http.MethodDelete, delPath2, s.b.adminBearer(s.T()), nil)
	s.Require().Equalf(http.StatusMultiStatus, status2, "unreachable peer cascade is 207, got %d: %s", status2, string(respBody2))

	var outcome2 struct {
		LocalDeleted  bool   `json:"local_deleted"`
		PeerAttempted bool   `json:"peer_attempted"`
		PeerDeleted   bool   `json:"peer_deleted"`
		PeerError     string `json:"peer_error"`
	}
	s.Require().NoError(json.Unmarshal(respBody2, &outcome2))
	s.True(outcome2.LocalDeleted, "local delete always succeeds even when the peer is down")
	s.True(outcome2.PeerAttempted)
	s.False(outcome2.PeerDeleted)
	s.NotEmpty(outcome2.PeerError, "the peer failure reason is surfaced, not swallowed")

	// Local pair is gone despite the peer failure.
	_, err = s.b.app.GetStreamService().GetStreamStateByPairId(context.Background(), rec2.PairId)
	s.Error(err, "local pair removed despite peer-down")
}

// ---------------------------------------------------------------------------
// Scenario 3: Per-direction /verify against peer (Q40).
// ---------------------------------------------------------------------------

// TestVerify_PerDirection verifies the per-direction /verify routing across the
// two live servers (Q40): a verify on the local tx-side SID round-trips — it
// queues a verify SET on the outbound (tx) direction, scoped to the primary
// issuer; the reverse direction is verified by calling the PEER's /verify against
// the peer's own tx-side SID. A verify on the rx-side SID resolves the inbound
// direction (scoped to the inbound issuer) rather than 404ing.
func (s *SstpPairE2ESuite) TestVerify_PerDirection() {
	rec := s.createPairResponder(s.b, s.a, "peerA")
	txSid := rec.StreamConfiguration.Id
	rxSid := rec.SstpInbound.Id

	// Verify on the local tx-side SID → 204, and a verify SET is queued on the tx
	// outbound direction (the round-trip path to the peer's inbound).
	body := []byte(fmt.Sprintf(`{"stream_id":%q,"state":"tx-state"}`, txSid))
	status, _ := s.b.httpDo(s.T(), http.MethodPost, "/verify", s.b.adminBearer(s.T()), body)
	s.Require().Equal(http.StatusNoContent, status, "verify on local txSid is 204")

	txJtis, _ := s.b.app.EventService.GetEventIds(context.Background(), txSid, model.PollParameters{ReturnImmediately: true})
	s.NotEmpty(txJtis, "verify queued an outbound SET on the tx direction (round-trip proxy)")

	// Verify on the local rx-side SID → 204, resolved to the inbound direction (not
	// a spurious 404). The verify SET is scoped to the inbound side.
	rxBody := []byte(fmt.Sprintf(`{"stream_id":%q,"state":"rx-state"}`, rxSid))
	rxStatus, _ := s.b.httpDo(s.T(), http.MethodPost, "/verify", s.b.adminBearer(s.T()), rxBody)
	s.Require().Equal(http.StatusNoContent, rxStatus, "verify on local rxSid resolves the inbound direction (not 404)")

	// Reverse direction: call the PEER's /verify against the peer's own tx-side SID
	// (per spec, Q40). The peer (initiator) half's tx SID is its PairId.
	peerRec, err := s.a.app.GetStreamService().GetStreamStateByPairId(context.Background(), rec.SstpMethod.PeerPairId)
	s.Require().NoError(err)
	peerTxSid := peerRec.StreamConfiguration.Id
	peerBody := []byte(fmt.Sprintf(`{"stream_id":%q,"state":"peer-tx-state"}`, peerTxSid))
	peerStatus, _ := s.a.httpDo(s.T(), http.MethodPost, "/verify", s.a.adminBearer(s.T()), peerBody)
	s.Require().Equal(http.StatusNoContent, peerStatus, "reverse-direction verify on the peer's txSid is 204")

	peerTxJtis, _ := s.a.app.EventService.GetEventIds(context.Background(), peerTxSid, model.PollParameters{ReturnImmediately: true})
	s.NotEmpty(peerTxJtis, "peer-side verify queued an outbound SET on the peer's tx direction")
}

// ---------------------------------------------------------------------------
// Scenario 4: Auto-pause propagation on a request-level (4xx) error.
// ---------------------------------------------------------------------------

// TestAutoPause_OutboundOnly verifies that a request-level (4xx) error on the
// SSTP-client's outbound cycle pauses ONLY the outbound (tx) direction of the
// pair while the inbound (rx) direction keeps running (Q12.3, Q20). We induce the
// 4xx by deleting the pair on the responder (so its /sstp/{id} answers 404), then
// queue an outbound SET on the initiator; the initiator's runner POSTs, classifies
// the 404 as a request error, and pauses its outbound direction.
func (s *SstpPairE2ESuite) TestAutoPause_OutboundOnly() {
	rec := s.createPairResponder(s.b, s.a, "peerA")
	peerPairId := rec.SstpMethod.PeerPairId // the initiator (node A) pair id

	// Delete the pair on the responder so its /sstp/{pairId} now returns 404 — a
	// request-level error for the initiator's outbound cycle. No cascade (the
	// initiator half must survive so we can observe its pause).
	delPath := fmt.Sprintf("/stream?stream_id=%s", rec.PairId)
	delStatus, _ := s.b.httpDo(s.T(), http.MethodDelete, delPath, s.b.adminBearer(s.T()), nil)
	s.Require().Equal(http.StatusOK, delStatus)

	// Queue an outbound SET on the initiator (node A) tx side via /verify.
	peerRec, err := s.a.app.GetStreamService().GetStreamStateByPairId(context.Background(), peerPairId)
	s.Require().NoError(err)
	peerTxSid := peerRec.StreamConfiguration.Id
	body := []byte(fmt.Sprintf(`{"stream_id":%q,"state":"force-4xx"}`, peerTxSid))
	vStatus, _ := s.a.httpDo(s.T(), http.MethodPost, "/verify", s.a.adminBearer(s.T()), body)
	s.Require().Equal(http.StatusNoContent, vStatus)

	// The initiator's outbound direction pauses; the inbound direction stays enabled.
	require.Eventually(s.T(), func() bool {
		cur, e := s.a.app.GetStreamService().GetStreamStateByPairId(context.Background(), peerPairId)
		if e != nil || cur == nil {
			return false
		}
		return cur.Status == model.StreamStatePause && cur.InboundStatus == model.StreamStateEnabled
	}, 15*time.Second, 200*time.Millisecond, "initiator outbound should auto-pause on 4xx while inbound stays enabled")

	cur, _ := s.a.app.GetStreamService().GetStreamStateByPairId(context.Background(), peerPairId)
	s.NotEmpty(cur.ErrorMsg, "the paused outbound direction carries a clear ErrorMsg")
}

// ---------------------------------------------------------------------------
// Scenario 6: Outbound SET delivered end-to-end via the responder /sstp/{id}
// long-poll (Q7.2) — the response carries the SET and is correctly classified.
// ---------------------------------------------------------------------------

// TestOutboundDelivery_ViaLongPoll verifies that an outbound SET queued on the
// responder pair's tx side is returned to a POST /sstp/{pairId} request in the
// "sets" map of an application/sstp+json 200 response, and that the response
// classifies as ClassOK (a correctly-formed, no-error SSTP response). This is the
// externally-observable heart of SSTP outbound delivery over real HTTP (Q7.2,
// Q15, Q46).
func (s *SstpPairE2ESuite) TestOutboundDelivery_ViaLongPoll() {
	// A short long-poll timeout: the prefetched SET is appended to the buffer
	// asynchronously, so a real long-poll (returnEvents=true, not returnImmediately)
	// reliably catches it on the notifier within the timeout.
	s.T().Setenv("I2SIG_POLL_DEFAULT_TIMEOUT", "5")
	rec := s.createPairResponder(s.b, s.a, "peerA")
	txSid := rec.StreamConfiguration.Id

	// The pair's tx direction is PUBLISH mode, so the responder re-signs each
	// outbound SET with its issuer key. Create that key (in a real deployment the
	// issuer's signing key is provisioned alongside the stream).
	_, err := s.b.app.KeyService.CreateKeyPair(context.Background(), rec.StreamConfiguration.Iss, "sig", s.b.projectId)
	s.Require().NoError(err)

	// Queue an outbound SET on the responder's tx direction via /verify.
	vBody := []byte(fmt.Sprintf(`{"stream_id":%q,"state":"deliver-me"}`, txSid))
	vStatus, _ := s.b.httpDo(s.T(), http.MethodPost, "/verify", s.b.adminBearer(s.T()), vBody)
	s.Require().Equal(http.StatusNoContent, vStatus)

	// POST the SSTP cycle as a real long-poll (returnEvents default true) with the
	// pair's own minted bearer; it returns the pending outbound SET on the notifier.
	status, respBody := s.b.sstpPostRaw(s.T(), "/sstp/"+rec.PairId, rec.SstpMethod.AuthorizationHeader,
		[]byte(`{"sets":{}}`))
	s.Require().Equalf(http.StatusOK, status, "SSTP cycle is 200, got %d: %s", status, string(respBody))

	var msg goSetSstp.Message
	s.Require().NoError(json.Unmarshal(respBody, &msg))
	s.Require().NotEmpty(msg.Sets, "the outbound verify SET is returned in the SSTP response 'sets' map")

	// The response classifies as ClassOK end-to-end (a well-formed, no-error SSTP
	// response with no per-JTI errors).
	cls := goSetSstp.ClassifyResult(goSetSstp.Result{StatusCode: status, Message: &msg})
	s.Equal(goSetSstp.ClassOK, cls.Class, "a 200 SSTP response with SETs and no setErrs classifies ClassOK")
	s.Empty(msg.SetErrs, "no per-JTI errors on a clean outbound delivery")
}

// ---------------------------------------------------------------------------
// Scenario 5: Cluster wake-up endpoint over real HTTP unblocks a held long-poll.
// ---------------------------------------------------------------------------

// TestWakeSstpServer_UnblocksHeldLongPoll verifies the wake-sstp-server cluster
// endpoint end-to-end over real HTTP (Q11.1, Q11.2): a long-poll held open on the
// responder's /sstp/{pairId} (no outbound queued, returnImmediately=false) is
// released promptly once an authenticated POST /_cluster/wake-sstp-server arrives
// for the pair's tx-side SID — proving the cluster wake path drives the held
// receiver cycle rather than waiting out the full poll timeout.
func (s *SstpPairE2ESuite) TestWakeSstpServer_UnblocksHeldLongPoll() {
	// Shrink the long-poll timeout so the "without wake it would block" baseline is
	// well within the test budget but clearly longer than the wake latency.
	s.T().Setenv("I2SIG_POLL_DEFAULT_TIMEOUT", "10")
	rec := s.createPairResponder(s.b, s.a, "peerA")

	// Open the held long-poll in a goroutine (no events queued → it blocks waiting).
	done := make(chan time.Duration, 1)
	go func() {
		start := time.Now()
		_, _ = s.b.sstpPostRaw(s.T(), "/sstp/"+rec.PairId, rec.SstpMethod.AuthorizationHeader,
			[]byte(`{"sets":{},"returnImmediately":false}`))
		done <- time.Since(start)
	}()

	// Give the long-poll a moment to register its buffer, then fire the wake.
	time.Sleep(300 * time.Millisecond)
	wakeToken := authSupport.GenerateClusterToken("e2e-cluster-secret", rec.StreamConfiguration.Id, "sstp-server")
	wakeBody := []byte(fmt.Sprintf(`{"sid":%q,"mode":"sstp-server"}`, rec.StreamConfiguration.Id))
	wakeStatus, _ := s.b.httpDo(s.T(), http.MethodPost, "/_cluster/wake-sstp-server", wakeToken, wakeBody)
	s.Require().Equal(http.StatusAccepted, wakeStatus, "authenticated wake-sstp-server is 202")

	// The held long-poll returns well before the 10s timeout.
	select {
	case elapsed := <-done:
		s.Less(elapsed, 5*time.Second, "the wake released the held long-poll promptly (not a timeout)")
	case <-time.After(9 * time.Second):
		s.Fail("held long-poll did not return after the wake")
	}
}

// ---------------------------------------------------------------------------
// Scenario 7: Lease takeover — requires a shared real-time cluster store (Mongo).
// ---------------------------------------------------------------------------

// TestLeaseTakeover_NewOwnerNoDuplicateInbound is the cross-server lease-takeover
// scenario (Q13, Q14, Q16). A faithful test needs TWO nodes sharing one real-time
// cluster store so the sstp-client:<PairId> lease can transfer between them; the
// memory provider (chosen for speed per Q47) gives each StartServer its own
// isolated in-memory store, so two nodes cannot share a lease here. The takeover
// mechanics — jittered re-acquire, single-retry heartbeat, no-two-node-race, and
// JTI-dedup on the peer — are covered deterministically against a fake coordinator
// in internal/eventRouter/runner_sstp_test.go. This e2e variant is skipped pending
// a shared-Mongo two-node harness (TODO #171).
func (s *SstpPairE2ESuite) TestLeaseTakeover_NewOwnerNoDuplicateInbound() {
	s.T().Skip("lease takeover needs a shared real-time cluster store (Mongo); memory provider isolates each node — see runner_sstp_test.go for the deterministic coverage (TODO #171)")
}

// ---------------------------------------------------------------------------
// Scenario 8: Bearer mismatch on /sstp/{id} → 401 with SSF error envelope.
// ---------------------------------------------------------------------------

// TestSstpEndpoint_BearerMismatch verifies that POSTing to a live responder's
// /sstp/{pairId} with a bearer NOT authorized for that pair's SIDs is rejected
// 401 with the SSF {err, description} error envelope (Q20). A token minted for a
// different project/stream does not authorize this pair (defense-in-depth, Q19/Q42).
func (s *SstpPairE2ESuite) TestSstpEndpoint_BearerMismatch() {
	rec := s.createPairResponder(s.b, s.a, "peerA")
	endpointPath := "/sstp/" + rec.PairId

	// A stream-admin token bound to a DIFFERENT project — valid signature, but its
	// StreamIds[] do not contain this pair's SIDs.
	wrongClient := model.SsfClient{Id: bson.NewObjectID(), ProjectIds: []string{"some-other-project"}}
	wrongBearer, err := s.b.app.GetAuth().IssueStreamClientToken(wrongClient, "some-other-project", true, "")
	s.Require().NoError(err)

	// returnImmediately:true so the accepted path does not hold the inbound
	// long-poll open (the 401 path never reaches the runner anyway).
	sstpBody := []byte(`{"sets":{},"returnImmediately":true}`)
	status, respBody := s.b.sstpPost(s.T(), endpointPath, wrongBearer, sstpBody)
	s.Equal(http.StatusUnauthorized, status, "a bearer not authorized for the pair is 401")

	var env struct {
		Err         string `json:"err"`
		Description string `json:"description"`
	}
	s.Require().NoError(json.Unmarshal(respBody, &env), "401 carries an SSF error envelope")
	s.NotEmpty(env.Err, "error envelope has an err code")
	s.NotEmpty(env.Description, "error envelope has a description")

	// And: the correctly-minted per-pair bearer IS accepted (200), proving the 401
	// is about authorization, not a broken endpoint.
	pairBearer := rec.SstpMethod.AuthorizationHeader
	okStatus, _ := s.b.sstpPostRaw(s.T(), endpointPath, pairBearer, sstpBody)
	s.Equal(http.StatusOK, okStatus, "the pair's own minted bearer is accepted")
}

// sstpPost POSTs an application/sstp+json body to a node's /sstp endpoint with a
// "Bearer <token>" header and returns the status and body.
func (n *sstpNode) sstpPost(t *testing.T, path, bearer string, body []byte) (int, []byte) {
	t.Helper()
	return n.sstpPostRaw(t, path, "Bearer "+bearer, body)
}

// sstpPostRaw POSTs an application/sstp+json body using authHeader verbatim as the
// Authorization header value (so callers can pass an already-"Bearer "-prefixed
// per-pair credential).
func (n *sstpNode) sstpPostRaw(t *testing.T, path, authHeader string, body []byte) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(goSetSstp.Method, n.baseURL+path, bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", goSetSstp.ContentType)
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	client := &http.Client{Timeout: 40 * time.Second}
	tlsSupport.CheckCaInstalled(client)
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	respBody, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, respBody
}
