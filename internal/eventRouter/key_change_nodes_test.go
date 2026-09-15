package eventRouter

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/i2-open/i2goSignals/internal/eventRouter/delivery"
	"github.com/i2-open/i2goSignals/internal/providers/dbProviders"
	"github.com/i2-open/i2goSignals/pkg/authSupport"
	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/goSetPush"
	"github.com/i2-open/i2goSignals/pkg/services"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Issue #313: a key change made through one node reaches every node's signing
// transmitters within the key cache's 2s bound. Two routers sharing one key
// store stand in for two nodes: node A handles the key change and node B runs
// transmitters whose key cache runs on a fake clock.

const nodesIssuer = "https://key-change-nodes.example"

// keyChangeNodes is the two-node fixture.
type keyChangeNodes struct {
	a, b      *filterPushHarness
	clock     *fakeClock // node B's key cache clock
	projectId string
}

// newKeyChangeNodes starts nodes A and B over one memory store. Node B pushes
// through seam. Push runners check the key every 50ms and never reach the retry
// limit within a test; receiver status polls and T3 keepalives are off.
func newKeyChangeNodes(t *testing.T, seam delivery.PushDelivery) *keyChangeNodes {
	t.Helper()
	t.Setenv("I2SIG_PUSH_DISABLE_RECEIVER_STATUS", "true")
	t.Setenv("I2SIG_PUSH_KEEPALIVE_INTERVAL", "0")
	t.Setenv("I2SIG_PUSH_CONCURRENCY", "1")
	t.Setenv("I2SIG_PUSH_BACKFILL_INTERVAL", "50ms")
	t.Setenv("I2SIG_PUSH_AUTH_RETRY_DELAY", "50ms")
	t.Setenv("I2SIG_PUSH_AUTH_RETRY_LIMIT", "1000")
	t.Setenv("I2SIG_STORE_MEM_DIRECTORY", t.TempDir())
	persistence, err := dbProviders.OpenPersistence("memorydb:", "key_change_nodes_test")
	require.NoError(t, err)
	t.Cleanup(func() {
		if persistence.Storage != nil {
			_ = persistence.Storage.Close()
		}
	})
	n := &keyChangeNodes{
		a:     nodeOn(t, persistence, "node-a", nil),
		b:     nodeOn(t, persistence, "node-b", seam),
		clock: newFakeClock(time.Now()),
	}
	n.a.jtiSeq = 1000 // node A's events never reuse node B's jtis
	n.b.router.signingKeys.setClock(n.clock.Now)
	n.projectId = projectIdFromHarness(t, &testHarness{router: n.a.router, streamService: n.a.streamService, keyService: n.a.keyService})
	return n
}

func nodeOn(t *testing.T, persistence *dbProviders.Persistence, nodeId string, seam delivery.PushDelivery) *filterPushHarness {
	t.Helper()
	r := NewRouter(RouterDeps{
		StreamService:        persistence.StreamService,
		KeyService:           persistence.KeyService,
		EventService:         persistence.EventService,
		Coordinator:          persistence.Coordinator,
		SubjectFilterService: persistence.SubjectFilterService,
		PushDelivery:         seam,
	}, nodeId).(*router)
	t.Cleanup(r.Shutdown)
	return &filterPushHarness{
		router:        r,
		streamService: persistence.StreamService,
		keyService:    persistence.KeyService,
		eventService:  persistence.EventService,
		subjectFilter: persistence.SubjectFilterService,
	}
}

// passTheBound moves node B's key cache clock past the 2s bound.
func (n *keyChangeNodes) passTheBound() {
	n.clock.Advance(signingKeyCacheTTL)
}

// createStream creates a transmitter for cfg in the shared store. The issuer's
// signing key must already exist.
func (n *keyChangeNodes) createStream(t *testing.T, cfg model.StreamConfiguration) *model.StreamStateRecord {
	t.Helper()
	ctx := context.Background()
	if cfg.Aud == nil {
		cfg.Aud = []string{"https://receiver.example.com"}
	}
	cfg.EventsDelivered = []string{"https://schemas.openid.net/secevent/risc/event-type/account-disabled"}
	authCtx := context.WithValue(ctx, authSupport.AuthContextKey, authSupport.ConvertProject(n.projectId))
	created, err := n.a.streamService.CreateStream(authCtx, model.StreamStateRecord{StreamConfiguration: cfg}, n.projectId, nil)
	require.NoError(t, err)
	state, err := n.a.streamService.GetStreamState(ctx, created.Id)
	require.NoError(t, err)
	return state
}

// pollStreamOn creates a poll transmitter signing as nodesIssuer with alg and
// registers it with node h.
func (n *keyChangeNodes) pollStreamOn(t *testing.T, h *filterPushHarness, alg, routeMode string) string {
	t.Helper()
	state := n.createStream(t, model.StreamConfiguration{
		Iss: nodesIssuer, SigningAlg: alg, RouteMode: routeMode,
		Delivery: &model.OneOfStreamConfigurationDelivery{
			PollTransmitMethod: &model.PollTransmitMethod{Method: model.DeliveryPoll, EndpointUrl: "https://transmitter.example.com/poll"},
		},
	})
	h.router.UpdateStreamState(state)
	h.queuePollEvents(t, state.StreamConfiguration.Id, 1)
	return state.StreamConfiguration.Id
}

// runningPushOnB creates a push transmitter signing as nodesIssuer in routeMode,
// starts its runner on node B and waits for its first delivery.
func (n *keyChangeNodes) runningPushOnB(t *testing.T, routeMode string, rec *signingRecorder) string {
	t.Helper()
	state := n.createStream(t, model.StreamConfiguration{
		Iss: nodesIssuer, RouteMode: routeMode,
		Delivery: &model.OneOfStreamConfigurationDelivery{
			PushTransmitMethod: &model.PushTransmitMethod{Method: model.DeliveryPush, EndpointUrl: "https://receiver.example.com/events"},
		},
	})
	sid := state.StreamConfiguration.Id
	n.b.addPendingEvents(t, sid, 1)
	n.b.router.UpdateStreamState(state.DeepCopy())
	require.Eventually(t, func() bool { return n.b.pendingCount(sid) == 0 }, 10*time.Second, 5*time.Millisecond)
	require.Len(t, rec.snapshot(), 1)
	return sid
}

// pushAgain queues one event on push stream sid and waits for its delivery,
// returning what it was signed with.
func (n *keyChangeNodes) pushAgain(t *testing.T, sid string, rec *signingRecorder) signedPush {
	t.Helper()
	before := len(rec.snapshot())
	n.b.addPendingEvents(t, sid, 1)
	require.Eventually(t, func() bool { return len(rec.snapshot()) > before && n.b.pendingCount(sid) == 0 }, 10*time.Second, 5*time.Millisecond)
	pushes := rec.snapshot()
	return pushes[len(pushes)-1]
}

// signedPush is what one push was signed with.
type signedPush struct {
	key crypto.Signer
	kid string
}

// signingRecorder is a push receiver that records the signing key and kid of
// every push and accepts it.
type signingRecorder struct {
	mu     sync.Mutex
	pushes []signedPush
}

func (s *signingRecorder) Deliver(_ context.Context, req delivery.PushRequest) delivery.PushOutcome {
	s.mu.Lock()
	s.pushes = append(s.pushes, signedPush{key: req.Key, kid: req.Kid})
	s.mu.Unlock()
	return delivery.PushOutcome{Classification: goSetPush.Classification{Class: goSetPush.ClassAccepted}, Key: req.Key, Kid: req.Kid}
}

func (s *signingRecorder) snapshot() []signedPush {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]signedPush(nil), s.pushes...)
}

// pollSigned polls sid on node h, requires a 200 with one SET, and returns the
// SET's kid and whether its signature verifies with pub.
func pollSigned(t *testing.T, h *filterPushHarness, sid string, pub crypto.PublicKey) (string, bool) {
	t.Helper()
	sets, status := h.poll(sid)
	require.Equal(t, http.StatusOK, status)
	require.Len(t, sets, 1)
	for _, set := range sets {
		return setKid(t, set), verifiesWith(set, pub)
	}
	return "", false
}

func setKid(t *testing.T, set string) string {
	t.Helper()
	token, _, err := jwt.NewParser().ParseUnverified(set, jwt.MapClaims{})
	require.NoError(t, err)
	kid, _ := token.Header["kid"].(string)
	return kid
}

func verifiesWith(set string, pub crypto.PublicKey) bool {
	_, err := jwt.NewParser(jwt.WithoutClaimsValidation()).Parse(set, func(*jwt.Token) (interface{}, error) { return pub, nil })
	return err == nil
}

func samePublicKey(a crypto.Signer, b crypto.PublicKey) bool {
	if a == nil {
		return false
	}
	pub, ok := a.Public().(interface{ Equal(crypto.PublicKey) bool })
	return ok && pub.Equal(b)
}

func (n *keyChangeNodes) revokeThroughA(t *testing.T) {
	t.Helper()
	n.a.setKeyStatus(t, nodesIssuer, interfaces.KeyStatusRevoked)
}

func TestKeyChangeAcrossNodes_RevokeThroughAStopsNodeBsTransmitters(t *testing.T) {
	rec := &signingRecorder{}
	n := newKeyChangeNodes(t, rec)
	ctx := context.Background()
	_, err := n.a.keyService.CreateKeyPair(ctx, nodesIssuer, "sig", n.projectId)
	require.NoError(t, err)

	pushSid := n.runningPushOnB(t, model.RouteModePublish, rec)
	pollSid := n.pollStreamOn(t, n.b, "", model.RouteModePublish)
	_, status := n.b.poll(pollSid)
	require.Equal(t, http.StatusOK, status)
	pair := sstpServerPairState("keychange-tx", "keychange-rx", "keychange-pair")
	pair.StreamConfiguration.Iss = nodesIssuer
	pair.StreamConfiguration.RouteMode = model.RouteModePublish
	require.NoError(t, n.b.streamService.PersistStreamStateRecord(ctx, pair))
	storedPair, err := n.b.streamService.GetStreamStateByPairId(ctx, "keychange-pair")
	require.NoError(t, err)
	require.NoError(t, n.b.router.CheckSstpSigningKey(storedPair))
	dialKey, _ := n.b.router.LoadSigningKey("keychange-tx", nodesIssuer, "")
	require.NotNil(t, dialKey, "node B holds the key before the revoke")

	n.revokeThroughA(t)
	n.passTheBound()

	// Poll: a 503 and the key-unavailable pause.
	sets, status := n.b.poll(pollSid)
	assert.Equal(t, http.StatusServiceUnavailable, status)
	assert.Empty(t, sets)
	polled := n.b.stored(t, pollSid)
	assert.Equal(t, model.StreamStatePause, polled.Status)
	assert.NotNil(t, polled.KeyUnavailableSince)

	// Push: the running runner pauses without sending.
	n.b.addPendingEvents(t, pushSid, 1)
	n.b.waitStoredStatus(t, pushSid, model.StreamStatePause, services.NoActiveSigningKeyReason(nodesIssuer, ""))
	assert.Len(t, rec.snapshot(), 1, "nothing is pushed with the revoked key")
	assert.Equal(t, 1, n.b.pendingCount(pushSid), "the event stays queued")

	// SSTP: the dialing end has no key to sign with, the accepting end pauses.
	dialKey, _ = n.b.router.LoadSigningKey("keychange-tx", nodesIssuer, "")
	assert.True(t, dialKey == nil, "the dialing end gets no key")
	assert.Error(t, n.b.router.CheckSstpSigningKey(storedPair))
	paused, err := n.b.streamService.GetStreamStateByPairId(ctx, "keychange-pair")
	require.NoError(t, err)
	assert.Equal(t, model.StreamStatePause, paused.Status)
	assert.NotNil(t, paused.KeyUnavailableSince)
}

// rotateUntilSelected rotates nodesIssuer's RS256 key through node A, as the
// rotate handler does, until the key store selects a key other than the one
// with kid from. The store signs with the active key whose record id is
// highest, and record ids are not minted in order, so one rotation moves the
// selection only about half the time. What #313 pins is that every node
// follows the selection within the bound, whichever key it is.
func (n *keyChangeNodes) rotateUntilSelected(t *testing.T, from string) (crypto.Signer, string) {
	t.Helper()
	ctx := context.Background()
	for i := 0; i < 64; i++ {
		_, _, err := n.a.keyService.RotateKey(ctx, nodesIssuer, "", n.projectId)
		require.NoError(t, err)
		n.a.router.InvalidateIssuerKey(nodesIssuer)
		key, kid, err := n.a.keyService.GetSigner(ctx, nodesIssuer, "")
		require.NoError(t, err)
		if kid != from {
			return key, kid
		}
	}
	require.FailNow(t, "the key store never selected a rotated key")
	return nil, ""
}

// warmRotationNodes starts a running push transmitter on node B and a poll
// transmitter on each node, all signing with the issuer's first key.
func warmRotationNodes(t *testing.T, n *keyChangeNodes, rec *signingRecorder, oldKey crypto.Signer) (pushSid, pollA, pollB string) {
	t.Helper()
	pushSid = n.runningPushOnB(t, model.RouteModePublish, rec)
	require.True(t, samePublicKey(rec.snapshot()[0].key, oldKey.Public()))
	pollA = n.pollStreamOn(t, n.a, "", model.RouteModePublish)
	pollB = n.pollStreamOn(t, n.b, "", model.RouteModePublish)
	kidA, _ := pollSigned(t, n.a, pollA, oldKey.Public())
	kidB, _ := pollSigned(t, n.b, pollB, oldKey.Public())
	require.Equal(t, nodesIssuer, kidA)
	require.Equal(t, nodesIssuer, kidB)
	return pushSid, pollA, pollB
}

// assertBothNodesSignWith checks that node A signs with key at once and that,
// past the bound, node B's poll transmitter and its already-running push loop
// do too, and keep delivering.
func assertBothNodesSignWith(t *testing.T, n *keyChangeNodes, rec *signingRecorder, pushSid, pollA, pollB string, key crypto.Signer, kid string) {
	t.Helper()
	got, verifies := pollSigned(t, n.a, pollA, key.Public())
	assert.Equal(t, kid, got, "node A signs with the new kid the next time it signs")
	assert.True(t, verifies)

	n.passTheBound()
	got, verifies = pollSigned(t, n.b, pollB, key.Public())
	assert.Equal(t, kid, got, "node B's poll transmitter signs with the new kid")
	assert.True(t, verifies)
	pushed := n.pushAgain(t, pushSid, rec)
	assert.Equal(t, kid, pushed.kid, "node B's running push loop signs with the new kid")
	assert.True(t, samePublicKey(pushed.key, key.Public()))
	status, _ := n.b.storedStatus(t, pushSid)
	assert.Equal(t, model.StreamStateEnabled, status, "a rotation keeps the transmitter delivering")
}

func TestKeyChangeAcrossNodes_RotateThroughAMovesBothNodesToTheNewKid(t *testing.T) {
	rec := &signingRecorder{}
	n := newKeyChangeNodes(t, rec)
	oldKey, err := n.a.keyService.CreateKeyPair(context.Background(), nodesIssuer, "sig", n.projectId)
	require.NoError(t, err)
	pushSid, pollA, pollB := warmRotationNodes(t, n, rec, oldKey)

	newKey, newKid := n.rotateUntilSelected(t, nodesIssuer)

	assertBothNodesSignWith(t, n, rec, pushSid, pollA, pollB, newKey, newKid)
}

// A completed rotation: the replacement is created through node A, then the old
// key is revoked there. Both nodes end up on the replacement and keep delivering.
func TestKeyChangeAcrossNodes_RotateThenRevokeTheOldKeyKeepsBothNodesDelivering(t *testing.T) {
	rec := &signingRecorder{}
	n := newKeyChangeNodes(t, rec)
	ctx := context.Background()
	oldKey, err := n.a.keyService.CreateKeyPair(ctx, nodesIssuer, "sig", n.projectId)
	require.NoError(t, err)
	pushSid, pollA, pollB := warmRotationNodes(t, n, rec, oldKey)

	newKey, newKid, err := n.a.keyService.RotateKey(ctx, nodesIssuer, "", n.projectId)
	require.NoError(t, err)
	n.a.router.InvalidateIssuerKey(nodesIssuer)
	_, _, err = n.a.keyService.SetKeyStatus(ctx, nodesIssuer, nodesIssuer, interfaces.KeyStatusRevoked)
	require.NoError(t, err)
	n.a.router.InvalidateIssuerKey(nodesIssuer)

	assertBothNodesSignWith(t, n, rec, pushSid, pollA, pollB, newKey, newKid)
}

func TestKeyChangeAcrossNodes_ReplaceThroughALeavesNoNodeSigningWithTheDeletedKey(t *testing.T) {
	for _, path := range []string{"create", "key load"} {
		t.Run(path, func(t *testing.T) {
			rec := &signingRecorder{}
			n := newKeyChangeNodes(t, rec)
			ctx := context.Background()
			oldKey, err := n.a.keyService.CreateKeyPair(ctx, nodesIssuer, "sig", n.projectId)
			require.NoError(t, err)
			pushSid := n.runningPushOnB(t, model.RouteModePublish, rec)
			pollA := n.pollStreamOn(t, n.a, "", model.RouteModePublish)
			pollB := n.pollStreamOn(t, n.b, "", model.RouteModePublish)
			_, verifies := pollSigned(t, n.b, pollB, oldKey.Public())
			require.True(t, verifies)

			// What the create or key-load handler does on node A for force=replace.
			require.NoError(t, n.a.keyService.DeleteKeysByNameAndAlg(ctx, nodesIssuer, ""))
			var newKey crypto.Signer
			if path == "create" {
				newKey, _, err = n.a.keyService.CreateKeyPairForAlg(ctx, nodesIssuer, "", "sig", n.projectId)
				require.NoError(t, err)
			} else {
				loaded, err := rsa.GenerateKey(rand.Reader, 2048)
				require.NoError(t, err)
				require.NoError(t, n.a.keyService.AddKey(ctx, nodesIssuer, "sig", "", loaded, nil, n.projectId))
				newKey = loaded
			}
			n.a.router.InvalidateIssuerKey(nodesIssuer)

			kid, verifies := pollSigned(t, n.a, pollA, newKey.Public())
			assert.True(t, verifies, "node A signs with the replacement at once")
			assert.Equal(t, nodesIssuer, kid, "the replacement keeps the kid")

			n.passTheBound()
			_, verifies = pollSigned(t, n.b, pollB, newKey.Public())
			assert.True(t, verifies, "node B's poll transmitter no longer signs with the deleted key")
			pushed := n.pushAgain(t, pushSid, rec)
			assert.True(t, samePublicKey(pushed.key, newKey.Public()), "node B's push loop no longer signs with the deleted key")
			assert.False(t, samePublicKey(pushed.key, oldKey.Public()))
		})
	}
}

func TestKeyChangeAcrossNodes_EveryAlgorithmOfTheIssuerPicksUpTheChange(t *testing.T) {
	n := newKeyChangeNodes(t, nil)
	ctx := context.Background()
	for _, alg := range []string{"RS256", "ES256"} {
		_, _, err := n.a.keyService.CreateKeyPairForAlg(ctx, nodesIssuer, alg, "sig", n.projectId)
		require.NoError(t, err)
	}
	polls := map[*filterPushHarness]map[string]string{n.a: {}, n.b: {}}
	for node, byAlg := range polls {
		for _, alg := range []string{"RS256", "ES256"} {
			sid := n.pollStreamOn(t, node, alg, model.RouteModePublish)
			_, status := node.poll(sid)
			require.Equal(t, http.StatusOK, status, "%s is signing before the revoke", alg)
			byAlg[alg] = sid
		}
	}

	n.revokeThroughA(t)

	for _, alg := range []string{"RS256", "ES256"} {
		_, status := n.a.poll(polls[n.a][alg])
		assert.Equal(t, http.StatusServiceUnavailable, status, "node A dropped its %s key at once", alg)
	}
	n.passTheBound()
	for _, alg := range []string{"RS256", "ES256"} {
		_, status := n.b.poll(polls[n.b][alg])
		assert.Equal(t, http.StatusServiceUnavailable, status, "node B dropped its %s key within the bound", alg)
	}
}

func TestKeyChangeAcrossNodes_ForwardTransmitterIsUnaffected(t *testing.T) {
	rec := &signingRecorder{}
	n := newKeyChangeNodes(t, rec)
	_, err := n.a.keyService.CreateKeyPair(context.Background(), nodesIssuer, "sig", n.projectId)
	require.NoError(t, err)
	sid := n.runningPushOnB(t, model.RouteModeForward, rec)

	n.revokeThroughA(t)
	n.passTheBound()

	for i := 0; i < 2; i++ {
		pushed := n.pushAgain(t, sid, rec)
		assert.True(t, pushed.key == nil, "a Forward transmitter signs nothing")
	}
	status, reason := n.b.storedStatus(t, sid)
	assert.Equal(t, model.StreamStateEnabled, status)
	assert.Empty(t, reason)
	assert.Len(t, rec.snapshot(), 3, "every event is relayed")
}
