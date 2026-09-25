package eventRouter

import (
	"context"
	"crypto"
	"errors"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/dao/memory"
	"github.com/i2-open/i2goSignals/pkg/services"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Issue #318: a signing key has a validity period. The router's key cache holds
// a key no later than the moment its selection changes (the key's NotAfter, or a
// newer key's NotBefore), so a node stops signing with an expired key, and picks
// up a pre-staged successor, at that instant rather than up to a TTL later.

const validityCacheIssuer = "https://key-validity-cache.example"

// TestKeyCache_ExpiredKeyIsNotServedFromCache: a key minted with a one-second
// lifetime signs, and one second later (well inside the cache TTL) the router
// has no key for the issuer, exactly as a fresh read of the key store says.
func TestKeyCache_ExpiredKeyIsNotServedFromCache(t *testing.T) {
	ctx := context.Background()
	svc := services.NewKeyService(memory.NewKeyDAO(), "DEFAULT", nil, nil)
	r, clk := keyCacheRouter(svc)
	svc.SetClock(clk.Now)

	_, kid, err := svc.CreateKeyPairForAlg(ctx, validityCacheIssuer, "RS256", "sig", "", services.WithLifetime(time.Second))
	require.NoError(t, err)

	key, gotKid := r.checkAndLoadKey("s1", validityCacheIssuer, "RS256")
	require.NotNil(t, key, "the key signs inside its validity period")
	assert.Equal(t, kid, gotKid)

	clk.Advance(time.Second)
	_, _, err = svc.GetSigner(ctx, validityCacheIssuer, "RS256")
	require.ErrorIs(t, err, interfaces.ErrKeyNotFound, "the key store has no active key once the key expired")

	key, gotKid = r.checkAndLoadKey("s1", validityCacheIssuer, "RS256")
	assert.Nil(t, key, "the cache must not keep signing with an expired key")
	assert.Empty(t, gotKid)
}

// untilSignerSource answers GetSignerUntil with key a until switchAt, then with
// key b, telling the cache when the answer changes.
type untilSignerSource struct {
	mu       sync.Mutex
	now      func() time.Time
	switchAt time.Time
	a, b     crypto.Signer
	err      error
	reads    int
}

func (s *untilSignerSource) GetSigner(ctx context.Context, issuer, alg string) (crypto.Signer, string, error) {
	key, kid, _, err := s.GetSignerUntil(ctx, issuer, alg)
	return key, kid, err
}

func (s *untilSignerSource) GetSignerUntil(_ context.Context, _ string, _ string) (crypto.Signer, string, time.Time, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reads++
	if s.err != nil {
		return nil, "", time.Time{}, s.err
	}
	if s.now().Before(s.switchAt) {
		return s.a, "kid-a", s.switchAt, nil
	}
	return s.b, "kid-b", time.Time{}, nil
}

func (s *untilSignerSource) fail(err error) {
	s.mu.Lock()
	s.err = err
	s.mu.Unlock()
}

// TestKeyCache_SuccessorTakesOverAtItsNotBefore: a newer key pre-staged with a
// future NotBefore takes over at that instant, not a TTL later.
func TestKeyCache_SuccessorTakesOverAtItsNotBefore(t *testing.T) {
	src := &untilSignerSource{a: testSigner(t), b: testSigner(t)}
	r, clk := keyCacheRouter(src)
	src.now = clk.Now
	src.switchAt = clk.Now().Add(500 * time.Millisecond)

	_, kid := r.checkAndLoadKey("s1", validityCacheIssuer, "RS256")
	assert.Equal(t, "kid-a", kid)
	_, kid = r.checkAndLoadKey("s1", validityCacheIssuer, "RS256")
	assert.Equal(t, "kid-a", kid, "a fresh entry is served from the cache")

	clk.Advance(500 * time.Millisecond)
	_, kid = r.checkAndLoadKey("s1", validityCacheIssuer, "RS256")
	assert.Equal(t, "kid-b", kid, "the successor signs from its NotBefore")
}

// TestKeyCache_OutageDoesNotExtendAnExpiredKey: a key store outage keeps the
// current key only while it is still valid; past its expiry there is no key.
func TestKeyCache_OutageDoesNotExtendAnExpiredKey(t *testing.T) {
	src := &untilSignerSource{a: testSigner(t), b: nil}
	r, clk := keyCacheRouter(src)
	src.now = clk.Now
	src.switchAt = clk.Now().Add(3 * signingKeyCacheTTL)

	_, kid := r.checkAndLoadKey("s1", validityCacheIssuer, "RS256")
	require.Equal(t, "kid-a", kid)

	src.fail(errors.New("key store unavailable"))
	clk.Advance(signingKeyCacheTTL)
	_, kid = r.checkAndLoadKey("s1", validityCacheIssuer, "RS256")
	assert.Equal(t, "kid-a", kid, "a still-valid key survives an outage")

	clk.Advance(2 * signingKeyCacheTTL)
	key, kid := r.checkAndLoadKey("s1", validityCacheIssuer, "RS256")
	assert.Nil(t, key, "an outage must not extend a key past its expiry")
	assert.Empty(t, kid)
}

// shiftedClock is wall time plus an offset the test moves, shared by the key
// service and the router's key cache so a key can be made to expire under a
// running stream without sleeping.
type shiftedClock struct{ offset atomic.Int64 }

func (c *shiftedClock) Now() time.Time       { return time.Now().Add(time.Duration(c.offset.Load())) }
func (c *shiftedClock) jump(d time.Duration) { c.offset.Add(int64(d)) }
func (c *shiftedClock) attach(h *filterPushHarness) {
	h.keyService.SetClock(c.Now)
	h.router.signingKeys.setClock(c.Now)
}

// expiringIssuerKey leaves iss signing with a key that expires in an hour: it
// rotates in a key with that lifetime and suspends iss's original key.
func expiringIssuerKey(t *testing.T, h *filterPushHarness, iss string) *shiftedClock {
	t.Helper()
	clk := &shiftedClock{}
	clk.attach(h)
	_, _, err := h.keyService.RotateKey(context.Background(), iss, "RS256", "", services.WithLifetime(time.Hour))
	require.NoError(t, err)
	_, _, err = h.keyService.SetKeyStatus(context.Background(), iss, iss, interfaces.KeyStatusSuspended)
	require.NoError(t, err)
	h.router.InvalidateIssuerKey(iss)
	return clk
}

// TestPushSigningKey_ExpiredKeyPausesThenDisables: a key that expires under a
// running push stream is a key-unavailable pause, and still missing at the
// retry limit the stream is disabled, as for a suspended key (#312).
func TestPushSigningKey_ExpiredKeyPausesThenDisables(t *testing.T) {
	rx := newHoldingReceiver()
	rx.release()
	h := newSigningKeyHarness(t, rx, 3)
	stream := h.createSigningPushStream(t, signingKeyIssuer, model.RouteModePublish, "https://receiver.example.com/events", "")
	sid := stream.StreamConfiguration.Id
	clk := expiringIssuerKey(t, h, signingKeyIssuer)
	h.addPendingEvents(t, sid, 1)
	h.router.UpdateStreamState(stream.DeepCopy())
	require.Eventually(t, func() bool { return h.pendingCount(sid) == 0 }, 10*time.Second, 5*time.Millisecond)

	clk.jump(time.Hour)
	h.addPendingEvents(t, sid, 1)

	h.waitStoredStatus(t, sid, model.StreamStateDisable, services.NoActiveSigningKeyReason(signingKeyIssuer, ""))
	assert.Len(t, rx.snapshot(), 1, "nothing is signed with the expired key")
	assert.Equal(t, 1, h.pendingCount(sid), "the event stays queued")
}

// TestPushSigningKey_RotationAfterExpiryResumes: a paused push stream resumes
// once a valid key is rotated in.
func TestPushSigningKey_RotationAfterExpiryResumes(t *testing.T) {
	h, rx, sid := startKeyedRunner(t, 1000)
	clk := expiringIssuerKey(t, h, signingKeyIssuer)
	clk.jump(time.Hour)
	queued := h.addPendingEvents(t, sid, 1)
	h.waitStoredStatus(t, sid, model.StreamStatePause, services.NoActiveSigningKeyReason(signingKeyIssuer, ""))

	_, _, err := h.keyService.RotateKey(context.Background(), signingKeyIssuer, "RS256", "")
	require.NoError(t, err)

	h.waitStoredStatus(t, sid, model.StreamStateEnabled, "")
	require.Eventually(t, func() bool { return h.pendingCount(sid) == 0 }, 10*time.Second, 5*time.Millisecond)
	assert.Len(t, deliveriesByJti(rx.settle(t))[queued[0]], 1, "the queued event is delivered once")
}

// TestPollSigningKey_ExpiredKeyAnswers503AndPauses: a poll after the key
// expired takes the stored key-unavailable pause; the background check resumes
// the stream once a valid key is rotated in.
func TestPollSigningKey_ExpiredKeyAnswers503AndPauses(t *testing.T) {
	h, _ := newPollKeyHarness(t, "1h")
	stream := h.createSigningPollStream(t, pollKeyIssuer, model.RouteModePublish)
	sid := stream.StreamConfiguration.Id
	clk := expiringIssuerKey(t, h, pollKeyIssuer)
	delivered := h.queuePollEvents(t, sid, 1)
	sets, status := h.poll(sid)
	require.Equal(t, http.StatusOK, status)
	require.Contains(t, sets, delivered[0])
	queued := h.queuePollEvents(t, sid, 1)

	clk.jump(time.Hour)
	sets, status = h.poll(sid, delivered[0])
	assert.Equal(t, http.StatusServiceUnavailable, status)
	assert.Empty(t, sets)
	rec := h.stored(t, sid)
	assert.Equal(t, model.StreamStatePause, rec.Status)
	assert.Equal(t, "POLL-SRV: "+services.NoActiveSigningKeyReason(pollKeyIssuer, ""), rec.ErrorMsg)
	require.NotNil(t, rec.KeyUnavailableSince)

	_, _, err := h.keyService.RotateKey(context.Background(), pollKeyIssuer, "RS256", "")
	require.NoError(t, err)
	h.router.checkKeyUnavailablePauses(keyCheckAt(clk.Now()))
	assert.Equal(t, model.StreamStateEnabled, h.stored(t, sid).Status, "the key check resumes the stream")
	sets, status = h.poll(sid)
	assert.Equal(t, http.StatusOK, status)
	assert.Contains(t, sets, queued[0])
}

// TestKeyCheck_WarnsOfSigningKeysNearExpiry: the background key check WARNs of
// a signing key inside the expiry-warning window, once a day per key.
func TestKeyCheck_WarnsOfSigningKeysNearExpiry(t *testing.T) {
	h, _ := newPollKeyHarness(t, "1h")
	clk := &shiftedClock{}
	clk.attach(h)
	_, kid, err := h.keyService.CreateKeyPairForAlg(context.Background(), pollKeyIssuer, "ES256", "sig", "", services.WithLifetime(10*24*time.Hour))
	require.NoError(t, err)
	logs := captureLogs(t)

	h.router.checkKeyUnavailablePauses(keyCheckAt(clk.Now()))
	h.router.checkKeyUnavailablePauses(keyCheckAt(clk.Now()))

	warns := 0
	for _, line := range logs.lines() {
		if strings.Contains(line, "level=WARN") && strings.Contains(line, "expires soon") {
			warns++
			assert.Contains(t, line, pollKeyIssuer)
			assert.Contains(t, line, kid)
			assert.Contains(t, line, "alg=ES256")
			assert.Contains(t, line, "daysRemaining=")
		}
	}
	assert.Equal(t, 1, warns, "one WARN per key per day")
}
