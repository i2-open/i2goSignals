package services

import (
	"context"
	"sync"
	"testing"
	"time"

	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/dao/memory"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// countingTokenDAO counts the FindByJTI round trip #287 removes from the
// per-request revocation check. Everything else passes through to the real
// memory store, so the deferred-revocation semantics under test are the real
// ones.
type countingTokenDAO struct {
	interfaces.TokenDAO
	mu    sync.Mutex
	finds int
}

func (d *countingTokenDAO) FindByJTI(ctx context.Context, jti string) (*model.TokenRecord, error) {
	d.mu.Lock()
	d.finds++
	d.mu.Unlock()
	return d.TokenDAO.FindByJTI(ctx, jti)
}

func (d *countingTokenDAO) count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.finds
}

func (d *countingTokenDAO) reset() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.finds = 0
}

// newClockedTokenService returns a TokenService whose revocation memo runs on a
// test-driven clock, so the TTL and the deferred-revocation boundary are
// asserted exactly rather than slept through.
func newClockedTokenService(t *testing.T) (*TokenService, *countingTokenDAO, *time.Time) {
	t.Helper()
	dao := &countingTokenDAO{TokenDAO: memory.NewTokenDAO()}
	svc := NewTokenService(dao)
	nowVal := time.Now()
	svc.revocations.now = func() time.Time { return nowVal }
	return svc, dao, &nowVal
}

func insertToken(t *testing.T, dao interfaces.TokenDAO, jti string) {
	t.Helper()
	require.NoError(t, dao.Insert(context.Background(), &model.TokenRecord{
		JTI:      jti,
		Type:     model.TokenTypeStream,
		IssuedAt: time.Now(),
	}))
}

// TestIsRevokedServesRepeatedChecksFromMemo is the #287 claim: 5000 ingested
// events asked the same question 5009 times.
func TestIsRevokedServesRepeatedChecksFromMemo(t *testing.T) {
	svc, dao, _ := newClockedTokenService(t)
	insertToken(t, dao, "jti-live")
	ctx := context.Background()

	for i := 0; i < 50; i++ {
		revoked, err := svc.IsRevoked(ctx, "jti-live")
		require.NoError(t, err)
		require.False(t, revoked)
	}
	assert.Equal(t, 1, dao.count())
}

// TestIsRevokedCachesUntrackedJTIs covers the not-found branch: an untracked
// bearer is re-presented as often as a tracked one.
func TestIsRevokedCachesUntrackedJTIs(t *testing.T) {
	svc, dao, _ := newClockedTokenService(t)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		revoked, err := svc.IsRevoked(ctx, "never-issued")
		require.NoError(t, err)
		require.False(t, revoked)
	}
	assert.Equal(t, 1, dao.count())
}

// TestRevokeThroughServiceTakesEffectImmediately is the invalidation hook: a
// revoke issued on this node must NOT wait out the TTL.
func TestRevokeThroughServiceTakesEffectImmediately(t *testing.T) {
	for _, tc := range []struct {
		name   string
		revoke func(svc *TokenService, jti string) error
	}{
		{"RevokeToken", func(svc *TokenService, jti string) error {
			return svc.RevokeToken(context.Background(), jti)
		}},
		{"RevokeTokenAt", func(svc *TokenService, jti string) error {
			return svc.RevokeTokenAt(context.Background(), jti, time.Now().Add(-time.Second))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc, dao, _ := newClockedTokenService(t)
			insertToken(t, dao, "jti-doomed")
			ctx := context.Background()

			revoked, err := svc.IsRevoked(ctx, "jti-doomed")
			require.NoError(t, err)
			require.False(t, revoked)

			require.NoError(t, tc.revoke(svc, "jti-doomed"))

			// Same instant on the memo's clock: no TTL has elapsed, so only the
			// invalidation hook can make this true.
			revoked, err = svc.IsRevoked(ctx, "jti-doomed")
			require.NoError(t, err)
			assert.True(t, revoked, "a revoke made through this service must be effective at once")
		})
	}
}

// TestRevocationTakesEffectWithinTTL is the documented bound for the one case
// the hooks cannot cover: a peer node revoking the token, which this node sees
// only as a change in the store beneath it.
func TestRevocationTakesEffectWithinTTL(t *testing.T) {
	svc, dao, now := newClockedTokenService(t)
	insertToken(t, dao, "jti-peer-revoked")
	ctx := context.Background()

	revoked, err := svc.IsRevoked(ctx, "jti-peer-revoked")
	require.NoError(t, err)
	require.False(t, revoked)

	// Revoked behind this node's back — straight through the DAO, exactly as a
	// peer node's write would appear.
	require.NoError(t, dao.Revoke(ctx, "jti-peer-revoked"))

	revoked, err = svc.IsRevoked(ctx, "jti-peer-revoked")
	require.NoError(t, err)
	assert.False(t, revoked, "inside the TTL the memoised answer still stands")

	*now = now.Add(revocationCacheTTL)
	dao.reset()
	revoked, err = svc.IsRevoked(ctx, "jti-peer-revoked")
	require.NoError(t, err)
	assert.True(t, revoked, "revocation must take effect within revocationCacheTTL")
	assert.Equal(t, 1, dao.count(), "the expired entry must be re-read, not extended")
}

// TestDeferredRevocationBoundaryIsExact guards ADR 0022 §2 against the memo: a
// rotation grace window ends when it says it does, not up to revocationCacheTTL
// later. It runs on the real clock, because the boundary being asserted is the
// token record's own revoked_at instant — and it is the only test here that
// needs to: a memo that ignored revoked_at would still be answering "not
// revoked" at the point this test checks, since the grace is far shorter than
// the TTL.
func TestDeferredRevocationBoundaryIsExact(t *testing.T) {
	dao := &countingTokenDAO{TokenDAO: memory.NewTokenDAO()}
	svc := NewTokenService(dao)
	insertToken(t, dao, "jti-rotating")
	ctx := context.Background()

	const grace = 50 * time.Millisecond
	require.Less(t, grace, revocationCacheTTL, "the grace must close well inside the TTL for this to prove anything")
	require.NoError(t, svc.RevokeTokenAt(ctx, "jti-rotating", time.Now().Add(grace)))

	revoked, err := svc.IsRevoked(ctx, "jti-rotating")
	require.NoError(t, err)
	require.False(t, revoked, "the old bearer keeps validating during the grace window")

	time.Sleep(grace + 25*time.Millisecond)

	dao.reset()
	revoked, err = svc.IsRevoked(ctx, "jti-rotating")
	require.NoError(t, err)
	assert.True(t, revoked, "the memo must not extend a rotation grace window")
	assert.Equal(t, 1, dao.count(), "the capped entry must lapse at the grace instant and be re-read")
}

// TestRevocationCacheCapsEntryAtGraceInstant is the same rule stated against
// the cache alone, on a driven clock: a future revoked_at shortens the entry,
// a past or absent one leaves the full TTL.
func TestRevocationCacheCapsEntryAtGraceInstant(t *testing.T) {
	base := time.Now()
	c := newRevocationCache()
	c.now = func() time.Time { return base }

	grace := revocationCacheTTL / 4
	c.putIfCurrent("deferred", false, base.Add(grace), c.generation())
	c.putIfCurrent("plain", false, time.Time{}, c.generation())
	c.putIfCurrent("already-revoked", true, base.Add(-time.Hour), c.generation())

	assert.Equal(t, base.Add(grace), c.entries["deferred"].expires)
	assert.Equal(t, base.Add(revocationCacheTTL), c.entries["plain"].expires)
	assert.Equal(t, base.Add(revocationCacheTTL), c.entries["already-revoked"].expires)

	// A revoked_at beyond the TTL cannot lengthen the entry.
	c.putIfCurrent("far-future", false, base.Add(time.Hour), c.generation())
	assert.Equal(t, base.Add(revocationCacheTTL), c.entries["far-future"].expires)
}

// TestRevocationCacheEvictsWhenFull keeps the memo bounded: JTIs are unbounded
// over a process lifetime, and dropping entries costs a re-read, never a wrong
// answer.
func TestRevocationCacheEvictsWhenFull(t *testing.T) {
	c := newRevocationCache()
	c.max = 4
	base := time.Now()
	c.now = func() time.Time { return base }

	for i := 0; i < 40; i++ {
		c.putIfCurrent(string(rune('a'+i%26))+string(rune('0'+i/26)), false, time.Time{}, c.generation())
	}
	assert.LessOrEqual(t, len(c.entries), c.max)
}

// blockingTokenDAO lets a test hold FindByJTI open so a revoke can land in the
// middle of an in-flight revocation read — the straddle the cache generation
// exists to defeat.
type blockingTokenDAO struct {
	interfaces.TokenDAO
	release chan struct{}
	entered chan struct{}
	once    sync.Once
}

func (d *blockingTokenDAO) FindByJTI(ctx context.Context, jti string) (*model.TokenRecord, error) {
	rec, err := d.TokenDAO.FindByJTI(ctx, jti)
	// Snapshot before blocking. The memory store hands back a live pointer, and
	// the revoke this test interleaves mutates it in place — without the copy
	// the caller would observe the revoke through the pointer and the straddle
	// under test could not occur at all.
	if rec != nil {
		snapshot := *rec
		rec = &snapshot
	}
	// Signal once, then wait: the caller has read a pre-revoke record and has
	// not yet cached it.
	d.once.Do(func() { close(d.entered) })
	<-d.release
	return rec, err
}

// TestRevokeDuringInFlightReadIsNotStraddled pins the ordering that would
// otherwise install a stale "not revoked" for the whole TTL: the reader loads
// the pre-revoke record, RevokeToken runs both its invalidations against a memo
// that has no entry yet, and only then does the reader cache what it read.
func TestRevokeDuringInFlightReadIsNotStraddled(t *testing.T) {
	dao := &blockingTokenDAO{
		TokenDAO: memory.NewTokenDAO(),
		release:  make(chan struct{}),
		entered:  make(chan struct{}),
	}
	svc := NewTokenService(dao)
	nowVal := time.Now()
	svc.revocations.now = func() time.Time { return nowVal }
	insertToken(t, dao, "jti-straddled")
	ctx := context.Background()

	readDone := make(chan bool, 1)
	go func() {
		revoked, err := svc.IsRevoked(ctx, "jti-straddled")
		require.NoError(t, err)
		readDone <- revoked
	}()

	<-dao.entered
	require.NoError(t, svc.RevokeToken(ctx, "jti-straddled"))
	close(dao.release)

	// The in-flight read legitimately returns the pre-revoke answer; what it
	// must NOT do is leave that answer in the memo.
	<-readDone

	// Same instant on the memo's clock, so nothing has expired. A cached
	// "not revoked" here would survive revocationCacheTTL.
	revoked, err := svc.IsRevoked(ctx, "jti-straddled")
	require.NoError(t, err)
	assert.True(t, revoked, "a revoke that landed during an in-flight read must not be overwritten by that read")
}
