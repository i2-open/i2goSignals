package eventRouter

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"

	"github.com/i2-open/i2goSignals/internal/eventRouter/buffer"
)

// Poll claims (#337) are owned by the stream's delivery queue (#363). A JTI an
// RFC 8936 poll or an SSTP acceptor has taken and not yet had acked is held
// by a claim and skipped by every other claim until it is acked, its claim is
// released, or the claim expires, so two overlapping requests on one stream
// get disjoint batches. An expired claim makes its JTI servable again, which
// keeps delivery at-least-once (ADR 0038). Claims are in-memory state of the
// owner's queue only: the pending rows stay the durable source of truth, so a
// restart or a lease takeover (a fresh queue) makes the whole pending set
// servable again.

// pollClaim is one claim's hold on a JTI.
type pollClaim struct {
	token   string
	expires time.Time
}

// queueClaims is the queue's claim table. It has its own lock because the
// buffer consults it with the buffer's lock held.
type queueClaims struct {
	mu     sync.Mutex
	claims map[string]pollClaim // by inbound JTI
}

// claimTake is one claiming read's view of the queue's table: ttl is how long
// the claims it takes last.
type claimTake struct {
	c   *queueClaims
	ttl time.Duration
}

var _ buffer.Claims = claimTake{}

// Unclaimed implements buffer.Claims.
func (t claimTake) Unclaimed(now time.Time, events []string) ([]string, time.Time) {
	t.c.mu.Lock()
	defer t.c.mu.Unlock()
	next := t.c.expireLocked(now)
	if len(t.c.claims) == 0 {
		return events, next
	}
	out := make([]string, 0, len(events))
	for _, jti := range events {
		if _, held := t.c.claims[jti]; !held {
			out = append(out, jti)
		}
	}
	return out, next
}

// Take implements buffer.Claims. A ttl <= 0 takes no claim and returns token
// "". A claiming read serves a JTI once per batch: nothing in available is
// claimed on entry, so a JTI already claimed is this batch's own copy. The
// copies past the batch are hidden by the claim and removed by the ack, so
// they do not count as more.
func (t claimTake) Take(now time.Time, available []string, limit int) (string, []string, bool) {
	if t.ttl <= 0 {
		values := append(make([]string, 0, limit), available[:limit]...)
		return "", values, limit < len(available)
	}
	t.c.mu.Lock()
	defer t.c.mu.Unlock()
	if t.c.claims == nil {
		t.c.claims = map[string]pollClaim{}
	}
	token := newClaimToken()
	expires := now.Add(t.ttl)
	values := make([]string, 0, limit)
	i := 0
	for ; i < len(available) && len(values) < limit; i++ {
		jti := available[i]
		if _, dup := t.c.claims[jti]; dup {
			continue
		}
		t.c.claims[jti] = pollClaim{token: token, expires: expires}
		values = append(values, jti)
	}
	more := false
	for ; i < len(available); i++ {
		if _, dup := t.c.claims[available[i]]; !dup {
			more = true
			break
		}
	}
	return token, values, more
}

// expireLocked drops claims that expired by now and returns the earliest
// expiry still outstanding (zero when none is).
func (c *queueClaims) expireLocked(now time.Time) time.Time {
	var next time.Time
	for jti, cl := range c.claims {
		if !cl.expires.After(now) {
			delete(c.claims, jti)
			continue
		}
		if next.IsZero() || cl.expires.Before(next) {
			next = cl.expires
		}
	}
	return next
}

func newClaimToken() string {
	var raw [16]byte
	_, _ = rand.Read(raw[:])
	return hex.EncodeToString(raw[:])
}

// ClaimEvents takes up to maxEvents of buf's unclaimed JTIs under a fresh
// claim for ttl and returns its token, the JTIs, and whether more are
// unclaimed. It waits at most wait for a first unclaimed JTI (waking when a
// claim expires), returns as soon as ctx is done, and claims nothing after
// that. maxEvents <= 0 takes every unclaimed JTI; ttl <= 0 takes no claim.
func (q *deliveryQueue) ClaimEvents(ctx context.Context, buf *buffer.EventPollBuffer, maxEvents int32, wait, ttl time.Duration) (string, []string, bool) {
	token, jtis, more := buf.ClaimEventsCtx(ctx, claimTake{c: &q.claims, ttl: ttl}, maxEvents, wait)
	if jtis == nil {
		return token, nil, more
	}
	return token, *jtis, more
}

// ReleaseClaim drops every claim taken under token without acknowledging its
// JTIs, so they are served by the next claim rather than after the claim
// expires. The serve point calls it when it could not send the batch.
func (q *deliveryQueue) ReleaseClaim(token string) {
	if token == "" {
		return
	}
	q.claims.mu.Lock()
	defer q.claims.mu.Unlock()
	for jti, cl := range q.claims.claims {
		if cl.token == token {
			delete(q.claims.claims, jti)
		}
	}
}

// releaseClaims drops the claims held on jtis without acknowledging them, so
// the next claim serves them.
func (q *deliveryQueue) releaseClaims(jtis []string) {
	if len(jtis) == 0 {
		return
	}
	q.claims.mu.Lock()
	defer q.claims.mu.Unlock()
	for _, jti := range jtis {
		delete(q.claims.claims, jti)
	}
}

// ClaimedCnt is the number of JTIs held by an unexpired claim.
func (q *deliveryQueue) ClaimedCnt() int {
	q.claims.mu.Lock()
	defer q.claims.mu.Unlock()
	q.claims.expireLocked(time.Now())
	return len(q.claims.claims)
}

// ackBuffered removes acknowledged JTIs from buf and frees their claims.
func (q *deliveryQueue) ackBuffered(buf *buffer.EventPollBuffer, jtis []string) {
	if len(jtis) == 0 {
		return
	}
	buf.AckEvents(jtis)
	q.claims.mu.Lock()
	defer q.claims.mu.Unlock()
	for _, jti := range jtis {
		delete(q.claims.claims, jti)
	}
}

// clearClaims drops every claim (stream reset).
func (q *deliveryQueue) clearClaims() {
	q.claims.mu.Lock()
	defer q.claims.mu.Unlock()
	q.claims.claims = nil
}
