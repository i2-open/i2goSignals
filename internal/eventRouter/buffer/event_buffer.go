package buffer

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"

	"github.com/i2-open/i2goSignals/pkg/logger"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
)

var bLog = logger.Sub("BUFFER")

type EventBuf interface {
	SubmitEvent(jti string)
	IsClosed() bool
	Close()
	Cnt() int
	Wakeup()
	WakeupCh() <-chan struct{}
}

type EventPollBuffer struct {
	in chan string
	// events holds the queued JTIs in submit order.
	//
	// Design note — duplicates are tolerated here, not prevented. A wake and
	// a poll's prefetch can both submit the same JTI, so it may appear more
	// than once. The alternative, a set of queued JTIs consulted on every
	// submit, made submit a map insert and ack a map delete per JTI, and the
	// set grew with the backlog (BenchmarkPollBufferSubmitDrain ~5x slower at
	// depth). Instead the submit path stays a plain append, and the duplicate
	// is made harmless where it would be seen, at no cost when there is none:
	// a claiming poll serves a JTI once per batch (the claim it writes anyway
	// doubles as the batch's seen-set) and that claim hides the other copies
	// from an overlapping poll; AckEvents removes the served batch with one
	// merge walk and only builds a set, reused across calls, when a tail is
	// left that could hold a copy. A claim-less GetEvents (the SSTP pushers,
	// which never prefetch) serves the queue as is. Copies only accumulate
	// for the life of one delivery, so the slice stays close to the true
	// backlog.
	events    []string
	mutex     sync.Mutex
	closed    bool
	notifier  chan struct{}
	pollReady bool
	// defaultTimeoutSecs is the long-poll timeout applied when a receiver
	// omits timeoutSecs (sends 0). 0 means "no implicit long-poll" — return
	// immediately on empty buffer when ReturnImmediately is false and
	// TimeoutSecs is 0.
	defaultTimeoutSecs int
	// maxTimeoutSecs caps receiver-supplied timeoutSecs. 0 disables the cap.
	maxTimeoutSecs int
	// claims holds the JTIs an RFC 8936 poll has taken and not yet had acked
	// (#337), keyed by JTI. A claimed JTI is skipped by every other poll until
	// it is acked, its claim is released, or the claim expires, so two
	// overlapping polls on one stream get disjoint batches. An expired claim
	// makes its JTI visible again, which keeps delivery at-least-once
	// (ADR 0038). Claims are in-memory state of this node's buffer only: the
	// pending list stays the durable source of truth, so no schema changes
	// and a node restart (a fresh buffer) makes the whole pending set
	// servable again.
	claims map[string]pollClaim
	// ackScratch is the set AckEvents reuses for the tail pass, kept so an
	// ack allocates nothing.
	ackScratch map[string]struct{}
}

// pollClaim is one poll's hold on a JTI.
type pollClaim struct {
	token   string
	expires time.Time
}

// CreateEventPollBuffer queues up events via an in channel; subsequently
// retrieved via EventPollBuffer.GetEvents(). The two timeout parameters
// govern long-poll behaviour for this buffer: defaultTimeoutSecs is applied
// when a receiver omits timeoutSecs, and maxTimeoutSecs (>0) caps receiver
// requests. See docs/configuration_properties.md
// (I2SIG_POLL_DEFAULT_TIMEOUT, I2SIG_POLL_MAX_TIMEOUT) for the wired-up env vars.
func CreateEventPollBuffer(initialJtis []string, defaultTimeoutSecs, maxTimeoutSecs int) *EventPollBuffer {

	buffer := &EventPollBuffer{
		in:                 make(chan string, 100),
		events:             []string{},
		pollReady:          false,
		closed:             false,
		notifier:           make(chan struct{}),
		defaultTimeoutSecs: defaultTimeoutSecs,
		maxTimeoutSecs:     maxTimeoutSecs,
		claims:             map[string]pollClaim{},
	}

	if len(initialJtis) > 0 {
		buffer.addEvents(initialJtis)
	}

	// Capture buffer.in on the spawning goroutine so the read sequences
	// before the `go` statement (program-order happens-before to the
	// spawned goroutine). Close() later writes buffer.in = nil under the
	// mutex; the spawned goroutine works against the captured channel
	// rather than re-reading buffer.in without synchronisation.
	inCh := buffer.in

	// The pump's only job is to move JTIs off `in` and into the slice that
	// GetEvents reads. It therefore runs exactly as long as `in` is open:
	// Close() closes `in`, the receive below reports !ok, inCh goes nil and the
	// loop ends.
	//
	// The loop condition is `inCh != nil` and NOT "inCh is nil and everything
	// has been read". Waiting for the events slice to drain looks tidier but is
	// a goroutine leak: once inCh is nil there is nothing left to receive, so a
	// second pass parks this goroutine on a receive from a nil channel, which
	// blocks forever. Closing a buffer that still holds unread JTIs is routine —
	// it is what happens whenever a stream is deleted or a node loses its lease
	// with events pending — so that leak was reachable on an ordinary path. The
	// Go 1.27 goroutineleak gate in `make qa` is what surfaced it; see
	// long_poll_synctest_test.go for the regression test.
	go func() {
		for inCh != nil {
			v, ok := <-inCh
			buffer.mutex.Lock()
			if !ok {
				inCh = nil
			} else {
				buffer.events = append(buffer.events, v)
				if !buffer.closed {
					close(buffer.notifier)
					buffer.notifier = make(chan struct{})
				}
			}
			buffer.mutex.Unlock()
		}

		buffer.mutex.Lock()
		if len(buffer.events) > 0 {
			bLog.Warn("The following JTIs were not read", "jtis", buffer.events)
		}
		buffer.mutex.Unlock()
	}()

	return buffer
}

// resolveTimeoutSecs applies the per-buffer default+max policy to a
// receiver-supplied timeoutSecs. Result <=0 means "return immediately".
//
//   - requested == 0: apply defaultTimeoutSecs (may itself be 0, meaning
//     no implicit long-poll).
//   - requested > 0 and maxTimeoutSecs > 0 and requested > maxTimeoutSecs:
//     silently clamp to maxTimeoutSecs (RFC8936 §2.4 makes timeoutSecs a
//     SHOULD, so clamping is spec-compliant).
//   - maxTimeoutSecs == 0: cap disabled; honour receiver value as given.
//   - requested < 0: treat as 0 (defensive; PollParameters typing makes
//     this unreachable in practice).
func (b *EventPollBuffer) resolveTimeoutSecs(requested int) int {
	if requested <= 0 {
		return b.defaultTimeoutSecs
	}
	if b.maxTimeoutSecs > 0 && requested > b.maxTimeoutSecs {
		return b.maxTimeoutSecs
	}
	return requested
}

func (b *EventPollBuffer) Cnt() int {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	return len(b.events)
}

func (b *EventPollBuffer) addEvents(jtis []string) {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	b.events = append(b.events, jtis...)
}

// AddEvents queues jtis before it returns, where SubmitEvents hands them to
// the pump goroutine. A poll that prefetched them serves them in the same
// call rather than finding the buffer still empty.
func (b *EventPollBuffer) AddEvents(jtis []string) {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	if b.closed || len(jtis) == 0 {
		return
	}
	b.events = append(b.events, jtis...)
	close(b.notifier)
	b.notifier = make(chan struct{})
}

// Absent returns the jtis this buffer does not queue. It walks the whole
// queue, so it is for the rare path that seeds a buffer from a pending read
// and then needs to know which of a batch the read already covered.
func (b *EventPollBuffer) Absent(jtis []string) []string {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	queued := make(map[string]struct{}, len(b.events))
	for _, jti := range b.events {
		queued[jti] = struct{}{}
	}
	out := make([]string, 0, len(jtis))
	for _, jti := range jtis {
		if _, ok := queued[jti]; !ok {
			out = append(out, jti)
		}
	}
	return out
}

func (b *EventPollBuffer) SubmitEvent(jti string) {
	b.SubmitEvents([]string{jti})
}

func (b *EventPollBuffer) SubmitEvents(jtis []string) {
	b.mutex.Lock()
	if b.closed {
		b.mutex.Unlock()
		return
	}
	in := b.in
	b.mutex.Unlock()

	defer func() {
		recover()
	}()
	for _, jti := range jtis {
		in <- jti
	}
}

func (b *EventPollBuffer) IsClosed() bool {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	return b.closed
}

func (b *EventPollBuffer) Close() {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	if b.closed {
		return
	}
	b.closed = true
	close(b.in)
	close(b.notifier)
}

// Wakeup sends a notification to the buffer to wake up Poller to end the current long poll session (e.g., because of stream state change)
func (b *EventPollBuffer) Wakeup() {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	if b.closed {
		return
	}
	close(b.notifier)
	b.notifier = make(chan struct{})
}

func (b *EventPollBuffer) WakeupCh() <-chan struct{} {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	return b.notifier
}

// AckEvents removes every copy of the JTIs from the buffer and releases any
// claim on them.
func (b *EventPollBuffer) AckEvents(jtis []string) {
	if len(jtis) == 0 {
		return
	}
	b.mutex.Lock()
	defer b.mutex.Unlock()
	for _, jti := range jtis {
		delete(b.claims, jti)
	}
	// A poll acks the batch it was served, which sits at the head of events
	// in the same order, so one merge walk removes it without a set.
	kept := b.events[:0]
	next := 0
	for _, jti := range b.events {
		if next < len(jtis) && jti == jtis[next] {
			next++
			continue
		}
		kept = append(kept, jti)
	}
	// Whatever is left may hold another copy of an acked JTI, or an ack
	// given out of order; one set-based pass settles both.
	if len(kept) > 0 {
		if b.ackScratch == nil {
			b.ackScratch = make(map[string]struct{}, len(jtis))
		}
		acked := b.ackScratch
		for _, jti := range jtis {
			acked[jti] = struct{}{}
		}
		n := 0
		for _, jti := range kept {
			if _, ok := acked[jti]; !ok {
				kept[n] = jti
				n++
			}
		}
		kept = kept[:n]
		clear(acked)
	}
	clear(b.events[len(kept):])
	b.events = kept
}

func (b *EventPollBuffer) Clear() {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	b.events = []string{}
	b.claims = map[string]pollClaim{}
}

// ReleaseClaim drops every claim taken under token without removing its
// JTIs, so they are served by the next poll rather than after the claim
// expires. The poll transmitter calls it when it could not send the batch.
func (b *EventPollBuffer) ReleaseClaim(token string) {
	if token == "" {
		return
	}
	b.mutex.Lock()
	defer b.mutex.Unlock()
	for jti, c := range b.claims {
		if c.token == token {
			delete(b.claims, jti)
		}
	}
}

// ClaimedCnt is the number of buffered JTIs held by an unexpired claim.
func (b *EventPollBuffer) ClaimedCnt() int {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	b.expireClaimsLocked(time.Now())
	return len(b.claims)
}

// expireClaimsLocked drops claims that expired by now and returns the
// earliest expiry still outstanding (zero when none is).
func (b *EventPollBuffer) expireClaimsLocked(now time.Time) time.Time {
	var next time.Time
	for jti, c := range b.claims {
		if !c.expires.After(now) {
			delete(b.claims, jti)
			continue
		}
		if next.IsZero() || c.expires.Before(next) {
			next = c.expires
		}
	}
	return next
}

// unclaimedLocked returns the buffered JTIs no live claim holds, in buffer
// (jti, ADR 0040) order.
func (b *EventPollBuffer) unclaimedLocked() []string {
	if len(b.claims) == 0 {
		return b.events
	}
	out := make([]string, 0, len(b.events))
	for _, jti := range b.events {
		if _, held := b.claims[jti]; !held {
			out = append(out, jti)
		}
	}
	return out
}

func newClaimToken() string {
	var raw [16]byte
	_, _ = rand.Read(raw[:])
	return hex.EncodeToString(raw[:])
}

// awaitNotify blocks until the buffer signals new events on notifier or deadline
// fires, and reports true when a notification arrived first.
//
// It takes an owned *time.Timer rather than calling time.After because the
// timeout is client-controlled: an RFC 8936 long-poll request names its own
// timeoutSecs (up to pollMaxTimeoutSecs), so a receiver that polls with the
// maximum timeout and is then woken immediately by a delivered event would,
// with time.After, leave a fully-armed runtime timer behind on every poll.
// Under Go 1.27 timer channels are unbuffered and there is no asynctimerchan
// escape hatch, so the only correct discipline is to own the timer and stop it
// on every exit path — which the deferred Stop here does.
func awaitNotify(ctx context.Context, notifier <-chan struct{}, deadline *time.Timer) bool {
	defer deadline.Stop()
	select {
	case <-notifier:
		return true
	case <-deadline.C:
		return false
	case <-ctx.Done():
		return false
	}
}

// GetEvents returns the unclaimed events in the buffer, up to
// params.MaxEvents. Events remain in the buffer until acknowledged. It takes
// no claim, so repeated calls return the same events.
func (b *EventPollBuffer) GetEvents(params model.PollParameters) (*[]string, bool) {
	_, values, more := b.collect(params, 0)
	return values, more
}

// ClaimEvents is GetEvents for an RFC 8936 poll (#337): the JTIs it returns
// are claimed under a fresh token for ttl, so an overlapping poll skips them
// and is served the next disjoint slice. The claim ends when the JTIs are
// acked (AckEvents), when ReleaseClaim(token) is called, or when ttl passes,
// after which unacked JTIs are served again. With params.ReturnImmediately
// false and nothing unclaimed it long-polls as GetEvents does, also waking
// when a claim expires. A ttl <= 0 takes no claim and returns token "".
func (b *EventPollBuffer) ClaimEvents(params model.PollParameters, ttl time.Duration) (string, *[]string, bool) {
	return b.collect(params, ttl)
}

// ResolveWait returns the long-poll wait a request asking for timeoutSecs
// gets from this buffer: the buffer's default when timeoutSecs is 0, capped
// by its maximum.
func (b *EventPollBuffer) ResolveWait(timeoutSecs int) time.Duration {
	return time.Duration(b.resolveTimeoutSecs(timeoutSecs)) * time.Second
}

// ClaimEventsCtx is ClaimEvents with the wait given explicitly and bounded by
// ctx (#365): it waits at most wait for a first unclaimed JTI, returns as
// soon as ctx is done, and claims nothing once ctx is done. A wait <= 0
// returns at once with what is ready. maxEvents <= 0 takes every unclaimed
// JTI.
func (b *EventPollBuffer) ClaimEventsCtx(ctx context.Context, maxEvents int32, wait time.Duration, ttl time.Duration) (string, *[]string, bool) {
	return b.collectWait(ctx, maxEvents, wait, ttl)
}

func (b *EventPollBuffer) collect(params model.PollParameters, ttl time.Duration) (string, *[]string, bool) {
	var wait time.Duration
	if !params.ReturnImmediately {
		wait = b.ResolveWait(params.TimeoutSecs)
	}
	return b.collectWait(context.Background(), params.MaxEvents, wait, ttl)
}

func (b *EventPollBuffer) collectWait(ctx context.Context, maxEvents int32, maxWait time.Duration, ttl time.Duration) (string, *[]string, bool) {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	nextExpiry := b.expireClaimsLocked(time.Now())
	available := b.unclaimedLocked()
	if len(available) == 0 && !b.closed && ctx.Err() == nil {
		if maxWait > 0 {
			deadline := time.Now().Add(maxWait)
			for {
				wait := time.Until(deadline)
				if wait <= 0 {
					break
				}
				// A claim expiring before the deadline frees its JTIs, so the
				// wait ends then and the buffer is re-checked.
				if !nextExpiry.IsZero() {
					if untilExpiry := nextExpiry.Sub(time.Now()); untilExpiry < wait {
						wait = max(untilExpiry, time.Millisecond)
					}
				}
				notifier := b.notifier
				b.mutex.Unlock()
				notified := awaitNotify(ctx, notifier, time.NewTimer(wait))
				b.mutex.Lock()
				nextExpiry = b.expireClaimsLocked(time.Now())
				available = b.unclaimedLocked()
				// A notification (new events, a stream-state wakeup, Close)
				// ends the long poll whatever the buffer holds, as before; an
				// expiry wake-up only ends it once something is unclaimed.
				if notified || len(available) > 0 || b.closed || ctx.Err() != nil {
					break
				}
			}
		}
	}

	if len(available) == 0 || ctx.Err() != nil {
		return "", nil, false
	}
	limit := len(available)
	if maxEvents > 0 && limit > int(maxEvents) {
		limit = int(maxEvents)
	}
	values := make([]string, 0, limit)
	if ttl <= 0 {
		values = append(values, available[:limit]...)
		return "", &values, limit < len(available)
	}

	// A claiming poll serves a JTI once per batch: nothing in available is
	// claimed on entry, so a JTI already in claims is this batch's own copy.
	// The copies past the batch are hidden by the claim and removed by the
	// ack, so they do not count as more.
	token := newClaimToken()
	expires := time.Now().Add(ttl)
	i := 0
	for ; i < len(available) && len(values) < limit; i++ {
		jti := available[i]
		if _, dup := b.claims[jti]; dup {
			continue
		}
		b.claims[jti] = pollClaim{token: token, expires: expires}
		values = append(values, jti)
	}
	more := false
	for ; i < len(available); i++ {
		if _, dup := b.claims[available[i]]; !dup {
			more = true
			break
		}
	}
	return token, &values, more
}

type EventPushBuffer struct {
	in          chan interface{}
	Out         chan interface{}
	wakeup      chan struct{}
	events      []interface{}
	eventsMutex sync.Mutex
}

// CreateEventPushBuffer creates an input and output channel that allows events to be queued up (using in channel) for a reader
// that is sending events one at a time using the Out channel
func CreateEventPushBuffer(initialJtis []string) *EventPushBuffer {

	buffer := &EventPushBuffer{
		in:          make(chan interface{}, 100),
		Out:         make(chan interface{}),
		wakeup:      make(chan struct{}, 1),
		events:      []interface{}{},
		eventsMutex: sync.Mutex{},
	}

	if len(initialJtis) > 0 {
		for _, jti := range initialJtis {
			buffer.events = append(buffer.events, jti)
		}
	}

	// Capture buffer.in on the spawning goroutine; see the matching note
	// in CreateEventPollBuffer for the happens-before reasoning.
	inCh := buffer.in

	go func() {
		for {
			buffer.eventsMutex.Lock()
			var outCh chan interface{}
			var next interface{}
			if len(buffer.events) > 0 {
				outCh = buffer.Out
				next = buffer.events[0]
			}

			if inCh == nil && outCh == nil {
				buffer.eventsMutex.Unlock()
				break
			}
			buffer.eventsMutex.Unlock()

			if outCh != nil {
				select {
				case v, ok := <-inCh:
					buffer.eventsMutex.Lock()
					if !ok {
						inCh = nil
					} else {
						buffer.events = append(buffer.events, v)
					}
					buffer.eventsMutex.Unlock()
				case outCh <- next:
					buffer.eventsMutex.Lock()
					buffer.events = buffer.events[1:]
					buffer.eventsMutex.Unlock()
				}
			} else {
				v, ok := <-inCh
				buffer.eventsMutex.Lock()
				if !ok {
					inCh = nil
				} else {
					buffer.events = append(buffer.events, v)
				}
				buffer.eventsMutex.Unlock()
			}
		}
		close(buffer.Out)
		bLog.Info("Stream buffer closing")
		buffer.eventsMutex.Lock()
		if len(buffer.events) > 0 {
			bLog.Warn("The following JTIs were not read", "jtis", buffer.events)
		}
		buffer.eventsMutex.Unlock()
	}()
	return buffer
}

func (b *EventPushBuffer) Cnt() int {
	b.eventsMutex.Lock()
	defer b.eventsMutex.Unlock()
	return len(b.events)
}

// Queued returns a snapshot of the JTIs the buffer holds, oldest first. A JTI
// submitted but not yet taken off the input channel is not included.
func (b *EventPushBuffer) Queued() []string {
	b.eventsMutex.Lock()
	defer b.eventsMutex.Unlock()
	out := make([]string, 0, len(b.events))
	for _, v := range b.events {
		if jti, ok := v.(string); ok {
			out = append(out, jti)
		}
	}
	return out
}

func (b *EventPushBuffer) addEvents(jtis []string) {
	b.eventsMutex.Lock()
	defer b.eventsMutex.Unlock()
	for _, jti := range jtis {
		b.events = append(b.events, jti)
	}
}

func (b *EventPushBuffer) SubmitEvent(jti string) {
	b.SubmitEvents([]string{jti})
}

func (b *EventPushBuffer) SubmitEvents(jtis []string) {
	b.eventsMutex.Lock()
	in := b.in
	b.eventsMutex.Unlock()

	if in == nil {
		return
	}
	defer func() {
		recover()
	}()
	for _, jti := range jtis {
		in <- jti
	}
}

func (b *EventPushBuffer) IsClosed() bool {
	b.eventsMutex.Lock()
	defer b.eventsMutex.Unlock()
	return b.in == nil
}

func (b *EventPushBuffer) Close() {
	b.eventsMutex.Lock()
	defer b.eventsMutex.Unlock()
	if b.in == nil {
		return
	}
	close(b.in)
	b.in = nil
}

func (b *EventPushBuffer) Wakeup() {
	select {
	case b.wakeup <- struct{}{}:
	default:
	}
}

func (b *EventPushBuffer) WakeupCh() <-chan struct{} {
	return b.wakeup
}
