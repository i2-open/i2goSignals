package eventRouter

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recordingMeteringObserver captures every MeteringObservation the router emits
// so a test can assert direction, stream_urn, and subject after driving an
// event through the live routing path.
type recordingMeteringObserver struct {
	mu           sync.Mutex
	observations []MeteringObservation
}

func (o *recordingMeteringObserver) ObserveEvent(observation MeteringObservation) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.observations = append(o.observations, observation)
}

func (o *recordingMeteringObserver) snapshot() []MeteringObservation {
	o.mu.Lock()
	defer o.mu.Unlock()
	out := make([]MeteringObservation, len(o.observations))
	copy(out, o.observations)
	return out
}

func (o *recordingMeteringObserver) byDirection(dir Direction) []MeteringObservation {
	var out []MeteringObservation
	for _, obs := range o.snapshot() {
		if obs.Direction == dir {
			out = append(out, obs)
		}
	}
	return out
}

func (o *recordingMeteringObserver) bySource(src MeteringSource) []MeteringObservation {
	var out []MeteringObservation
	for _, obs := range o.snapshot() {
		if obs.Source == src {
			out = append(out, obs)
		}
	}
	return out
}

// TestResetEventStream_EmitsEgressTaggedReset is the Q91.4 billing-escape fix
// (ADR 0055): ResetEventStream re-queues already-stored events, bypassing the
// router fan-out where egress is normally metered — so reset re-deliveries used
// to escape billing entirely. Each re-queued (stream, JTI) must now emit a
// DirectionEgress observation tagged source:reset (reset is fresh chargeable
// delivery). A subsequent re-poll of the still-pending events (protocol replay)
// must emit ZERO additional observations — charged once at reset, free
// thereafter, per Q91.4 "free by construction".
func TestResetEventStream_EmitsEgressTaggedReset(t *testing.T) {
	s := setupDedupRouterPollStream(t)

	observer := &recordingMeteringObserver{}
	s.h.router.RegisterMeteringObserver(observer)

	ctx := context.Background()
	state, err := s.h.streamService.GetStreamState(ctx, s.streamID)
	require.NoError(t, err)

	const n = 3
	for i := 0; i < n; i++ {
		token := newRiscToken(fmt.Sprintf("reset-jti-%d", i), dupTestIssuer, s.audience)
		token.SubjectId = (&goSet.SubjectIdentifier{}).AddEmail(fmt.Sprintf("user%d@example.com", i))
		require.NoError(t, s.h.router.HandleEvent(token, `{"raw":true}`, s.streamID))
	}

	// Baseline: fan-out produced n normal (source-empty) egress observations and
	// no reset-tagged ones yet.
	require.Len(t, observer.byDirection(DirectionEgress), n, "fan-out egress before reset")
	require.Empty(t, observer.bySource(SourceReset), "no reset observations before a reset")

	// Reset by date: re-queue every stored, matching, non-operational event —
	// exactly the predicate the stream-management handler applies.
	resetDate := time.Now().Add(-time.Hour)
	err = s.h.router.eventService.ResetEventStream(ctx, s.streamID, "", &resetDate,
		func(e *model.EventRecord) bool {
			if e.Operational {
				return false
			}
			return s.h.router.eventService.MatchesStream(state, e)
		})
	require.NoError(t, err)

	reset := observer.bySource(SourceReset)
	require.Len(t, reset, n, "one reset-tagged egress per re-queued (stream, JTI) — date reset")
	for _, obs := range reset {
		assert.Equal(t, DirectionEgress, obs.Direction, "reset re-delivery is egress")
		assert.Equal(t, s.streamID, obs.StreamURN, "reset egress urn is the target stream")
		require.NotNil(t, obs.Subject, "reset observation carries the event subject")
	}

	// Protocol replay: re-polling the now-pending events (a failed-ack re-poll)
	// must NOT re-observe — GetEventIds never re-enters fan-out or reset.
	before := len(observer.snapshot())
	_, _ = s.h.router.eventService.GetEventIds(ctx, s.streamID, model.PollParameters{MaxEvents: 100})
	_, _ = s.h.router.eventService.GetEventIds(ctx, s.streamID, model.PollParameters{MaxEvents: 100})
	assert.Equal(t, before, len(observer.snapshot()),
		"re-polling pending events (protocol replay) must emit zero additional observations")

	// Reset by JTI: re-queue the reference event and every following one. Reset to
	// the first JTI re-delivers all n events again, each a fresh source:reset egress.
	err = s.h.router.eventService.ResetEventStream(ctx, s.streamID, "reset-jti-0", nil,
		func(e *model.EventRecord) bool {
			if e.Operational {
				return false
			}
			return s.h.router.eventService.MatchesStream(state, e)
		})
	require.NoError(t, err)
	assert.Len(t, observer.bySource(SourceReset), 2*n,
		"a JTI reset re-delivering n events adds n more reset-tagged egress observations")
}

// TestRegisterMeteringObserver_FiresIngressOnLivePath is the ingress half of the
// production-wiring AC (#218): it registers a metering observer on a real router
// and drives one event through HandleEvent on the live routing path (not a
// fake). The observer must fire exactly one ingress observation carrying the
// inbound stream's urn and the event's subject identity.
func TestRegisterMeteringObserver_FiresIngressOnLivePath(t *testing.T) {
	s := setupDedupRouterPollStream(t)

	observer := &recordingMeteringObserver{}
	s.h.router.RegisterMeteringObserver(observer)

	token := newRiscToken("metering-ingress-jti", dupTestIssuer, s.audience)
	token.SubjectId = (&goSet.SubjectIdentifier{}).AddEmail("alice@example.com")

	require.NoError(t, s.h.router.HandleEvent(token, `{"raw":true}`, s.streamID))

	ingress := observer.byDirection(DirectionIngress)
	require.Len(t, ingress, 1, "exactly one ingress observation per accepted event")
	assert.Equal(t, s.streamID, ingress[0].StreamURN, "ingress urn is the inbound stream id")
	require.NotNil(t, ingress[0].Subject, "ingress observation must carry the event subject")
	assert.Equal(t, "alice@example.com", ingress[0].Subject.Email, "ingress subject identity captured")
}

// TestRegisterMeteringObserver_FiresEgressOnLivePath is the egress half of the
// production-wiring AC (#218): the same event, driven through the live router,
// is fanned out to the matching poll-transmit (business) stream. The observer
// must fire an egress observation carrying the matched transmitter stream's urn
// and the same subject identity.
func TestRegisterMeteringObserver_FiresEgressOnLivePath(t *testing.T) {
	s := setupDedupRouterPollStream(t)

	observer := &recordingMeteringObserver{}
	s.h.router.RegisterMeteringObserver(observer)

	token := newRiscToken("metering-egress-jti", dupTestIssuer, s.audience)
	token.SubjectId = (&goSet.SubjectIdentifier{}).AddEmail("bob@example.com")

	require.NoError(t, s.h.router.HandleEvent(token, `{"raw":true}`, s.streamID))

	egress := observer.byDirection(DirectionEgress)
	require.Len(t, egress, 1, "exactly one egress observation per matched transmitter stream")
	assert.Equal(t, s.streamID, egress[0].StreamURN, "egress urn is the matched transmitter stream id")
	require.NotNil(t, egress[0].Subject, "egress observation must carry the event subject")
	assert.Equal(t, "bob@example.com", egress[0].Subject.Email, "egress subject identity captured")
}

// TestMeteringObserver_DistinctFromPrometheusCounter proves the metering hook is
// a separate seam from SetEventCounter (#218 AC): a registered observer fires
// while the Prometheus inbound counter increments exactly once, unchanged. The
// two surfaces coexist — the observer carries the subject the counter cannot,
// and registering it does not perturb /metrics.
func TestMeteringObserver_DistinctFromPrometheusCounter(t *testing.T) {
	s := setupDedupRouterPollStream(t)

	observer := &recordingMeteringObserver{}
	s.h.router.RegisterMeteringObserver(observer)

	token := newRiscToken("metering-distinct-jti", dupTestIssuer, s.audience)
	token.SubjectId = (&goSet.SubjectIdentifier{}).AddEmail("carol@example.com")

	require.NoError(t, s.h.router.HandleEvent(token, `{"raw":true}`, s.streamID))

	// Prometheus path is unchanged: exactly one inbound count, as the
	// observer-free dedup tests already assert.
	assert.InDelta(t, 1.0, inCounterValue(t, s.inCounter, s.streamID), 0.0001,
		"registering a metering observer must not change the Prometheus inbound counter")

	// The distinct metering seam fired both directions, carrying the subject the
	// Prometheus counter cannot express.
	assert.Len(t, observer.byDirection(DirectionIngress), 1, "one ingress observation")
	assert.Len(t, observer.byDirection(DirectionEgress), 1, "one egress observation")
}

// TestMeteringObserver_DuplicateJTI_NotObserved confirms the metering seam
// inherits the router's JTI-dedup short-circuit: a duplicate ingestion that the
// Prometheus path already suppresses produces no second observation either.
func TestMeteringObserver_DuplicateJTI_NotObserved(t *testing.T) {
	s := setupDedupRouterPollStream(t)

	observer := &recordingMeteringObserver{}
	s.h.router.RegisterMeteringObserver(observer)

	token := newRiscToken("metering-dup-jti", dupTestIssuer, s.audience)
	token.SubjectId = (&goSet.SubjectIdentifier{}).AddEmail("dave@example.com")

	require.NoError(t, s.h.router.HandleEvent(token, `{"first":true}`, s.streamID))
	require.NoError(t, s.h.router.HandleEvent(token, `{"second":true}`, s.streamID))

	assert.Len(t, observer.byDirection(DirectionIngress), 1, "duplicate JTI must not re-observe ingress")
	assert.Len(t, observer.byDirection(DirectionEgress), 1, "duplicate JTI must not re-observe egress")
}
