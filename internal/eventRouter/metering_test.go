package eventRouter

import (
	"sync"
	"testing"

	"github.com/i2-open/i2goSignals/pkg/goSet"
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
