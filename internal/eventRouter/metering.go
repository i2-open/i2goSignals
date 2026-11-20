package eventRouter

import (
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// Direction labels a metering observation as an inbound (ingress) or outbound
// (egress) routed event. It mirrors the In/Out axis of the Prometheus event
// counters (IncrementCounter) but is kept deliberately separate from them: the
// metering observer is a distinct, subject-carrying seam (issue #218).
type Direction string

const (
	// DirectionIngress marks an event accepted into the router on an inbound
	// stream — the point HandleEvent has persisted-and-counted it.
	DirectionIngress Direction = "ingress"
	// DirectionEgress marks an event routed out to a matching transmitter
	// (business) stream during fan-out.
	DirectionEgress Direction = "egress"
)

// MeteringSource tags an egress observation with the delivery path that produced
// it, so a downstream aggregator can carry a dispute-audit sub-count. It is
// additive: the empty value is normal router fan-out egress and needs no
// special-casing (ADR 0055 Q91.4).
type MeteringSource string

const (
	// SourceReset marks an egress observation produced by ResetEventStream
	// re-queuing an already-stored event. A reset is fresh chargeable delivery
	// (ADR 0055 Q91.4) and bypasses the fan-out where egress is normally metered,
	// so these observations are emitted from the reset path and tagged so the
	// enterprise aggregator can sub-count reset volume for dispute transparency.
	SourceReset MeteringSource = "reset"
)

// MeteringObservation is the per-routed-event record handed to a
// MeteringObserver. Unlike the Prometheus counter hook (SetEventCounter) it
// carries the event Subject, which distinct-set metering (MAS) requires and a
// counter cannot express.
type MeteringObservation struct {
	// StreamURN identifies the business stream the event was routed on: the
	// inbound stream id for DirectionIngress, the matched transmitter stream
	// id for DirectionEgress.
	StreamURN string
	// Direction is ingress or egress.
	Direction Direction
	// Subject is the event's RFC9493 subject identifier (the SET sub_id
	// claim), or nil when the event carries no subject (e.g. some operational
	// events). It is read from the same field the subject filter selects on.
	Subject *goSet.SubjectIdentifier
	// Source names the delivery path that produced the observation. The empty
	// value is normal router fan-out; SourceReset marks a re-delivery emitted by
	// ResetEventStream. The aggregator consumes it additively — safe to ignore
	// initially (ADR 0055 Q91.4).
	Source MeteringSource
}

// MeteringObserver receives one MeteringObservation per routed event. It is the
// subject-carrying metering seam the enterprise superset registers to aggregate
// business-stream usage; community itself registers none, so /metrics and the
// Prometheus path are unaffected (issue #218).
type MeteringObserver interface {
	ObserveEvent(observation MeteringObservation)
}

// meteringObserverHolder boxes a MeteringObserver so it can live in an
// atomic.Pointer — a lock-free read on the hot routing path with no extra
// mutex contention against the router's RWMutex.
type meteringObserverHolder struct {
	observer MeteringObserver
}

// RegisterMeteringObserver installs (or replaces) the metering observer. It is
// safe to call after construction and concurrently with routing; a nil observer
// clears it. The read side is lock-free, so HandleEvent's fan-out pays only an
// atomic load per event when no observer is registered.
func (r *router) RegisterMeteringObserver(observer MeteringObserver) {
	r.meteringObserver.Store(&meteringObserverHolder{observer: observer})
}

func (r *router) loadMeteringObserver() MeteringObserver {
	holder := r.meteringObserver.Load()
	if holder == nil {
		return nil
	}
	return holder.observer
}

// observeMeteredEvent emits one fan-out MeteringObservation (empty Source) when
// an observer is registered. A nil observer or nil token is a no-op. The Subject
// is read from the SET sub_id claim.
func (r *router) observeMeteredEvent(streamURN string, direction Direction, token *goSet.SecurityEventToken) {
	r.observeMeteredEventSourced(streamURN, direction, token, "")
}

// observeMeteredEventSourced emits one MeteringObservation tagged with source
// when an observer is registered. A nil observer or nil token is a no-op.
func (r *router) observeMeteredEventSourced(streamURN string, direction Direction, token *goSet.SecurityEventToken, source MeteringSource) {
	observer := r.loadMeteringObserver()
	if observer == nil || token == nil {
		return
	}
	observer.ObserveEvent(MeteringObservation{
		StreamURN: streamURN,
		Direction: direction,
		Subject:   token.SubjectId,
		Source:    source,
	})
}

// ObserveResetEgress implements services.ResetEgressObserver. EventService calls
// it once per event ResetEventStream re-queues onto a stream, so reset
// re-deliveries — which bypass the fan-out where egress is normally metered —
// are charged as fresh egress and tagged source:reset (ADR 0055 Q91.4). It funnels
// through the same metering observer the fan-out uses, so no observer registered
// means no-op.
func (r *router) ObserveResetEgress(streamID string, event *model.EventRecord) {
	if event == nil {
		return
	}
	r.observeMeteredEventSourced(streamID, DirectionEgress, &event.Event, SourceReset)
}
