package eventRouter

import (
	"github.com/i2-open/i2goSignals/pkg/goSet"
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

// observeMeteredEvent emits one MeteringObservation when an observer is
// registered. A nil observer or nil token is a no-op. The Subject is read from
// the SET sub_id claim.
func (r *router) observeMeteredEvent(streamURN string, direction Direction, token *goSet.SecurityEventToken) {
	observer := r.loadMeteringObserver()
	if observer == nil || token == nil {
		return
	}
	observer.ObserveEvent(MeteringObservation{
		StreamURN: streamURN,
		Direction: direction,
		Subject:   token.SubjectId,
	})
}
