// Package eventRouter is the exported embedding surface for the community
// business-stream event router. It re-exports the minimal construct-and-drive
// API plus the subject-carrying metering observer hook so an out-of-tree
// superset (the enterprise edition, enterprise#86) can embed and meter the
// router without importing internal/ (issue #218).
//
// Boundary note — reconciles PRD #50 / PR #54. PR #54 deliberately kept the
// router in internal/eventRouter to restore the pkg/internal seam. This facade
// does NOT move or fork that router: the implementation, its tests, and the
// pkg/internal discipline #50 established all stay in internal/eventRouter.
// What crosses the boundary is only this deliberately narrow, exported wrapper —
// type aliases over the internal contract plus one constructor — so #50's seam
// is preserved (community keeps a single router) while the enterprise superset
// gains a no-internal-import embedding point. The enterprise product owner
// authorized the export direction on 2026-06-27.
package eventRouter

import (
	internalrouter "github.com/i2-open/i2goSignals/internal/eventRouter"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// Direction labels a MeteringObservation as ingress or egress.
type Direction = internalrouter.Direction

const (
	// DirectionIngress marks an event accepted into the router on an inbound stream.
	DirectionIngress = internalrouter.DirectionIngress
	// DirectionEgress marks an event routed out to a matching transmitter stream.
	DirectionEgress = internalrouter.DirectionEgress
)

// MeteringObservation is the per-routed-event record carrying {stream_urn,
// direction, subject}. It is the type a MeteringObserver receives.
type MeteringObservation = internalrouter.MeteringObservation

// MeteringObserver receives one MeteringObservation per routed event. Implement
// it in the embedder to aggregate business-stream usage; it carries the event
// subject that the Prometheus counter hook cannot.
type MeteringObserver = internalrouter.MeteringObserver

// Deps is the dependency bundle NewBusinessRouter needs. The embedder populates
// the exported service fields (pkg/services) and supplies a Coordinator value
// obtained from the persistence layer — it never has to name an internal/ type.
type Deps = internalrouter.RouterDeps

// BusinessRouter is the minimal construct-and-drive surface an embedder uses:
// feed inbound events, sync stream state, register the metering observer, and
// shut down. It is intentionally narrower than the full internal EventRouter
// (no cluster/SSTP/wake/Prometheus methods) per the minimal-surface AC of #218 —
// just what the enterprise superset needs to embed and drive the router.
type BusinessRouter interface {
	// HandleEvent ingests an inbound SET on stream sid, persists it, and fans it
	// out to matching transmitter streams. It fires the registered metering
	// observer once for the ingress and once per egress.
	HandleEvent(eventToken *goSet.SecurityEventToken, rawEvent string, sid string) error
	// UpdateStreamState (re)syncs a stream's state into the router.
	UpdateStreamState(stream *model.StreamStateRecord)
	// RegisterMeteringObserver installs the subject-carrying metering observer.
	// Distinct from any Prometheus wiring; /metrics is unaffected.
	RegisterMeteringObserver(observer MeteringObserver)
	// Shutdown stops the router's delivery goroutines.
	Shutdown()
}

// NewBusinessRouter constructs the community business-stream router behind the
// minimal BusinessRouter surface. nodeId is this node's cluster identity. The
// returned router is the same deep internal implementation #50 protects; only
// the exposed surface is narrowed.
func NewBusinessRouter(deps Deps, nodeId string) BusinessRouter {
	return internalrouter.NewRouter(deps, nodeId)
}
