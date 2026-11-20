package eventRouter

import (
	"context"

	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// newBareRouter returns a bare router for unit tests: the per-mode stream
// maps, a Background context and a leaseManager for deps.Coordinator on
// deps.Clock, wired the way NewRouter wires them, without NewRouter's
// goroutines, environment reads or default adapters. Tests set any other
// field they need on the result.
func newBareRouter(deps RouterDeps) *router {
	r := &router{
		ctx:               context.Background(),
		coordinator:       deps.Coordinator,
		eventService:      deps.EventService,
		streamService:     deps.StreamService,
		keyService:        deps.KeyService,
		retentionWindow:   deps.RetentionWindow,
		pushStreams:       map[string]model.StreamStateRecord{},
		pollStreams:       map[string]model.StreamStateRecord{},
		sstpClientStreams: map[string]model.StreamStateRecord{},
		sstpServerStreams: map[string]model.StreamStateRecord{},
	}
	r.leases = newLeaseManager(r.coordinator, deps.Clock)
	return r
}
