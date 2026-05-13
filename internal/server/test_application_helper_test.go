package server

import (
	"github.com/i2-open/i2goSignals/internal/providers/dbProviders"
)

// newTestApplication builds a minimal SignalsApplication for tests that
// drive ClientPollStream / ReceiverPushStream goroutines directly without
// the full NewApplication lifecycle. Those goroutines depend on per-service
// references; going through NewApplication would also start backgroundSync
// and receiver-loop goroutines that race with the test's own loop. This
// helper populates only what the unit tests need.
func newTestApplication(persistence *dbProviders.Persistence) *SignalsApplication {
	return &SignalsApplication{
		Coordinator:   persistence.Coordinator,
		Storage:       persistence.Storage,
		StreamService: persistence.StreamService,
		KeyService:    persistence.KeyService,
		EventService:  persistence.EventService,
		ClientService: persistence.ClientService,
		ServerService: persistence.ServerService,
		TokenService:  persistence.TokenService,
	}
}
