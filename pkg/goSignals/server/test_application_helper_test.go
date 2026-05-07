package server

import (
    "github.com/i2-open/i2goSignals/internal/providers/dbProviders"
)

// newTestApplication builds a minimal SignalsApplication for tests that
// drive ClientPollStream / ReceiverPushStream goroutines directly without
// the full NewApplication lifecycle. After PRD #39 PR4 phase C, those
// goroutines depend on per-service references (sa.StreamService, etc.).
// Going through NewApplication would also start backgroundSync and
// receiver-loop goroutines that race with the test's own loop; this
// helper populates only what the unit tests need.
func newTestApplication(provider dbProviders.DbProviderInterface) *SignalsApplication {
    return &SignalsApplication{
        Provider:      provider,
        StreamService: provider.(serviceSource).GetStreamService(),
        KeyService:    provider.(serviceSource).GetKeyService(),
        EventService:  provider.(serviceSource).GetEventService(),
        ClientService: provider.(serviceSource).GetClientService(),
        ServerService: provider.(serviceSource).GetServerService(),
        TokenService:  provider.(serviceSource).GetTokenService(),
        Storage:       providerStorageAdapter{source: provider.(storageSource)},
    }
}
