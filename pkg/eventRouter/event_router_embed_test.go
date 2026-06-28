package eventRouter_test

import (
	"context"
	"sync"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	// IMPORTANT: this file imports NO internal/ package. It uses ONLY exported
	// github.com/i2-open/i2goSignals/pkg/... symbols — the compile-time proof
	// that an out-of-tree embedder (enterprise#87) can stand up the
	// business-stream composition root, build Deps, and construct + drive +
	// meter the router with zero internal imports. The composition-root opener
	// it relies on is eventRouter.OpenPersistence (#218 seam closure).
	"github.com/i2-open/i2goSignals/pkg/authSupport"
	pkgrouter "github.com/i2-open/i2goSignals/pkg/eventRouter"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// embedObserver implements pkgrouter.MeteringObserver naming only the exported
// package — the metering hook an embedder satisfies.
type embedObserver struct {
	mu           sync.Mutex
	observations []pkgrouter.MeteringObservation
}

func (o *embedObserver) ObserveEvent(observation pkgrouter.MeteringObservation) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.observations = append(o.observations, observation)
}

func (o *embedObserver) byDirection(dir pkgrouter.Direction) []pkgrouter.MeteringObservation {
	o.mu.Lock()
	defer o.mu.Unlock()
	var out []pkgrouter.MeteringObservation
	for _, obs := range o.observations {
		if obs.Direction == dir {
			out = append(out, obs)
		}
	}
	return out
}

// TestEmbedderRecipe_NoInternalImports is the enterprise#87 construct-and-drive
// recipe proven through the exported facade ALONE. It opens the composition-root
// persistence via eventRouter.OpenPersistence (the #218 seam closure), builds
// Deps from the returned persistence's exported fields, constructs the router,
// registers a metering observer, drives a real event through the live
// HandleEvent path, and asserts the observer fires ingress + egress. The import
// block above names zero internal/ packages: that is the whole point — this file
// compiles as an external module consumer would.
func TestEmbedderRecipe_NoInternalImports(t *testing.T) {
	t.Setenv("I2SIG_STORE_MEM_DIRECTORY", t.TempDir())

	// Composition-root opener — the ONLY symbol an embedder needs to obtain
	// Deps's services + Coordinator and the Storage handle to Close on shutdown.
	persistence, err := pkgrouter.OpenPersistence("memorydb:", "pkg_eventrouter_embed_test")
	require.NoError(t, err)
	t.Cleanup(func() {
		if persistence.Storage != nil {
			_ = persistence.Storage.Close()
		}
	})

	br := pkgrouter.NewBusinessRouter(pkgrouter.Deps{
		StreamService: persistence.StreamService,
		KeyService:    persistence.KeyService,
		EventService:  persistence.EventService,
		Coordinator:   persistence.Coordinator,
	}, "node-embed-test")
	t.Cleanup(br.Shutdown)

	observer := &embedObserver{}
	br.RegisterMeteringObserver(observer)

	// A project IAT scopes the stream create (mirrors the internal harness).
	iat, err := persistence.KeyService.GetAuthIssuer().IssueProjectIat(nil)
	require.NoError(t, err)
	parsed, err := persistence.KeyService.GetAuthIssuer().ParseAuthToken(iat)
	require.NoError(t, err)
	projectId := parsed.ProjectId

	const issuer = "https://issuer.example.com"
	const audience = "https://receiver.example.com"
	cfg := model.StreamConfiguration{
		Iss:             issuer,
		Aud:             []string{audience},
		EventsRequested: []string{typeAcctDisabled},
		Delivery: &model.OneOfStreamConfigurationDelivery{
			PollTransmitMethod: &model.PollTransmitMethod{
				Method:      model.DeliveryPoll,
				EndpointUrl: "https://transmitter.example.com/events",
			},
		},
	}
	ctx := context.WithValue(context.Background(), authSupport.AuthContextKey, authSupport.ConvertProject(projectId))
	created, err := persistence.StreamService.CreateStream(ctx, model.StreamStateRecord{StreamConfiguration: cfg}, projectId, nil)
	require.NoError(t, err)
	state, err := persistence.StreamService.GetStreamState(context.Background(), created.Id)
	require.NoError(t, err)
	br.UpdateStreamState(state)

	token := &goSet.SecurityEventToken{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:   issuer,
			Audience: jwt.ClaimStrings{audience},
		},
		Events: map[string]interface{}{typeAcctDisabled: map[string]interface{}{}},
	}
	token.ID = "pkg-embed-jti"
	token.SubjectId = (&goSet.SubjectIdentifier{}).AddEmail("erin@example.com")

	require.NoError(t, br.HandleEvent(token, `{"raw":true}`, created.Id))

	ingress := observer.byDirection(pkgrouter.DirectionIngress)
	require.Len(t, ingress, 1, "embedder seam must fire one ingress observation")
	assert.Equal(t, created.Id, ingress[0].StreamURN)
	require.NotNil(t, ingress[0].Subject)
	assert.Equal(t, "erin@example.com", ingress[0].Subject.Email)

	egress := observer.byDirection(pkgrouter.DirectionEgress)
	require.Len(t, egress, 1, "embedder seam must fire one egress observation")
	assert.Equal(t, created.Id, egress[0].StreamURN)
	require.NotNil(t, egress[0].Subject)
	assert.Equal(t, "erin@example.com", egress[0].Subject.Email)
}
