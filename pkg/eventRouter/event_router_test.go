package eventRouter_test

import (
	"context"
	"sync"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	// dbProviders (internal) is used only to stand up persistence for the test —
	// that is the composition-root seam an embedder wires separately (enterprise
	// #87). The router seam under test below names ONLY exported pkg/ types.
	"github.com/i2-open/i2goSignals/internal/providers/dbProviders"
	"github.com/i2-open/i2goSignals/pkg/authSupport"
	pkgrouter "github.com/i2-open/i2goSignals/pkg/eventRouter"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

const typeAcctDisabled = "https://schemas.openid.net/secevent/risc/event-type/account-disabled"

// recordingObserver implements pkgrouter.MeteringObserver — proving an embedder
// can satisfy the metering hook naming only the exported package.
type recordingObserver struct {
	mu           sync.Mutex
	observations []pkgrouter.MeteringObservation
}

func (o *recordingObserver) ObserveEvent(observation pkgrouter.MeteringObservation) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.observations = append(o.observations, observation)
}

func (o *recordingObserver) byDirection(dir pkgrouter.Direction) []pkgrouter.MeteringObservation {
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

// TestExportedBusinessRouter_DrivesAndObserves proves the #218 export AC end to
// end through the EXPORTED facade only: construct the router via
// pkgrouter.NewBusinessRouter naming only exported types, register a metering
// observer, drive a real event through the live HandleEvent path, and assert the
// observer fires ingress + egress with the correct stream_urn and subject.
func TestExportedBusinessRouter_DrivesAndObserves(t *testing.T) {
	t.Setenv("I2SIG_STORE_MEM_DIRECTORY", t.TempDir())
	persistence, err := dbProviders.OpenPersistence("memorydb:", "pkg_eventrouter_test")
	require.NoError(t, err)
	t.Cleanup(func() {
		if persistence.Storage != nil {
			_ = persistence.Storage.Close()
		}
	})

	// Construct the router naming only pkgrouter.Deps + pkg/services values. The
	// Coordinator flows through from persistence without the embedder naming the
	// internal cluster type — the no-internal-import seam #218 requires.
	br := pkgrouter.NewBusinessRouter(pkgrouter.Deps{
		StreamService: persistence.StreamService,
		KeyService:    persistence.KeyService,
		EventService:  persistence.EventService,
		Coordinator:   persistence.Coordinator,
	}, "node-pkg-test")
	t.Cleanup(br.Shutdown)

	observer := &recordingObserver{}
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
	token.ID = "pkg-export-jti"
	token.SubjectId = (&goSet.SubjectIdentifier{}).AddEmail("erin@example.com")

	require.NoError(t, br.HandleEvent(token, `{"raw":true}`, created.Id))

	ingress := observer.byDirection(pkgrouter.DirectionIngress)
	require.Len(t, ingress, 1, "exported seam must fire one ingress observation")
	assert.Equal(t, created.Id, ingress[0].StreamURN)
	require.NotNil(t, ingress[0].Subject)
	assert.Equal(t, "erin@example.com", ingress[0].Subject.Email)

	egress := observer.byDirection(pkgrouter.DirectionEgress)
	require.Len(t, egress, 1, "exported seam must fire one egress observation")
	assert.Equal(t, created.Id, egress[0].StreamURN)
	require.NotNil(t, egress[0].Subject)
	assert.Equal(t, "erin@example.com", egress[0].Subject.Email)
}
