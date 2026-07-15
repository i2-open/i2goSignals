package eventRouter

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/i2-open/i2goSignals/internal/providers/dbProviders"
	"github.com/i2-open/i2goSignals/pkg/authSupport"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/goSetPush"
	"github.com/i2-open/i2goSignals/pkg/services"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// pbResignHarness wires a router with the PRODUCTION push delivery seam
// (delivery.NewHTTPAdapter via PushDelivery:nil) so prepareAndSendEvent drives
// the real sign-and-push path. Used to lock the PB re-sign contract (#200):
// jti/txn preserved, per-stream iss/aud, copy-before-mutate concurrency safety.
type pbResignHarness struct {
	router        *router
	streamService *services.StreamService
	keyService    *services.KeyService
	eventService  *services.EventService
}

func newPBResignRouter(t *testing.T) *pbResignHarness {
	t.Helper()
	t.Setenv("I2SIG_STORE_MEM_DIRECTORY", t.TempDir())
	persistence, err := dbProviders.OpenPersistence("memorydb:", "pb_resign_test")
	require.NoError(t, err)
	t.Cleanup(func() {
		if persistence.Storage != nil {
			_ = persistence.Storage.Close()
		}
	})

	// PushDelivery left nil so NewRouter wires the production HTTPAdapter.
	r := NewRouter(RouterDeps{
		StreamService: persistence.StreamService,
		KeyService:    persistence.KeyService,
		EventService:  persistence.EventService,
		Coordinator:   persistence.Coordinator,
	}, "node-pb-resign").(*router)
	t.Cleanup(r.Shutdown)

	return &pbResignHarness{
		router:        r,
		streamService: persistence.StreamService,
		keyService:    persistence.KeyService,
		eventService:  persistence.EventService,
	}
}

// createPBStream creates a PUBLISH-mode push stream with the supplied iss/aud and
// receiver endpoint.
func (h *pbResignHarness) createPBStream(t *testing.T, projectId, iss string, aud []string, endpointURL string) *model.StreamStateRecord {
	t.Helper()
	cfg := model.StreamConfiguration{
		Iss:             iss,
		Aud:             aud,
		RouteMode:       model.RouteModePublish,
		EventsDelivered: []string{"https://schemas.openid.net/secevent/risc/event-type/account-disabled"},
		Delivery: &model.OneOfStreamConfigurationDelivery{
			PushTransmitMethod: &model.PushTransmitMethod{
				Method:      model.DeliveryPush,
				EndpointUrl: endpointURL,
			},
		},
	}
	ctx := context.WithValue(context.Background(), authSupport.AuthContextKey, authSupport.ConvertProject(projectId))
	created, err := h.streamService.CreateStream(ctx, model.StreamStateRecord{StreamConfiguration: cfg}, projectId, nil)
	require.NoError(t, err)
	state, err := h.streamService.GetStreamState(context.Background(), created.Id)
	require.NoError(t, err)
	require.NotNil(t, state)
	return state
}

// addSharedEvent persists one event carrying jti+txn and a source iss/aud, then
// makes it pending on every supplied stream so a single stored event fans out.
func (h *pbResignHarness) addSharedEvent(t *testing.T, jti, txn string, sids ...string) {
	t.Helper()
	token := &goSet.SecurityEventToken{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:       jti,
			Issuer:   "https://source-issuer.example.com",
			Audience: jwt.ClaimStrings{"https://source-audience.example.com"},
		},
		TransactionId: txn,
		Events: map[string]interface{}{
			"https://schemas.openid.net/secevent/risc/event-type/account-disabled": map[string]interface{}{},
		},
	}
	ctx := context.Background()
	rec, err := h.eventService.AddEvent(ctx, token, sids[0], "")
	require.NoError(t, err)
	for _, sid := range sids {
		require.NoError(t, h.eventService.AddEventToStream(ctx, rec.Jti, sid))
	}
}

// TestPrepareAndSendEvent_PBConcurrentFanOutProductionPath drives the real
// prepareAndSendEvent caller against the production HTTPAdapter push seam with
// concurrent fan-out across two PB streams that have distinct iss/aud. It asserts
// each receiver only ever sees a SET signed under its own stream's identity (no
// cross-stream iss/aud leak) and that jti+txn are preserved verbatim — under -race,
// proving the copy-before-mutate path is concurrency-safe (PRD #196 #200).
func TestPrepareAndSendEvent_PBConcurrentFanOutProductionPath(t *testing.T) {
	h := newPBResignRouter(t)
	projectId := projectIdFromHarness(t, &testHarness{
		router:        h.router,
		streamService: h.streamService,
		keyService:    h.keyService,
	})

	var muA, muB sync.Mutex
	var bodiesA, bodiesB []string
	recvA := httptest.NewServer(captureSETBody(&bodiesA, &muA))
	defer recvA.Close()
	recvB := httptest.NewServer(captureSETBody(&bodiesB, &muB))
	defer recvB.Close()

	streamA := h.createPBStream(t, projectId, "https://issuer-A.example.com", []string{"https://aud-A.example.com"}, recvA.URL+"/events")
	streamB := h.createPBStream(t, projectId, "https://issuer-B.example.com", []string{"https://aud-B.example.com"}, recvB.URL+"/events")

	keyA, _ := rsa.GenerateKey(rand.Reader, 2048)
	keyB, _ := rsa.GenerateKey(rand.Reader, 2048)

	// Pre-seed every event so each one is pending on BOTH streams before either
	// consumes it — the shared stored event is the thing two streams race to read
	// and re-sign. Each stream is then drained by its own goroutine, modelling the
	// production single-owner-per-stream push loop: two streams fanning out the same
	// events in parallel (not two goroutines mutating one stream's loop state).
	const iterations = 15
	jtis := make([]string, iterations)
	for i := 0; i < iterations; i++ {
		jti := goSet.GenerateJti()
		jtis[i] = jti
		h.addSharedEvent(t, jti, "txn-"+jti, streamA.StreamConfiguration.Id, streamB.StreamConfiguration.Id)
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for _, jti := range jtis {
			cls, _, _ := h.router.prepareAndSendEvent(jti, streamA, keyA, "kid-A", 0)
			assert.Equal(t, goSetPush.ClassAccepted, cls.Class)
		}
	}()
	go func() {
		defer wg.Done()
		for _, jti := range jtis {
			cls, _, _ := h.router.prepareAndSendEvent(jti, streamB, keyB, "kid-B", 0)
			assert.Equal(t, goSetPush.ClassAccepted, cls.Class)
		}
	}()
	wg.Wait()

	muA.Lock()
	defer muA.Unlock()
	muB.Lock()
	defer muB.Unlock()
	require.Len(t, bodiesA, iterations, "stream A receiver must see one SET per iteration")
	require.Len(t, bodiesB, iterations, "stream B receiver must see one SET per iteration")

	for _, body := range bodiesA {
		// Test-side inspection only: the captured HTTP body is examined for
		// claim shape, not accepted as a trust decision — use Peek per ADR-0066.
		parsed, err := goSet.Peek(body)
		require.NoError(t, err)
		assert.Equal(t, "https://issuer-A.example.com", parsed.Issuer, "stream A receiver must only see stream A's iss (no cross-stream leak)")
		assert.Equal(t, jwt.ClaimStrings{"https://aud-A.example.com"}, parsed.Audience, "stream A receiver must only see stream A's aud")
		assert.NotEmpty(t, parsed.ID, "jti must be present and preserved")
		assert.Equal(t, "txn-"+parsed.ID, parsed.TransactionId, "txn must be preserved verbatim alongside jti")
	}
	for _, body := range bodiesB {
		parsed, err := goSet.Peek(body)
		require.NoError(t, err)
		assert.Equal(t, "https://issuer-B.example.com", parsed.Issuer, "stream B receiver must only see stream B's iss (no cross-stream leak)")
		assert.Equal(t, jwt.ClaimStrings{"https://aud-B.example.com"}, parsed.Audience, "stream B receiver must only see stream B's aud")
		assert.NotEmpty(t, parsed.ID, "jti must be present and preserved")
		assert.Equal(t, "txn-"+parsed.ID, parsed.TransactionId, "txn must be preserved verbatim alongside jti")
	}
}

// captureSETBody records every POST body it sees and replies 202 Accepted.
func captureSETBody(bodies *[]string, mu *sync.Mutex) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		*bodies = append(*bodies, string(b))
		mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
	}
}
