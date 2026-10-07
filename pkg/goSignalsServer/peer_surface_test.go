package goSignalsServer_test

// Issue #373: the peer-plane surface. Like admin_surface_test.go this is an
// EXTERNAL test package whose import list names only pkg/... packages — the
// proof that enterprise can build and mount the peer routes without an
// internal/ import (ADR 0049 r1).

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/gorilla/mux"

	"github.com/i2-open/i2goSignals/pkg/dao/memory"
	pkgrouter "github.com/i2-open/i2goSignals/pkg/eventRouter"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/goSignalsServer"
	"github.com/i2-open/i2goSignals/pkg/services"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// newPeerSurface stands up the peer surface the way enterprise would: open
// persistence and build the business router through pkg/eventRouter, then hand
// the router and the public services to NewPeerSurface.
func newPeerSurface(t *testing.T) (*goSignalsServer.PeerSurface, *services.KeyService) {
	t.Helper()
	t.Setenv("I2SIG_STORE_MEM_DIRECTORY", t.TempDir())
	p, err := pkgrouter.OpenPersistence("memorydb:", "pkg_peer_surface_test")
	if err != nil {
		t.Fatalf("OpenPersistence: %v", err)
	}
	t.Cleanup(func() {
		if p.Storage != nil {
			_ = p.Storage.Close()
		}
	})
	if err := p.KeyService.InitializeTokenKey(context.Background(), testDefaultIssuer); err != nil {
		t.Fatalf("InitializeTokenKey: %v", err)
	}
	br := pkgrouter.NewBusinessRouter(pkgrouter.Deps{
		StreamService: p.StreamService,
		KeyService:    p.KeyService,
		EventService:  p.EventService,
		Coordinator:   p.Coordinator,
	}, "node-peer-surface-test")
	t.Cleanup(br.Shutdown)

	base, _ := url.Parse("https://gateway.example")
	surface, err := goSignalsServer.NewPeerSurface(goSignalsServer.PeerSurfaceConfig{
		StreamService: p.StreamService,
		KeyService:    p.KeyService,
		ClientService: services.NewClientService(memory.NewClientDAO(), p.KeyService),
		ServerService: services.NewServerService(memory.NewServerDAO()),
		TokenService:  services.NewTokenService(memory.NewTokenDAO()),
		Auth:          p.KeyService.GetAuthIssuer(),
		Router:        br,
		DefaultIssuer: testDefaultIssuer,
		BaseURL:       base,
	})
	if err != nil {
		t.Fatalf("NewPeerSurface with the business router: %v", err)
	}
	return surface, p.KeyService
}

// TestPeerRoutes_ExactSet: PeerRoutes() is exactly the eight routes of the
// #373 seam block, in order, each with a bound handler.
func TestPeerRoutes_ExactSet(t *testing.T) {
	surface, _ := newPeerSurface(t)

	want := []struct{ name, method, pattern string }{
		{"GenerateIat", http.MethodGet, "/iat"},
		{"RegisterClient", http.MethodPost, "/register"},
		{"TriggerEvent", http.MethodPost, "/trigger-event"},
		{"ReceivePushEvent", http.MethodPost, "/events/{id}"},
		{"VerificationRequestSSF", http.MethodPost, "/verify"},
		{"JwksJson", http.MethodGet, "/jwks.json"},
		{"JwksJsonTenant", http.MethodGet, "/jwks/{keyName:.+}"},
		{"PollEvents", http.MethodPost, "/poll/{id}"},
	}
	got := surface.PeerRoutes()
	if len(got) != len(want) {
		t.Fatalf("PeerRoutes(): got %d routes, want %d: %+v", len(got), len(want), got)
	}
	for i, w := range want {
		g := got[i]
		if g.Name != w.name || g.Method != w.method || g.Pattern != w.pattern {
			t.Errorf("route %d: got {%s %s %s}, want {%s %s %s}", i, g.Name, g.Method, g.Pattern, w.name, w.method, w.pattern)
		}
		if g.HandlerFunc == nil {
			t.Errorf("route %s has no handler", g.Name)
		}
		if g.IsIdQuery {
			t.Errorf("route %s: IsIdQuery should be false", g.Name)
		}
	}
}

// narrowRouter implements only the pkg BusinessRouter surface, not the router
// methods the peer handlers call.
type narrowRouter struct{}

func (narrowRouter) HandleEvent(*goSet.SecurityEventToken, string, string) error { return nil }
func (narrowRouter) HandleEvents([]*goSet.SecurityEventToken, []string, string) []error {
	return nil
}
func (narrowRouter) UpdateStreamState(*model.StreamStateRecord)          {}
func (narrowRouter) RegisterMeteringObserver(pkgrouter.MeteringObserver) {}
func (narrowRouter) Shutdown()                                           {}

var _ pkgrouter.BusinessRouter = narrowRouter{}

// TestNewPeerSurface_RejectsRouterWithoutPeerMethods: a router lacking the
// methods the peer handlers call fails at construction, not per request.
func TestNewPeerSurface_RejectsRouterWithoutPeerMethods(t *testing.T) {
	_, err := goSignalsServer.NewPeerSurface(goSignalsServer.PeerSurfaceConfig{
		Router:        narrowRouter{},
		DefaultIssuer: testDefaultIssuer,
	})
	if err == nil {
		t.Fatal("NewPeerSurface accepted a router without the peer-handler methods")
	}
	for _, m := range []string{"HandleEventCtx", "SubmitOperationalEvent", "PollStreamHandler", "DeliveryStarted", "GenerateVerifyEvent"} {
		if !strings.Contains(err.Error(), m) {
			t.Errorf("error %q does not name missing method %s", err, m)
		}
	}

	if _, err := goSignalsServer.NewPeerSurface(goSignalsServer.PeerSurfaceConfig{}); err == nil {
		t.Fatal("NewPeerSurface accepted a nil router")
	}
}

// TestAdminAndPeerOnOneRouter_JwksDispatchByMethod: with both surfaces on one
// gorilla router, GET /jwks/{keyName} serves the JWKS and POST /jwks/{keyName}
// reaches the admin key-create handler; neither is shadowed into a 405.
func TestAdminAndPeerOnOneRouter_JwksDispatchByMethod(t *testing.T) {
	peer, _ := newPeerSurface(t)
	admin := newAdminFixture(t)

	router := mux.NewRouter().StrictSlash(true).UseEncodedPath()
	routes := append(admin.surface.AdminRoutes(), peer.PeerRoutes()...)
	for _, rt := range routes {
		r := router.NewRoute().Name(rt.Name).Path(rt.Pattern).HandlerFunc(rt.HandlerFunc)
		if rt.Method != "" {
			r.Methods(rt.Method)
		}
	}

	rr := doJSON(t, router, http.MethodGet, "/jwks/"+testDefaultIssuer, "", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /jwks/%s: got %d, want 200 (body=%q)", testDefaultIssuer, rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"keys"`) {
		t.Errorf("GET /jwks/%s: body is not a JWKS: %q", testDefaultIssuer, rr.Body.String())
	}

	rr = doJSON(t, router, http.MethodGet, "/jwks.json", "", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /jwks.json: got %d, want 200", rr.Code)
	}

	// No bearer: the admin CreateKey handler answers 403. Reaching it at all
	// (rather than a router 405) is what proves the method dispatch.
	rr = doJSON(t, router, http.MethodPost, "/jwks/new-issuer", "", nil)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("POST /jwks/new-issuer: got %d, want 403 from the admin CreateKey handler", rr.Code)
	}
}
