package goSignalsServer_test

// Issue #373: the peer-plane surface. Like admin_surface_test.go this is an
// EXTERNAL test package whose import list names only pkg/... packages — the
// proof that enterprise can build and mount the peer routes without an
// internal/ import (ADR 0049 r1).

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"

	"github.com/i2-open/i2goSignals/pkg/dao/memory"
	pkgrouter "github.com/i2-open/i2goSignals/pkg/eventRouter"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/goSignalsServer"
	"github.com/i2-open/i2goSignals/pkg/services"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// peerConfig builds the peer-surface config the way enterprise would: open
// persistence and build the business router through pkg/eventRouter, then fill
// the public services. Tests override fields to exercise NewPeerSurface.
func peerConfig(t *testing.T) goSignalsServer.PeerSurfaceConfig {
	t.Helper()
	return peerConfigServing(t, true)
}

// peerConfigServing is peerConfig with the business router's ServesClaims set
// to servesClaims (#377).
func peerConfigServing(t *testing.T, servesClaims bool) goSignalsServer.PeerSurfaceConfig {
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
		ServesClaims:  servesClaims,
	}, "node-peer-surface-test")
	t.Cleanup(br.Shutdown)

	base, _ := url.Parse("https://gateway.example")
	return goSignalsServer.PeerSurfaceConfig{
		StreamService: p.StreamService,
		KeyService:    p.KeyService,
		ClientService: services.NewClientService(memory.NewClientDAO(), p.KeyService),
		ServerService: services.NewServerService(memory.NewServerDAO()),
		TokenService:  services.NewTokenService(memory.NewTokenDAO()),
		Auth:          p.KeyService.GetAuthIssuer(),
		Router:        br,
		DefaultIssuer: testDefaultIssuer,
		BaseURL:       base,
	}
}

// newPeerSurface builds the peer surface over the business router.
func newPeerSurface(t *testing.T) (*goSignalsServer.PeerSurface, *services.KeyService) {
	t.Helper()
	cfg := peerConfig(t)
	surface, err := goSignalsServer.NewPeerSurface(cfg)
	if err != nil {
		t.Fatalf("NewPeerSurface with the business router: %v", err)
	}
	return surface, cfg.KeyService
}

// mountPeer registers the peer routes on a fresh gorilla/mux router.
func mountPeer(surface *goSignalsServer.PeerSurface) *mux.Router {
	router := mux.NewRouter().StrictSlash(true).UseEncodedPath()
	for _, rt := range surface.PeerRoutes() {
		r := router.NewRoute().Name(rt.Name).Path(rt.Pattern).HandlerFunc(rt.HandlerFunc)
		if rt.Method != "" {
			r.Methods(rt.Method)
		}
	}
	return router
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
func (narrowRouter) ServesClaims() bool                                  { return true }

var _ pkgrouter.BusinessRouter = narrowRouter{}

// TestNewPeerSurface_RejectsRouterWithoutPeerMethods: a router lacking the
// methods the peer handlers call fails at construction, not per request.
func TestNewPeerSurface_RejectsRouterWithoutPeerMethods(t *testing.T) {
	cfg := peerConfig(t)
	cfg.Router = narrowRouter{}
	_, err := goSignalsServer.NewPeerSurface(cfg)
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

// wrongSigRouter has every peer method name, but GenerateVerifyEvent has the
// wrong signature, so it fails the PeerEventRouter assertion by type, not name.
type wrongSigRouter struct{ narrowRouter }

func (wrongSigRouter) HandleEventCtx(context.Context, *goSet.SecurityEventToken, string, string) error {
	return nil
}
func (wrongSigRouter) SubmitOperationalEvent(string, *goSet.SecurityEventToken, string) (*model.EventRecord, error) {
	return nil, nil
}
func (wrongSigRouter) GenerateVerifyEvent(string) (*model.EventRecord, error) { return nil, nil }
func (wrongSigRouter) PollStreamHandler(context.Context, string, model.PollParameters) (map[string]string, bool, int) {
	return nil, false, 0
}
func (wrongSigRouter) DeliveryStarted() bool { return true }

// TestNewPeerSurface_NamesWrongSignatureMethod (#374 review): a method with the
// right name but the wrong signature is named in the error, never an empty list.
func TestNewPeerSurface_NamesWrongSignatureMethod(t *testing.T) {
	cfg := peerConfig(t)
	cfg.Router = wrongSigRouter{}
	_, err := goSignalsServer.NewPeerSurface(cfg)
	if err == nil {
		t.Fatal("NewPeerSurface accepted a router whose GenerateVerifyEvent has the wrong signature")
	}
	if !strings.Contains(err.Error(), "GenerateVerifyEvent (wrong signature)") {
		t.Errorf("error %q does not name the wrong-signature method", err)
	}
	if strings.HasSuffix(strings.TrimSpace(err.Error()), ":") {
		t.Errorf("error %q ends with an empty method list", err)
	}
	for _, ok := range []string{"HandleEventCtx", "SubmitOperationalEvent", "PollStreamHandler", "DeliveryStarted"} {
		if strings.Contains(err.Error(), ok) {
			t.Errorf("error %q names %s, which has the right signature", err, ok)
		}
	}
}

// TestNewPeerSurface_RejectsNilService (#374 review): every handle the peer
// handlers read is checked at boot, so a missing one fails NewPeerSurface
// rather than a request.
func TestNewPeerSurface_RejectsNilService(t *testing.T) {
	cases := map[string]func(*goSignalsServer.PeerSurfaceConfig){
		"Auth":          func(c *goSignalsServer.PeerSurfaceConfig) { c.Auth = nil },
		"StreamService": func(c *goSignalsServer.PeerSurfaceConfig) { c.StreamService = nil },
		"KeyService":    func(c *goSignalsServer.PeerSurfaceConfig) { c.KeyService = nil },
		"ClientService": func(c *goSignalsServer.PeerSurfaceConfig) { c.ClientService = nil },
		"TokenService":  func(c *goSignalsServer.PeerSurfaceConfig) { c.TokenService = nil },
		"ServerService": func(c *goSignalsServer.PeerSurfaceConfig) { c.ServerService = nil },
	}
	base := peerConfig(t)
	for field, clear := range cases {
		t.Run(field, func(t *testing.T) {
			cfg := base
			clear(&cfg)
			_, err := goSignalsServer.NewPeerSurface(cfg)
			if err == nil {
				t.Fatalf("NewPeerSurface accepted a nil %s", field)
			}
			if !strings.Contains(err.Error(), field) {
				t.Errorf("error %q does not name the nil field %s", err, field)
			}
		})
	}
}

// peerOnlyRouter implements the pkg BusinessRouter (through the embedded
// narrowRouter) plus only the five peer methods. It does not implement the full
// internal EventRouter (no SSTP, cluster or counter methods), so NewPeerSurface
// takes the adapter path.
type peerOnlyRouter struct {
	narrowRouter
	verified []string
}

func (r *peerOnlyRouter) HandleEventCtx(context.Context, *goSet.SecurityEventToken, string, string) error {
	return nil
}
func (r *peerOnlyRouter) SubmitOperationalEvent(string, *goSet.SecurityEventToken, string) (*model.EventRecord, error) {
	return nil, nil
}
func (r *peerOnlyRouter) GenerateVerifyEvent(sid string, _ string) (*model.EventRecord, error) {
	r.verified = append(r.verified, sid)
	return &model.EventRecord{}, nil
}
func (r *peerOnlyRouter) PollStreamHandler(context.Context, string, model.PollParameters) (map[string]string, bool, int) {
	return map[string]string{}, false, http.StatusOK
}
func (r *peerOnlyRouter) DeliveryStarted() bool { return true }

// TestPeerSurface_PeerOnlyRouterThroughAdapter (#374 review): an external
// router with only the peer methods serves /verify through the adapter.
func TestPeerSurface_PeerOnlyRouterThroughAdapter(t *testing.T) {
	rt := &peerOnlyRouter{}
	// By construction the stub lacks the internal-only EventRouter methods, so
	// the adapter (not a direct EventRouter type assertion) carries the calls.
	for _, m := range []string{"SstpServerHandler", "WakeSstpServer", "ReplayStream"} {
		if _, ok := reflect.TypeOf(rt).MethodByName(m); ok {
			t.Fatalf("peerOnlyRouter has %s; it must not satisfy the full EventRouter", m)
		}
	}

	cfg := peerConfig(t)
	cfg.Router = rt
	surface, err := goSignalsServer.NewPeerSurface(cfg)
	if err != nil {
		t.Fatalf("NewPeerSurface with a peer-only router: %v", err)
	}
	router := mountPeer(surface)

	const project = "peer-project"
	stream, err := cfg.StreamService.CreateStream(context.Background(), model.StreamStateRecord{
		StreamConfiguration: model.StreamConfiguration{
			Aud:             []string{"http://rx.example"},
			EventsRequested: []string{"urn:ietf:params:sse:event-type:risc:account-enabled"},
			Delivery: &model.OneOfStreamConfigurationDelivery{
				PollTransmitMethod: &model.PollTransmitMethod{Method: model.DeliveryPoll},
			},
		},
	}, project, nil)
	if err != nil {
		t.Fatalf("CreateStream: %v", err)
	}
	client := model.SsfClient{Id: model.NewRecordId(), ProjectIds: []string{project}}
	bearer, err := cfg.Auth.IssueStreamClientToken(client, project, false, "")
	if err != nil {
		t.Fatalf("IssueStreamClientToken: %v", err)
	}

	body := []byte(`{"stream_id":"` + stream.Id + `","state":"s1"}`)
	rr := doJSON(t, router, http.MethodPost, "/verify", bearer, body)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("POST /verify: got %d, want 204 (body=%q)", rr.Code, rr.Body.String())
	}
	if len(rt.verified) != 1 || rt.verified[0] != stream.Id {
		t.Fatalf("GenerateVerifyEvent calls: got %v, want [%s]", rt.verified, stream.Id)
	}
}

// TestPeerRoutes_SmokeNoBearer (#374 review): one unauthenticated request to
// each of the eight peer routes answers without a 5xx — 200 for the JWKS
// routes, 401/403 for the authed ones — so a handler that reads a field the
// peer application does not wire fails here rather than in production.
func TestPeerRoutes_SmokeNoBearer(t *testing.T) {
	surface, _ := newPeerSurface(t)
	router := mountPeer(surface)

	cases := []struct {
		method, target string
		want           []int
	}{
		{http.MethodGet, "/iat", []int{http.StatusUnauthorized, http.StatusForbidden}},
		{http.MethodPost, "/register", []int{http.StatusUnauthorized, http.StatusForbidden}},
		{http.MethodPost, "/trigger-event", []int{http.StatusUnauthorized, http.StatusForbidden}},
		// RFC8935 §2.3: a push receiver reports an auth failure as 400 with an
		// authentication_failed error body.
		{http.MethodPost, "/events/no-such-stream", []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound}},
		{http.MethodPost, "/verify", []int{http.StatusUnauthorized, http.StatusForbidden}},
		{http.MethodGet, "/jwks.json", []int{http.StatusOK}},
		{http.MethodGet, "/jwks/" + testDefaultIssuer, []int{http.StatusOK}},
		{http.MethodPost, "/poll/no-such-stream", []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound}},
	}
	if len(cases) != len(surface.PeerRoutes()) {
		t.Fatalf("smoke covers %d routes, surface exports %d", len(cases), len(surface.PeerRoutes()))
	}
	for _, c := range cases {
		t.Run(c.method+" "+c.target, func(t *testing.T) {
			rr := doJSON(t, router, c.method, c.target, "", []byte(`{}`))
			if rr.Code >= 500 {
				t.Fatalf("got %d, a 5xx (body=%q)", rr.Code, rr.Body.String())
			}
			if !slices.Contains(c.want, rr.Code) {
				t.Errorf("got %d, want one of %v (body=%q)", rr.Code, c.want, rr.Body.String())
			}
		})
	}
}

// TestPeerSurface_ExplicitAuthWins (#376): PeerSurfaceConfig.Auth from a
// different key store than KeyService is the issuer the peer handlers validate
// with; a token minted by KeyService.GetAuthIssuer() gets 401 on /verify.
func TestPeerSurface_ExplicitAuthWins(t *testing.T) {
	cfg := peerConfig(t)
	cfg.Auth = otherIssuer(t)
	if cfg.Auth == cfg.KeyService.GetAuthIssuer() {
		t.Fatal("Auth is KeyService's issuer; the test needs two issuers")
	}
	rt := &peerOnlyRouter{}
	cfg.Router = rt
	surface, err := goSignalsServer.NewPeerSurface(cfg)
	if err != nil {
		t.Fatalf("NewPeerSurface: %v", err)
	}
	router := mountPeer(surface)

	const project = "peer-project"
	stream, err := cfg.StreamService.CreateStream(context.Background(), model.StreamStateRecord{
		StreamConfiguration: model.StreamConfiguration{
			Aud:             []string{"http://rx.example"},
			EventsRequested: []string{"urn:ietf:params:sse:event-type:risc:account-enabled"},
			Delivery: &model.OneOfStreamConfigurationDelivery{
				PollTransmitMethod: &model.PollTransmitMethod{Method: model.DeliveryPoll},
			},
		},
	}, project, nil)
	if err != nil {
		t.Fatalf("CreateStream: %v", err)
	}
	client := model.SsfClient{Id: model.NewRecordId(), ProjectIds: []string{project}}
	body := []byte(`{"stream_id":"` + stream.Id + `","state":"s1"}`)

	keyTok, err := cfg.KeyService.GetAuthIssuer().IssueStreamClientToken(client, project, false, "")
	if err != nil {
		t.Fatalf("IssueStreamClientToken (KeyService): %v", err)
	}
	rr := doJSON(t, router, http.MethodPost, "/verify", keyTok, body)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("POST /verify with a KeyService-minted bearer: got %d, want 401", rr.Code)
	}

	authTok, err := cfg.Auth.IssueStreamClientToken(client, project, false, "")
	if err != nil {
		t.Fatalf("IssueStreamClientToken (Auth): %v", err)
	}
	rr = doJSON(t, router, http.MethodPost, "/verify", authTok, body)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("POST /verify with an Auth-minted bearer: got %d, want 204 (body=%q)", rr.Code, rr.Body.String())
	}
	if len(rt.verified) != 1 || rt.verified[0] != stream.Id {
		t.Fatalf("GenerateVerifyEvent calls: got %v, want [%s]", rt.verified, stream.Id)
	}
}

// TestNewPeerSurface_RejectsRouterNotServingClaims (#377): a router built
// with ServesClaims false never takes a poll-transmitter lease, so every poll
// on the surface would answer 200 with empty sets. NewPeerSurface refuses it.
func TestNewPeerSurface_RejectsRouterNotServingClaims(t *testing.T) {
	_, err := goSignalsServer.NewPeerSurface(peerConfigServing(t, false))
	if err == nil {
		t.Fatal("NewPeerSurface accepted a router built with ServesClaims false")
	}
	if !strings.Contains(err.Error(), "ServesClaims") {
		t.Errorf("error %q does not name ServesClaims", err)
	}

	if _, err := goSignalsServer.NewPeerSurface(peerConfigServing(t, true)); err != nil {
		t.Fatalf("NewPeerSurface with ServesClaims true: %v", err)
	}
}

// TestPeerSurface_PollReturnsHandledEvent (#377): a SET the business router
// ingests through HandleEvent is returned by POST /poll/{id} on the peer
// surface's routes.
func TestPeerSurface_PollReturnsHandledEvent(t *testing.T) {
	cfg := peerConfig(t)
	surface, err := goSignalsServer.NewPeerSurface(cfg)
	if err != nil {
		t.Fatalf("NewPeerSurface: %v", err)
	}
	router := mountPeer(surface)

	const project = "peer-project"
	const aud = "http://rx.example"
	stream, err := cfg.StreamService.CreateStream(context.Background(), model.StreamStateRecord{
		StreamConfiguration: model.StreamConfiguration{
			Iss:             testDefaultIssuer,
			Aud:             []string{aud},
			EventsRequested: []string{"https://schemas.openid.net/secevent/risc/event-type/account-disabled"},
			Delivery: &model.OneOfStreamConfigurationDelivery{
				PollTransmitMethod: &model.PollTransmitMethod{Method: model.DeliveryPoll},
			},
		},
	}, project, nil)
	if err != nil {
		t.Fatalf("CreateStream: %v", err)
	}
	state, err := cfg.StreamService.GetStreamState(context.Background(), stream.Id)
	if err != nil {
		t.Fatalf("GetStreamState: %v", err)
	}
	cfg.Router.UpdateStreamState(state)

	started, ok := cfg.Router.(interface{ DeliveryStarted() bool })
	if !ok {
		t.Fatal("business router has no DeliveryStarted")
	}
	deadline := time.Now().Add(5 * time.Second)
	for !started.DeliveryStarted() {
		if time.Now().After(deadline) {
			t.Fatal("delivery did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}

	subject := &goSet.EventSubject{SubjectIdentifier: *goSet.NewScimSubjectIdentifier("/Users/peer-poll")}
	set := goSet.CreateSet(subject, testDefaultIssuer, []string{aud})
	set.AddEventPayload("https://schemas.openid.net/secevent/risc/event-type/account-disabled", map[string]interface{}{})
	if err := cfg.Router.HandleEvent(&set, "", stream.Id); err != nil {
		t.Fatalf("HandleEvent: %v", err)
	}

	bearer, err := cfg.Auth.IssueStreamToken(stream.Id, project, nil)
	if err != nil {
		t.Fatalf("IssueStreamToken: %v", err)
	}
	rr := doJSON(t, router, http.MethodPost, "/poll/"+stream.Id, bearer, []byte(`{"returnImmediately":true,"maxEvents":10}`))
	if rr.Code != http.StatusOK {
		t.Fatalf("POST /poll: got %d, want 200 (body=%q)", rr.Code, rr.Body.String())
	}
	var resp model.PollResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode poll response: %v", err)
	}
	// The router re-issues the SET on the transmitter stream under its own
	// jti, so match the SET by its subject.
	if len(resp.Sets) != 1 {
		t.Fatalf("poll returned %d SETs, want the 1 handled SET (sets=%v)", len(resp.Sets), resp.Sets)
	}
	for jti, raw := range resp.Sets {
		parts := strings.Split(raw, ".")
		if len(parts) != 3 {
			t.Fatalf("SET %s is not a compact JWS: %q", jti, raw)
		}
		claims, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			t.Fatalf("decode SET %s claims: %v", jti, err)
		}
		if !strings.Contains(string(claims), "/Users/peer-poll") {
			t.Fatalf("polled SET %s is not the handled SET: %s", jti, claims)
		}
	}
}
