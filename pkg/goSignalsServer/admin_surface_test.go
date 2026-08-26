// Package goSignalsServer_test is an EXTERNAL test package (package
// goSignalsServer_test, not goSignalsServer). Its import list is the load-bearing
// acceptance criterion of issue #215: it imports ONLY pkg/... packages plus the
// goSignalsServer package itself and never anything under internal/. The test
// thereby proves that an out-of-tree consumer (the enterprise REST-coexistence
// binary) can build the community admin handler set from public services, mount
// it behind a runtime flag, and observe the stream/subject-filter state
// transitions — all without an internal/ import.
package goSignalsServer_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"

	"github.com/gorilla/mux"

	"github.com/i2-open/i2goSignals/pkg/authSupport"
	"github.com/i2-open/i2goSignals/pkg/dao/memory"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/goSignalsServer"
	"github.com/i2-open/i2goSignals/pkg/services"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

const testDefaultIssuer = "DEFAULT"

// recordingSink is a test StreamStateSink (the 3-method seam the caller
// implements per the #215 contract) that records every transition the admin
// mutation handlers emit, so the test can assert which ones fired.
type recordingSink struct {
	mu             sync.Mutex
	updated        []*model.StreamStateRecord
	removed        []string
	filterNotified []string
}

func (s *recordingSink) UpdateStreamState(stream *model.StreamStateRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.updated = append(s.updated, stream)
}

func (s *recordingSink) RemoveStream(sid string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.removed = append(s.removed, sid)
}

func (s *recordingSink) NotifySubjectFilterChange(sid string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.filterNotified = append(s.filterNotified, sid)
}

func (s *recordingSink) updateCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.updated)
}

func (s *recordingSink) removeCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.removed)
}

func (s *recordingSink) filterCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.filterNotified)
}

var _ goSignalsServer.StreamStateSink = (*recordingSink)(nil)

// adminFixture bundles the public services, the constructed admin surface, the
// recording sink, and a flag recording whether the injected SubjectRelayService's
// resolve closure fired (i.e. whether a HYBRID upstream relay was attempted).
type adminFixture struct {
	surface  *goSignalsServer.AdminSurface
	sink     *recordingSink
	auth     *authSupport.AuthIssuer
	relayHit *relayProbe
}

// relayProbe records whether the injected *services.SubjectRelayService was
// driven into its upstream-relay branch. RelayHybrid only reaches resolve() when
// the handler resolved a HYBRID downstream against a NONE upstream — so a fired
// resolve closure proves the subject change relayed through the injected relay
// service (the AC: "HYBRID subject change relays through the injected
// *services.SubjectRelayService").
type relayProbe struct {
	mu       sync.Mutex
	resolved int
}

func (p *relayProbe) hit() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.resolved++
}

func (p *relayProbe) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.resolved
}

// newAdminFixture builds the public services over the in-memory DAO and
// constructs an AdminSurface from them. It uses ONLY pkg/ constructors:
// pkg/dao/memory DAOs, pkg/services service constructors, and the AuthIssuer the
// KeyService exposes — the same pattern pkg/services' own tests use. No
// dbProviders.OpenPersistence (which is internal/) is involved.
func newAdminFixture(t *testing.T) *adminFixture {
	t.Helper()
	ctx := context.Background()

	// KeyService with a real signing key so the AuthIssuer can both mint and
	// validate the admin bearer the handlers gate on.
	keyService := services.NewKeyService(memory.NewKeyDAO(), testDefaultIssuer, nil, nil)
	if err := keyService.InitializeTokenKey(ctx, testDefaultIssuer); err != nil {
		t.Fatalf("InitializeTokenKey: %v", err)
	}
	auth := keyService.GetAuthIssuer()

	streamService := services.NewStreamService(
		memory.NewStreamDAO(), keyService, testDefaultIssuer, services.StreamServiceConfig{})
	serverService := services.NewServerService(memory.NewServerDAO())
	tokenService := services.NewTokenService(memory.NewTokenDAO())
	subjectFilterService := services.NewSubjectFilterService(memory.NewSubjectFilterDAO())

	probe := &relayProbe{}
	// A SubjectRelayService whose closures resolve a NONE upstream receiver
	// matching the created HYBRID stream's issuer. The resolve closure records
	// that it ran (the observation point) and returns a benign UpstreamConn; the
	// handler tolerates a relay that does not reach a live upstream, so no HTTP
	// server is needed to observe the relay being driven.
	relayService := services.NewSubjectRelayService(
		// listReceivers: one NONE upstream whose Iss matches the created stream's
		// Iss (DefIssuer), so ResolveRelayTarget finds exactly one target.
		func(context.Context) ([]model.StreamStateRecord, error) {
			rx := model.StreamStateRecord{DefaultSubjects: model.DefaultSubjectsNone}
			rx.StreamConfiguration.Id = "upstream-receiver"
			rx.StreamConfiguration.Iss = testDefaultIssuer
			remote := "remote-stream-id"
			rx.RemoteStreamId = &remote
			return []model.StreamStateRecord{rx}, nil
		},
		// listTransmitters: empty interested-set siblings, so a fresh add is a
		// 0->1 transition and RelayHybrid engages.
		func(context.Context) ([]model.StreamStateRecord, error) {
			return nil, nil
		},
		// interested: no sibling is interested (0->1 transition).
		func(context.Context, *model.StreamStateRecord, *goSet.SubjectIdentifier) bool {
			return false
		},
		// resolve: the observation point. Firing this proves the handler drove
		// RelayHybrid into its upstream-relay branch.
		func(context.Context, *model.StreamStateRecord) (*services.UpstreamConn, error) {
			probe.hit()
			return &services.UpstreamConn{
				Config:     &model.TransmitterConfiguration{},
				HttpClient: http.DefaultClient,
			}, nil
		},
	)

	base, _ := url.Parse("https://gateway.example")
	sink := &recordingSink{}
	surface := goSignalsServer.NewAdminSurface(goSignalsServer.AdminSurfaceConfig{
		StreamService:        streamService,
		KeyService:           keyService,
		ServerService:        serverService,
		TokenService:         tokenService,
		SubjectFilterService: subjectFilterService,
		SubjectRelayService:  relayService,
		Auth:                 auth,
		DefaultIssuer:        testDefaultIssuer,
		BaseURL:              base,
		Sink:                 sink,
	})

	return &adminFixture{surface: surface, sink: sink, auth: auth, relayHit: probe}
}

// adminBearer mints an admin-scoped bearer (Roles ["admin","stream"]) the admin
// handlers accept, using only the public AuthIssuer.IssueStreamClientToken.
func (f *adminFixture) adminBearer(t *testing.T, projectId string) string {
	t.Helper()
	client := model.SsfClient{Id: model.NewRecordId(), ProjectIds: []string{projectId}}
	tok, err := f.auth.IssueStreamClientToken(client, projectId, true, "")
	if err != nil {
		t.Fatalf("IssueStreamClientToken: %v", err)
	}
	return tok
}

// mountAdmin registers the admin routes onto a fresh gorilla/mux router, exactly
// as an enterprise REST-coexistence binary would when its admin flag is on.
func mountAdmin(surface *goSignalsServer.AdminSurface) *mux.Router {
	router := mux.NewRouter().StrictSlash(true).UseEncodedPath()
	for _, rt := range surface.AdminRoutes() {
		r := router.NewRoute().Name(rt.Name).Path(rt.Pattern).HandlerFunc(rt.HandlerFunc)
		if rt.Method != "" {
			r.Methods(rt.Method)
		}
	}
	return router
}

// doJSON drives one request with the given admin bearer and returns the response
// recorder.
func doJSON(t *testing.T, router *mux.Router, method, target, bearer string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	var rdr *bytes.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, target, rdr)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	return rr
}

// TestAdminRoutesResolveAndOmittedRoute404 is AC#1 (the headline criterion): an
// admin route RESOLVES when mounted, and the same path on a router that did NOT
// mount the admin routes returns route-not-registered 404 — the enterprise
// REST-admin flag's on/off behavior ("omitting => route-not-registered 404").
func TestAdminRoutesResolveAndOmittedRoute404(t *testing.T) {
	f := newAdminFixture(t)
	bearer := f.adminBearer(t, "proj-1")

	// Mounted: GET /states resolves to a handler (anything other than the
	// router's own 404 proves the route is registered). With a valid admin
	// bearer this read-only route returns 200.
	mounted := mountAdmin(f.surface)
	rr := doJSON(t, mounted, http.MethodGet, "/states", bearer, nil)
	if rr.Code == http.StatusNotFound {
		t.Fatalf("mounted /states should resolve to the admin handler, got 404 (route not registered)")
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("mounted /states: expected 200, got %d (body=%q)", rr.Code, rr.Body.String())
	}

	// Omitted: a router with NO admin routes mounted returns 404 for the same
	// path — the route is simply not registered (the flag-off behavior).
	empty := mux.NewRouter().StrictSlash(true).UseEncodedPath()
	rr = doJSON(t, empty, http.MethodGet, "/states", bearer, nil)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("omitted /states: expected 404 (route-not-registered), got %d", rr.Code)
	}
}

// TestAdminAuthGate confirms the mounted admin handlers gate on the admin
// authorization context: a request with no bearer is rejected (not 200), and the
// minted admin bearer is accepted — proving the test drives a VALID admin
// authorization context through public inputs only.
func TestAdminAuthGate(t *testing.T) {
	f := newAdminFixture(t)
	mounted := mountAdmin(f.surface)

	// No bearer: the handler's inline ValidateAuthorizationAny rejects it.
	rr := doJSON(t, mounted, http.MethodGet, "/states", "", nil)
	if rr.Code == http.StatusOK {
		t.Fatalf("unauthenticated /states must not be authorized, got 200")
	}

	// Admin bearer: accepted.
	bearer := f.adminBearer(t, "proj-1")
	rr = doJSON(t, mounted, http.MethodGet, "/states", bearer, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("admin /states: expected 200, got %d (body=%q)", rr.Code, rr.Body.String())
	}
}

// TestStreamMutationDrivesSink drives a stream create and delete through the
// admin routes and asserts the sink's UpdateStreamState fired on create and that
// RemoveStream (and a disabling UpdateStreamState) fired on delete.
func TestStreamMutationDrivesSink(t *testing.T) {
	f := newAdminFixture(t)
	mounted := mountAdmin(f.surface)
	bearer := f.adminBearer(t, "proj-1")

	// Create a minimal PUSH transmitter stream. After a successful CreateStream
	// the handler unconditionally calls EventRouter.UpdateStreamState, which the
	// adminRouterAdapter forwards to our sink.
	createBody := mustJSON(t, map[string]any{
		"delivery": map[string]any{
			"method":       "urn:ietf:rfc:8935",
			"endpoint_url": "https://receiver.example/events",
		},
	})
	rr := doJSON(t, mounted, http.MethodPost, "/stream", bearer, createBody)
	if rr.Code != http.StatusOK && rr.Code != http.StatusCreated {
		t.Fatalf("POST /stream: expected 200/201, got %d (body=%q)", rr.Code, rr.Body.String())
	}
	if f.sink.updateCount() == 0 {
		t.Fatalf("expected UpdateStreamState to fire on stream create, got none")
	}
	streamID := streamIDFromCreate(t, rr.Body.Bytes())

	// Delete the stream: addressed via ?stream_id=<id> (which also fills the
	// auth context's StreamId). The handler disables (UpdateStreamState) then
	// RemoveStream(sid).
	updatesBefore := f.sink.updateCount()
	rr = doJSON(t, mounted, http.MethodDelete, "/stream?stream_id="+url.QueryEscape(streamID), bearer, nil)
	if rr.Code != http.StatusOK && rr.Code != http.StatusNoContent {
		t.Fatalf("DELETE /stream: expected 200/204, got %d (body=%q)", rr.Code, rr.Body.String())
	}
	if f.sink.removeCount() == 0 {
		t.Fatalf("expected RemoveStream to fire on stream delete, got none")
	}
	if removed := f.sink.removed; removed[len(removed)-1] != streamID {
		t.Fatalf("RemoveStream(sid): expected %q, got %q", streamID, removed[len(removed)-1])
	}
	if f.sink.updateCount() <= updatesBefore {
		t.Fatalf("expected a disabling UpdateStreamState on delete (before=%d after=%d)",
			updatesBefore, f.sink.updateCount())
	}
}

// TestSubjectChangeDrivesSinkAndRelay drives /add-subject on a HYBRID stream and
// asserts NotifySubjectFilterChange fired on the sink AND that the change relayed
// through the injected *services.SubjectRelayService (the resolve probe fired).
func TestSubjectChangeDrivesSinkAndRelay(t *testing.T) {
	// /add-subject is gated by the server-wide I2SIG_SUBJECT_FILTERING setting
	// (read from the environment at request time); enable it for this test.
	t.Setenv("I2SIG_SUBJECT_FILTERING", "ENABLED")

	f := newAdminFixture(t)
	mounted := mountAdmin(f.surface)
	bearer := f.adminBearer(t, "proj-1")

	// Create a HYBRID transmitter stream whose Iss defaults to DefIssuer
	// (DEFAULT), matching the relay fixture's NONE upstream receiver. The
	// NONE baseline makes a fresh Add a genuine 0->1 delivery transition, so the
	// filter service returns RelayDecisionImmediate and the handler relays
	// upstream (under ALL, an Add is a no-op and never relays).
	createBody := mustJSON(t, map[string]any{
		"delivery": map[string]any{
			"method":       "urn:ietf:rfc:8935",
			"endpoint_url": "https://receiver.example/events",
		},
		"subject_filter_mode": model.SubjectFilterModeHybrid,
		"default_subjects":    model.DefaultSubjectsNone,
	})
	rr := doJSON(t, mounted, http.MethodPost, "/stream", bearer, createBody)
	if rr.Code != http.StatusOK && rr.Code != http.StatusCreated {
		t.Fatalf("POST /stream (hybrid): expected 200/201, got %d (body=%q)", rr.Code, rr.Body.String())
	}
	streamID := streamIDFromCreate(t, rr.Body.Bytes())

	// Add a subject to the HYBRID stream. The handler applies the local filter,
	// calls NotifySubjectFilterChange(sid) on the router sink, and (HYBRID +
	// immediate decision) drives RelayHybrid through the injected relay service.
	addBody := mustJSON(t, map[string]any{
		"stream_id": streamID,
		"subject":   map[string]any{"format": "email", "email": "alice@example.com"},
		"verified":  true,
	})
	rr = doJSON(t, mounted, http.MethodPost, "/add-subject", bearer, addBody)
	if rr.Code != http.StatusOK {
		t.Fatalf("POST /add-subject: expected 200, got %d (body=%q)", rr.Code, rr.Body.String())
	}
	if f.sink.filterCount() == 0 {
		t.Fatalf("expected NotifySubjectFilterChange to fire on /add-subject, got none")
	}
	if notified := f.sink.filterNotified; notified[len(notified)-1] != streamID {
		t.Fatalf("NotifySubjectFilterChange(sid): expected %q, got %q", streamID, notified[len(notified)-1])
	}
	if f.relayHit.count() == 0 {
		t.Fatalf("expected the HYBRID subject change to relay through the injected SubjectRelayService, got none")
	}
}

// mustJSON marshals v or fails the test.
func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

// streamIDFromCreate extracts the created stream_id from a POST /stream response.
func streamIDFromCreate(t *testing.T, body []byte) string {
	t.Helper()
	var resp struct {
		StreamId string `json:"stream_id"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode create response: %v (body=%q)", err, string(body))
	}
	if resp.StreamId == "" {
		t.Fatalf("create response carried no stream_id (body=%q)", string(body))
	}
	return resp.StreamId
}
