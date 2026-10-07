package goSignalsServer

// Issue #373: the peer-plane surface, sibling to AdminSurface. It exposes a
// named subset of the gateway's always-on peer routes (bootstrap, event
// delivery, verify, JWKS, poll) bound to the gateway's own handlers, so an
// external module (the enterprise server, enterprise#206) can serve the peer
// plane with only pkg/ imports. PeerRoutes() returns routes for the caller to
// register on its own router alongside AdminRoutes(); on one gorilla router
// GET /jwks/{keyName} (peer) and POST /jwks/{keyName} (admin) then dispatch by
// method.
//
// Not exported: /, /health, /.well-known/*, the legacy /verification alias,
// /sstp/{id}, /_cluster/* and the OAuth endpoints. The embedder owns health and
// discovery.

import (
	"fmt"
	"net/url"
	"reflect"
	"strings"

	"github.com/i2-open/i2goSignals/internal/server"
	"github.com/i2-open/i2goSignals/pkg/authSupport"
	"github.com/i2-open/i2goSignals/pkg/eventRouter"
	"github.com/i2-open/i2goSignals/pkg/services"
)

// PeerSurfaceConfig holds the public handles the peer surface is built from.
// Router is normally the router eventRouter.NewBusinessRouter returns; it must
// also implement the router methods the peer handlers call, which
// NewPeerSurface checks.
type PeerSurfaceConfig struct {
	StreamService *services.StreamService
	KeyService    *services.KeyService
	ClientService *services.ClientService
	ServerService *services.ServerService
	TokenService  *services.TokenService
	// Auth validates and mints this surface's bearer tokens. It is required,
	// and it takes precedence over KeyService.GetAuthIssuer(): an embedder may
	// pass an issuer from a different key store than KeyService (#376). Requests
	// through the surface's routes carry it to the services; an embedder
	// calling StreamService or ClientService directly binds it with
	// services.WithAuthIssuer(ctx, Auth), or those mint with KeyService's issuer.
	Auth          *authSupport.AuthIssuer
	Router        eventRouter.BusinessRouter
	DefaultIssuer string
	BaseURL       *url.URL
}

// PeerSurface is a bound peer-route surface. Construct it with NewPeerSurface
// and register PeerRoutes() on your own router.
type PeerSurface struct {
	app *server.SignalsApplication
}

// NewPeerSurface binds the peer handlers against the supplied services and
// router. It returns an error when cfg.Router or a service handle the handlers
// read is nil, the router lacks a router method the handlers call, or the
// router was built without ServesClaims (it would answer every poll with no
// SETs, #377), so a bad config fails at boot rather than per request.
func NewPeerSurface(cfg PeerSurfaceConfig) (*PeerSurface, error) {
	if cfg.Router == nil {
		return nil, fmt.Errorf("goSignalsServer: peer surface needs a Router")
	}
	if nils := nilPeerFields(cfg); len(nils) > 0 {
		return nil, fmt.Errorf("goSignalsServer: peer surface config has nil %s", strings.Join(nils, ", "))
	}
	if !cfg.Router.ServesClaims() {
		return nil, fmt.Errorf("goSignalsServer: peer surface Router does not serve claims; " +
			"build it with eventRouter.Deps{ServesClaims: true}: the peer plane (poll, SSTP acceptor) needs ServesClaims")
	}
	peer, ok := cfg.Router.(server.PeerEventRouter)
	if !ok {
		return nil, fmt.Errorf("goSignalsServer: peer surface Router %T lacks methods the peer handlers call: %s",
			cfg.Router, strings.Join(missingMethods(cfg.Router), ", "))
	}
	app := server.NewPeerApplication(server.PeerAppDeps{
		StreamService: cfg.StreamService,
		KeyService:    cfg.KeyService,
		ClientService: cfg.ClientService,
		ServerService: cfg.ServerService,
		TokenService:  cfg.TokenService,
		Auth:          cfg.Auth,
		DefIssuer:     cfg.DefaultIssuer,
		BaseUrl:       cfg.BaseURL,
		Router:        peer,
	})
	return &PeerSurface{app: app}, nil
}

// PeerRoutes returns the peer routes bound to the surface's handlers, with the
// same names, methods and patterns the community gateway registers.
func (p *PeerSurface) PeerRoutes() Routes {
	return toRoutes(p.app.PeerRouteTable())
}

// nilPeerFields names the service handles in cfg that are nil.
func nilPeerFields(cfg PeerSurfaceConfig) []string {
	var nils []string
	for _, f := range []struct {
		name  string
		isNil bool
	}{
		{"Auth", cfg.Auth == nil},
		{"StreamService", cfg.StreamService == nil},
		{"KeyService", cfg.KeyService == nil},
		{"ClientService", cfg.ClientService == nil},
		{"TokenService", cfg.TokenService == nil},
		{"ServerService", cfg.ServerService == nil},
	} {
		if f.isNil {
			nils = append(nils, f.name)
		}
	}
	return nils
}

// missingMethods names the PeerEventRouter methods v lacks, and those it has
// with a different signature as "Name (wrong signature)". Called only after v
// failed the PeerEventRouter assertion, it never returns an empty list.
func missingMethods(v any) []string {
	want := reflect.TypeOf((*server.PeerEventRouter)(nil)).Elem()
	have := reflect.ValueOf(v)
	var missing []string
	for i := 0; i < want.NumMethod(); i++ {
		m := want.Method(i)
		got := have.MethodByName(m.Name)
		switch {
		case !got.IsValid():
			missing = append(missing, m.Name)
		case got.Type() != m.Type:
			missing = append(missing, m.Name+" (wrong signature)")
		}
	}
	if len(missing) == 0 {
		missing = append(missing, "(unidentified; see server.PeerEventRouter)")
	}
	return missing
}
