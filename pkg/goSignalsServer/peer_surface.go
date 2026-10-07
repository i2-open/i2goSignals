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
// router. It returns an error when cfg.Router is nil or lacks a router method
// the handlers call, so a bad router fails at boot rather than per request.
func NewPeerSurface(cfg PeerSurfaceConfig) (*PeerSurface, error) {
	if cfg.Router == nil {
		return nil, fmt.Errorf("goSignalsServer: peer surface needs a Router")
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
	internal := p.app.PeerRouteTable()
	out := make(Routes, 0, len(internal))
	for _, r := range internal {
		out = append(out, Route{
			Name:        r.Name,
			Method:      r.Method,
			Pattern:     r.Pattern,
			HandlerFunc: r.HandlerFunc,
			IsIdQuery:   r.IsIdQuery,
		})
	}
	return out
}

// missingMethods names the PeerEventRouter methods v does not have.
func missingMethods(v any) []string {
	want := reflect.TypeOf((*server.PeerEventRouter)(nil)).Elem()
	have := reflect.TypeOf(v)
	var missing []string
	for i := 0; i < want.NumMethod(); i++ {
		if _, ok := have.MethodByName(want.Method(i).Name); !ok {
			missing = append(missing, want.Method(i).Name)
		}
	}
	return missing
}
