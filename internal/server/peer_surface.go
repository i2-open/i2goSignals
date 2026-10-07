package server

import (
	"context"
	"net/url"

	"github.com/i2-open/i2goSignals/internal/eventRouter"
	"github.com/i2-open/i2goSignals/pkg/authSupport"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/services"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// peer_surface.go is the issue #373 seam: it lets the pkg/goSignalsServer
// peer-surface wrapper build a *SignalsApplication that serves a named subset of
// the gateway's peer routes (bootstrap, event delivery, verify, JWKS, poll) from
// public service handles plus a caller-supplied router. The handler bodies are
// the gateway's own; only the application construction differs.

// peerSurfaceRouteNames is the #373 seam's named subset of peerRoutes(). The
// rest of peerRoutes() (/, /health, /.well-known/*, the legacy /verification
// alias, /sstp/{id}, /_cluster/*, the OAuth endpoints) is left to the embedder.
var peerSurfaceRouteNames = map[string]bool{
	"GenerateIat":            true,
	"RegisterClient":         true,
	"TriggerEvent":           true,
	"ReceivePushEvent":       true,
	"VerificationRequestSSF": true,
	"JwksJson":               true,
	"JwksJsonTenant":         true,
	"PollEvents":             true,
}

// PeerEventRouter is the router surface the peer-surface handlers call:
// ReceivePushEvent ingests (HandleEventCtx), TriggerEvent submits
// (SubmitOperationalEvent), /verify generates (GenerateVerifyEvent) and
// PollEvents polls (PollStreamHandler, DeliveryStarted). The router
// eventRouter.NewRouter returns implements it.
type PeerEventRouter interface {
	HandleEventCtx(ctx context.Context, eventToken *goSet.SecurityEventToken, rawEvent string, sid string) error
	SubmitOperationalEvent(sid string, eventToken *goSet.SecurityEventToken, rawEvent string) (*model.EventRecord, error)
	GenerateVerifyEvent(sid string, state string) (*model.EventRecord, error)
	PollStreamHandler(ctx context.Context, sid string, params model.PollParameters) (map[string]string, bool, int)
	DeliveryStarted() bool
}

var _ PeerEventRouter = (eventRouter.EventRouter)(nil)

// PeerAppDeps carries the public handles the peer surface is built from.
type PeerAppDeps struct {
	StreamService *services.StreamService
	KeyService    *services.KeyService
	ClientService *services.ClientService
	ServerService *services.ServerService
	TokenService  *services.TokenService
	Auth          *authSupport.AuthIssuer
	DefIssuer     string
	BaseUrl       *url.URL
	Router        PeerEventRouter
}

// NewPeerApplication assembles a *SignalsApplication for the peer-route
// surface only. Like NewAdminApplication it starts no cluster sync, internal
// cluster server or receivers. A router that implements the full EventRouter
// (the business router does) is used as is; a narrower one is adapted.
func NewPeerApplication(deps PeerAppDeps) *SignalsApplication {
	er, ok := deps.Router.(eventRouter.EventRouter)
	if !ok {
		er = &peerRouterAdapter{peer: deps.Router}
	}
	return &SignalsApplication{
		StreamService: deps.StreamService,
		KeyService:    deps.KeyService,
		ClientService: deps.ClientService,
		ServerService: deps.ServerService,
		TokenService:  deps.TokenService,
		Auth:          deps.Auth,
		DefIssuer:     deps.DefIssuer,
		BaseUrl:       deps.BaseUrl,
		AdminRole:     "ADMIN",
		EventRouter:   er,
		pollClients:   map[string]*ClientPollStream{},
		pushClients:   map[string]*ReceiverPushStream{},
		pushReceivers: map[string]model.StreamStateRecord{},
	}
}

// PeerRouteTable returns the #373 subset of peerRoutes(), in peerRoutes()
// order, bound to this application's handlers. It filters the gateway's own
// table, so the exported routes cannot drift from what the gateway serves.
func (sa *SignalsApplication) PeerRouteTable() Routes {
	h := &HttpRouter{sa: sa}
	out := Routes{}
	for _, r := range h.peerRoutes() {
		if peerSurfaceRouteNames[r.Name] {
			out = append(out, r)
		}
	}
	return out
}

// peerRouterAdapter lifts a PeerEventRouter to the full EventRouter interface
// that SignalsApplication holds. Only the five peer methods are wired; the
// embedded EventRouter is nil, so any other method panics if reached, which
// only a non-peer route bound onto a peer application could do.
type peerRouterAdapter struct {
	eventRouter.EventRouter
	peer PeerEventRouter
}

func (a *peerRouterAdapter) HandleEventCtx(ctx context.Context, eventToken *goSet.SecurityEventToken, rawEvent string, sid string) error {
	return a.peer.HandleEventCtx(ctx, eventToken, rawEvent, sid)
}

func (a *peerRouterAdapter) SubmitOperationalEvent(sid string, eventToken *goSet.SecurityEventToken, rawEvent string) (*model.EventRecord, error) {
	return a.peer.SubmitOperationalEvent(sid, eventToken, rawEvent)
}

func (a *peerRouterAdapter) GenerateVerifyEvent(sid string, state string) (*model.EventRecord, error) {
	return a.peer.GenerateVerifyEvent(sid, state)
}

func (a *peerRouterAdapter) PollStreamHandler(ctx context.Context, sid string, params model.PollParameters) (map[string]string, bool, int) {
	return a.peer.PollStreamHandler(ctx, sid, params)
}

func (a *peerRouterAdapter) DeliveryStarted() bool { return a.peer.DeliveryStarted() }
