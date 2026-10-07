package server

import (
	"context"
	"net/http"
	"net/url"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/i2-open/i2goSignals/internal/eventRouter"
	"github.com/i2-open/i2goSignals/pkg/authSupport"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/goSetSstp"
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
// order, bound to this application's handlers and to GetAuth() (#376).
func (sa *SignalsApplication) PeerRouteTable() Routes {
	return sa.bindSurfaceIssuer(sa.peerRouteSubset())
}

// peerRouteSubset filters the gateway's own peerRoutes() table, so the exported
// routes cannot drift from what the gateway serves.
func (sa *SignalsApplication) peerRouteSubset() Routes {
	h := &HttpRouter{sa: sa}
	out := Routes{}
	for _, r := range h.peerRoutes() {
		if peerSurfaceRouteNames[r.Name] {
			out = append(out, r)
		}
	}
	return out
}

// bindSurfaceIssuer wraps each route's handler so the request context carries
// GetAuth() (#376). Services that mint or check bearer tokens read it through
// services.WithAuthIssuer, so a surface whose Auth differs from KeyService's
// issuer never mixes two issuers.
func (sa *SignalsApplication) bindSurfaceIssuer(rs Routes) Routes {
	for i := range rs {
		next := rs[i].HandlerFunc
		rs[i].HandlerFunc = func(w http.ResponseWriter, r *http.Request) {
			next(w, r.WithContext(services.WithAuthIssuer(r.Context(), sa.GetAuth())))
		}
	}
	return rs
}

// peerRouterAdapter lifts a PeerEventRouter to the full EventRouter interface
// that SignalsApplication holds. It is the path every external router takes: an
// external module cannot implement the full EventRouter, whose SstpServerHandler
// takes an internal type. The five peer methods delegate to the router; every
// other method panics with a message naming the peer surface and the method,
// which only a non-peer route bound onto a peer application could reach.
type peerRouterAdapter struct {
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

// ServesClaims is true: the adapter carries a peer router, and
// goSignalsServer.NewPeerSurface refuses one that does not serve claims (#377).
func (a *peerRouterAdapter) ServesClaims() bool { return true }

func (a *peerRouterAdapter) unsupported(method string) {
	panic("goSignalsServer peer surface: eventRouter." + method +
		" is not served by the peer-route surface (issue #373 serves only the five peer router methods)")
}

func (a *peerRouterAdapter) UpdateStreamState(*model.StreamStateRecord) {
	a.unsupported("UpdateStreamState")
}

func (a *peerRouterAdapter) RemoveStream(string) { a.unsupported("RemoveStream") }

func (a *peerRouterAdapter) NotifySubjectFilterChange(string) {
	a.unsupported("NotifySubjectFilterChange")
}

func (a *peerRouterAdapter) HandleEvent(*goSet.SecurityEventToken, string, string) error {
	a.unsupported("HandleEvent")
	return nil
}

func (a *peerRouterAdapter) HandleEvents([]*goSet.SecurityEventToken, []string, string) []error {
	a.unsupported("HandleEvents")
	return nil
}

func (a *peerRouterAdapter) HandleEventsCtx(context.Context, []*goSet.SecurityEventToken, []string, string) []error {
	a.unsupported("HandleEventsCtx")
	return nil
}

func (a *peerRouterAdapter) CheckSstpSigningKey(*model.StreamStateRecord) error {
	a.unsupported("CheckSstpSigningKey")
	return nil
}

func (a *peerRouterAdapter) SstpServerHandler(context.Context, *model.StreamStateRecord, goSetSstp.Message, []eventRouter.SstpInboundSet) (goSetSstp.Message, error) {
	a.unsupported("SstpServerHandler")
	return goSetSstp.Message{}, nil
}

func (a *peerRouterAdapter) Shutdown() { a.unsupported("Shutdown") }

func (a *peerRouterAdapter) SetEventCounter(*prometheus.CounterVec, *prometheus.CounterVec) {
	a.unsupported("SetEventCounter")
}

func (a *peerRouterAdapter) RegisterMeteringObserver(eventRouter.MeteringObserver) {
	a.unsupported("RegisterMeteringObserver")
}

func (a *peerRouterAdapter) PreInitializeCounter(*model.StreamStateRecord) {
	a.unsupported("PreInitializeCounter")
}

func (a *peerRouterAdapter) GetPushStreamCnt() float64 {
	a.unsupported("GetPushStreamCnt")
	return 0
}

func (a *peerRouterAdapter) GetPollStreamCnt() float64 {
	a.unsupported("GetPollStreamCnt")
	return 0
}

func (a *peerRouterAdapter) IncrementCounter(*model.StreamStateRecord, *goSet.SecurityEventToken, bool) {
	a.unsupported("IncrementCounter")
}

func (a *peerRouterAdapter) SetStatsHandler(interface{}) { a.unsupported("SetStatsHandler") }

func (a *peerRouterAdapter) ResetStream(string) { a.unsupported("ResetStream") }

func (a *peerRouterAdapter) ReplayStream(context.Context, string, string, *time.Time) error {
	a.unsupported("ReplayStream")
	return nil
}

func (a *peerRouterAdapter) WakeTransmitter(string, string) { a.unsupported("WakeTransmitter") }

func (a *peerRouterAdapter) WakeSstpClient(string) { a.unsupported("WakeSstpClient") }

func (a *peerRouterAdapter) WakeSstpServer(string) { a.unsupported("WakeSstpServer") }

var _ eventRouter.EventRouter = (*peerRouterAdapter)(nil)
