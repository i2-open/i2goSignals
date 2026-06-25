package server

import (
	"context"
	"net/url"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/i2-open/i2goSignals/internal/eventRouter"
	"github.com/i2-open/i2goSignals/pkg/authSupport"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/goSetSstp"
	"github.com/i2-open/i2goSignals/pkg/services"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// admin_surface.go is the issue #215 seam: it lets the pkg/goSignalsServer
// admin-surface wrapper build a *SignalsApplication from PUBLIC service handles
// plus a narrow stream-state sink, without standing up the full clustered
// runtime (no backgroundSync, no internal cluster server, no live receivers).
// The admin handler bodies are reused verbatim — this only changes how the
// application they run against is constructed, so the admin REST behavior is
// byte-identical to the in-binary gateway.

// AdminStreamStateSink is the narrow router surface the admin mutation handlers
// drive. The full gateway passes its real *eventRouter.EventRouter (which has
// all three methods, so it satisfies this interface directly); the wrapper
// passes a caller-supplied sink so an external consumer can observe the same
// state transitions the in-binary router would apply. The pkg/goSignalsServer
// StreamStateSink has the identical method set and is adapted onto this.
//
// Audited against issue #215 Scope §1: the admin family touches the router only
// through these three methods — UpdateStreamState/RemoveStream from the four
// stream-mutation handlers (StreamCreate/Update/Delete, UpdateStatus, plus the
// SSTP-pair helpers) and NotifySubjectFilterChange additionally from
// handleSubjectChange (/add-subject, /remove-subject).
type AdminStreamStateSink interface {
	UpdateStreamState(stream *model.StreamStateRecord)
	RemoveStream(sid string)
	NotifySubjectFilterChange(sid string)
}

// AdminAppDeps carries the public handles the admin surface is built from. Every
// field is a pkg/-exported type, so the wrapper (and, transitively, an external
// consumer) needs no internal/ import to assemble them.
type AdminAppDeps struct {
	StreamService        *services.StreamService
	KeyService           *services.KeyService
	ServerService        *services.ServerService
	TokenService         *services.TokenService
	SubjectFilterService *services.SubjectFilterService
	SubjectRelayService  *services.SubjectRelayService
	Auth                 *authSupport.AuthIssuer
	DefIssuer            string
	BaseUrl              *url.URL
	// Sink receives the stream-state transitions the admin mutation handlers
	// emit. Required; nil is treated as a no-op sink so a read-only mount does
	// not panic.
	Sink AdminStreamStateSink
}

// NewAdminApplication assembles a *SignalsApplication wired for the admin-route
// surface only (issue #215). It deliberately does NOT start the cluster
// background sync, the internal cluster server, or live receivers, and does NOT
// build the full router — the caller (pkg/goSignalsServer) mounts only
// AdminRouteTable() on its own mux. The receiver-bookkeeping maps ARE
// initialized so the StreamDelete cascade (DrainReceiver/CloseReceiver/
// HandleReceiver) runs without panicking on a nil map; with no live receivers
// those calls are inert no-ops.
func NewAdminApplication(deps AdminAppDeps) *SignalsApplication {
	sink := deps.Sink
	if sink == nil {
		sink = noopStreamStateSink{}
	}

	sa := &SignalsApplication{
		StreamService:        deps.StreamService,
		KeyService:           deps.KeyService,
		ServerService:        deps.ServerService,
		TokenService:         deps.TokenService,
		SubjectFilterService: deps.SubjectFilterService,
		SubjectRelayService:  deps.SubjectRelayService,
		Auth:                 deps.Auth,
		DefIssuer:            deps.DefIssuer,
		BaseUrl:              deps.BaseUrl,
		AdminRole:            "ADMIN",
		// Receiver bookkeeping maps so the StreamDelete cascade is safe with no
		// live receivers (writes to a nil map would panic).
		pollClients:   map[string]*ClientPollStream{},
		pushClients:   map[string]*ReceiverPushStream{},
		pushReceivers: map[string]model.StreamStateRecord{},
		// EventRouter is the sink adapter: the three admin-driven methods forward
		// to the supplied sink; the other 17 EventRouter methods are unreachable
		// from the admin family and panic loudly if ever wired into an admin
		// route (a guardrail, not an expected path).
		EventRouter: &adminRouterAdapter{sink: sink},
	}
	return sa
}

// noopStreamStateSink absorbs stream-state transitions when the caller supplies
// no sink (a read-only admin mount).
type noopStreamStateSink struct{}

func (noopStreamStateSink) UpdateStreamState(*model.StreamStateRecord) {}
func (noopStreamStateSink) RemoveStream(string)                        {}
func (noopStreamStateSink) NotifySubjectFilterChange(string)           {}

// adminRouterAdapter adapts a 3-method AdminStreamStateSink up to the full
// eventRouter.EventRouter interface that SsfApplicationInterface.GetEventRouter
// returns. Only the three methods the admin handlers call are wired; the rest
// belong to the event/cluster/storage plane the admin surface does not serve
// (issue #215 out-of-scope) and panic if reached, which can only happen if a
// non-admin route were ever bound onto an admin application by mistake.
type adminRouterAdapter struct {
	sink AdminStreamStateSink
}

func (a *adminRouterAdapter) UpdateStreamState(stream *model.StreamStateRecord) {
	a.sink.UpdateStreamState(stream)
}
func (a *adminRouterAdapter) RemoveStream(sid string) { a.sink.RemoveStream(sid) }
func (a *adminRouterAdapter) NotifySubjectFilterChange(sid string) {
	a.sink.NotifySubjectFilterChange(sid)
}

func (a *adminRouterAdapter) unsupported(method string) {
	panic("goSignalsServer admin surface: eventRouter." + method +
		" is not served by the admin-route surface (issue #215 peer/event plane is out of scope)")
}

func (a *adminRouterAdapter) HandleEvent(*goSet.SecurityEventToken, string, string) error {
	a.unsupported("HandleEvent")
	return nil
}

func (a *adminRouterAdapter) SubmitOperationalEvent(string, *goSet.SecurityEventToken, string) (*model.EventRecord, error) {
	a.unsupported("SubmitOperationalEvent")
	return nil, nil
}

func (a *adminRouterAdapter) GenerateVerifyEvent(string, string) (*model.EventRecord, error) {
	a.unsupported("GenerateVerifyEvent")
	return nil, nil
}

func (a *adminRouterAdapter) PollStreamHandler(string, model.PollParameters) (map[string]string, bool, int) {
	a.unsupported("PollStreamHandler")
	return nil, false, 0
}

func (a *adminRouterAdapter) SstpServerHandler(context.Context, string, goSetSstp.Message, []eventRouter.SstpInboundSet) (goSetSstp.Message, int) {
	a.unsupported("SstpServerHandler")
	return goSetSstp.Message{}, 0
}

func (a *adminRouterAdapter) Shutdown() { a.unsupported("Shutdown") }

func (a *adminRouterAdapter) SetEventCounter(*prometheus.CounterVec, *prometheus.CounterVec) {
	a.unsupported("SetEventCounter")
}

func (a *adminRouterAdapter) PreInitializeCounter(*model.StreamStateRecord) {
	a.unsupported("PreInitializeCounter")
}

func (a *adminRouterAdapter) GetPushStreamCnt() float64 {
	a.unsupported("GetPushStreamCnt")
	return 0
}

func (a *adminRouterAdapter) GetPollStreamCnt() float64 {
	a.unsupported("GetPollStreamCnt")
	return 0
}

func (a *adminRouterAdapter) IncrementCounter(*model.StreamStateRecord, *goSet.SecurityEventToken, bool) {
	a.unsupported("IncrementCounter")
}

func (a *adminRouterAdapter) SetStatsHandler(interface{}) { a.unsupported("SetStatsHandler") }

func (a *adminRouterAdapter) ResetStream(string) { a.unsupported("ResetStream") }

func (a *adminRouterAdapter) WakeTransmitter(string, string) { a.unsupported("WakeTransmitter") }

func (a *adminRouterAdapter) WakeSstpClient(string) { a.unsupported("WakeSstpClient") }

func (a *adminRouterAdapter) WakeSstpServer(string) { a.unsupported("WakeSstpServer") }

// Compile-time assertions: the adapter satisfies the full EventRouter
// interface, and the real *eventRouter.EventRouter satisfies the narrow sink so
// the in-binary gateway can pass its router directly with byte-identical
// behavior.
var _ eventRouter.EventRouter = (*adminRouterAdapter)(nil)
var _ AdminStreamStateSink = (eventRouter.EventRouter)(nil)
