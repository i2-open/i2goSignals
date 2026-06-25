// Package goSignalsServer exposes the community goSignals strategic gateway's
// REST admin-route surface (stream/server/key/issuer CRUD plus subject
// management) as a pkg/-importable handler set that an external Go module can
// mount onto its own *mux.Router. It is the community-side enabler for the
// enterprise REST-coexistence binary (issue #215, PRD i2goSignalsAdmin#164):
// the enterprise admin must REUSE the community admin handlers rather than
// re-implement them, and toggle their registration behind a runtime flag.
//
// The wrapper follows the pkg/goSsfServer precedent — it imports internal/server
// within this module to bind the existing handler bodies (so admin behavior is
// byte-identical to the in-binary gateway) — but the EXTERNAL caller needs only
// pkg/ imports: it builds the public services (pkg/services over pkg/dao),
// supplies a StreamStateSink, calls NewAdminSurface, and mounts AdminRoutes().
//
// Out of scope (issue #215): the always-on peer routes (/.well-known/*, /health,
// OAuth, event delivery, bootstrap) are NOT exposed here — they require the
// event/cluster/storage seam and are served by the binary directly.
package goSignalsServer

import (
	"net/http"
	"net/url"

	"github.com/i2-open/i2goSignals/internal/server"
	"github.com/i2-open/i2goSignals/pkg/authSupport"
	"github.com/i2-open/i2goSignals/pkg/services"
	ssfModels "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// Route describes one bound admin HTTP route. It mirrors the internal gateway's
// route shape so a caller can register it on a gorilla/mux router exactly as the
// in-binary server does. IsIdQuery marks the legacy `?stream_id=` query-binding
// routes; none of the current admin routes set it, but it is surfaced for
// registration parity.
type Route struct {
	Name        string
	Method      string
	Pattern     string
	HandlerFunc http.HandlerFunc
	IsIdQuery   bool
}

// Routes is an ordered admin route set.
type Routes []Route

// StreamStateSink is the narrow router surface the admin mutation handlers
// drive. The wrapper supplies it to the bound handlers so an external consumer
// observes the same three stream-state transitions the in-binary EventRouter
// would apply:
//
//   - UpdateStreamState / RemoveStream — emitted by the four stream-mutation
//     handlers (StreamCreate/Update/Delete, UpdateStatus) and the SSTP-pair
//     helpers as a stream is created, reconfigured, or torn down.
//   - NotifySubjectFilterChange — emitted additionally by the subject-management
//     handler (/add-subject, /remove-subject) so the stream's PUSH lease owner
//     invalidates its match-result cache (issue #94).
//
// The in-binary gateway passes its real *eventRouter.EventRouter here (it has
// the identical method set), so wiring through this sink does not change gateway
// behavior. HYBRID subject-change upstream relay is NOT part of this sink — it
// is driven through the injected *services.SubjectRelayService instead.
type StreamStateSink interface {
	UpdateStreamState(stream *ssfModels.StreamStateRecord)
	RemoveStream(sid string)
	NotifySubjectFilterChange(sid string)
}

// AdminSurfaceConfig holds the PUBLIC handles the admin surface is built from.
// Every field is a pkg/-exported type, so an external module assembles them
// without importing anything under internal/. SubjectRelayService is injected
// directly (it is already pkg/-public) because the subject-management handler
// drives HYBRID/PASSTHRU upstream relay through it; it is deliberately NOT part
// of the StreamStateSink.
type AdminSurfaceConfig struct {
	StreamService        *services.StreamService
	KeyService           *services.KeyService
	ServerService        *services.ServerService
	TokenService         *services.TokenService
	SubjectFilterService *services.SubjectFilterService
	SubjectRelayService  *services.SubjectRelayService
	Auth                 *authSupport.AuthIssuer
	DefaultIssuer        string
	BaseURL              *url.URL
	// Sink observes stream-state transitions emitted by the admin mutation
	// handlers. Optional; nil is treated as a no-op sink (a read-only mount).
	Sink StreamStateSink
}

// AdminSurface is a bound admin-route surface. Construct it with NewAdminSurface
// and mount AdminRoutes() onto your own router.
type AdminSurface struct {
	app *server.SignalsApplication
}

// NewAdminSurface binds the community admin handlers against the supplied public
// services and sink. The returned surface's AdminRoutes() yields the admin route
// set ready to mount; the peer routes are intentionally absent.
func NewAdminSurface(cfg AdminSurfaceConfig) *AdminSurface {
	var sink server.AdminStreamStateSink
	if cfg.Sink != nil {
		sink = sinkAdapter{cfg.Sink}
	}
	app := server.NewAdminApplication(server.AdminAppDeps{
		StreamService:        cfg.StreamService,
		KeyService:           cfg.KeyService,
		ServerService:        cfg.ServerService,
		TokenService:         cfg.TokenService,
		SubjectFilterService: cfg.SubjectFilterService,
		SubjectRelayService:  cfg.SubjectRelayService,
		Auth:                 cfg.Auth,
		DefIssuer:            cfg.DefaultIssuer,
		BaseUrl:              cfg.BaseURL,
		Sink:                 sink,
	})
	return &AdminSurface{app: app}
}

// AdminRoutes returns the admin-family route set (issue #215 Scope §1) bound to
// the surface's handlers. Mount each Route on your own *mux.Router; when a
// deployment omits them, those paths are simply not registered and resolve to
// the router's 404 (route-not-registered) — the registration toggle the
// enterprise REST-admin flag relies on.
func (a *AdminSurface) AdminRoutes() Routes {
	internal := a.app.AdminRouteTable()
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

// sinkAdapter bridges the pkg StreamStateSink to the internal server sink
// interface. The two have identical method sets; this adapter exists only to
// keep the internal interface internal while the public one is pkg/-typed.
type sinkAdapter struct {
	s StreamStateSink
}

func (a sinkAdapter) UpdateStreamState(stream *ssfModels.StreamStateRecord) {
	a.s.UpdateStreamState(stream)
}
func (a sinkAdapter) RemoveStream(sid string)              { a.s.RemoveStream(sid) }
func (a sinkAdapter) NotifySubjectFilterChange(sid string) { a.s.NotifySubjectFilterChange(sid) }
