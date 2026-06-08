package server

import (
	"fmt"
	"io/fs"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/i2-open/i2goSignals/pkg/goSignals"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Route struct {
	Name        string
	Method      string
	Pattern     string
	HandlerFunc http.HandlerFunc
	IsIdQuery   bool
}

type HttpRouter struct {
	router *mux.Router
	sa     *SignalsApplication
}

type Routes []Route

func NewRouter(application *SignalsApplication) *HttpRouter {
	httpRouter := HttpRouter{
		router: mux.NewRouter().StrictSlash(true).UseEncodedPath(),
		sa:     application,
	}

	// Add the Prometheus middleware first so logging happens inside
	httpRouter.router.Use(PrometheusHttpMiddleware)

	// Host swagger-ui
	dist, err := fs.Sub(goSignals.SwaggerUI, "swagger-ui")
	if err != nil {
		log.Fatal(err)
	}
	httpRouter.router.PathPrefix("/swagger/").Handler(http.StripPrefix("/swagger/", http.FileServer(http.FS(dist))))

	routes := httpRouter.getRoutes()
	for _, route := range routes {
		var handler http.Handler
		handler = route.HandlerFunc
		handler = application.Logger(handler, route.Name)
		if route.IsIdQuery {
			httpRouter.router.
				Methods(route.Method).
				Path(route.Pattern).
				Name(route.Name).
				Handler(handler).
				Queries("stream_id", "{id:[^/]+}")
		} else if route.Method == "" {
			// A method-agnostic route (e.g. /sstp/{id}) matches every HTTP method
			// on its path so the handler can return an explicit 405 for the
			// disallowed ones rather than gorilla/mux 404ing an unmatched method.
			httpRouter.router.
				Path(route.Pattern).
				Name(route.Name).
				Handler(handler)
		} else {
			httpRouter.router.
				Methods(route.Method).
				Path(route.Pattern).
				Name(route.Name).
				Handler(handler)
		}

	}

	// Add prometheus handler metrics endpoint
	httpRouter.router.Path("/metrics").Handler(promhttp.Handler())

	return &httpRouter
}

// Index is a simple health check or welcome endpoint.
//
// Inputs:
//   - User-Agent (header): The user agent string of the requester.
//
// Return values:
//   - 200 OK: A greeting string including the user agent.
func (sa *SignalsApplication) Index(w http.ResponseWriter, r *http.Request) {
	test := r.UserAgent()
	_, _ = fmt.Fprintf(w, "Hello %s", test)
}

func (h *HttpRouter) getRoutes() Routes {
	routes := Routes{
		Route{
			"Index",
			"GET",
			"/",
			h.sa.Index,
			false,
		},
		Route{
			"Health",
			"GET",
			"/health",
			h.sa.Health,
			false,
		},

		Route{
			"GenerateIat",
			http.MethodGet,
			"/iat",
			h.sa.IssuerProjectIat,
			false,
		},

		Route{
			"RegisterClient",
			http.MethodPost,
			"/register",
			h.sa.RegisterClient,
			false,
		},

		Route{
			"TriggerEvent",
			http.MethodPost,
			"/trigger-event",
			h.sa.TriggerEvent,
			false,
		},

		Route{
			"ReceivePushEvent",
			http.MethodPost,
			"/events/{id}",
			h.sa.ReceivePushEvent,
			false,
		},

		Route{
			"AddSubject",
			http.MethodPost,
			"/add-subject",
			h.sa.AddSubject,
			false,
		},

		Route{
			"GetStatus",
			http.MethodGet,
			"/status",
			h.sa.GetStatus,
			false,
		},

		Route{
			"RemoveSubject",
			http.MethodPost,
			"/remove-subject",
			h.sa.RemoveSubject,
			false,
		},

		Route{
			"ReviewSubjectFilter",
			http.MethodPost,
			"/subject-filter/review",
			h.sa.ReviewSubjectFilter,
			false,
		},

		Route{
			"StreamDelete",
			http.MethodDelete,
			"/stream",
			h.sa.StreamDelete,
			false,
		},
		Route{"ListStreamStates",
			http.MethodGet,
			"/states",
			h.sa.ListStreamStates,
			false,
		},
		Route{"GetStreamState",
			http.MethodGet,
			"/state",
			h.sa.GetStreamState,
			false,
		},

		Route{
			"StreamGet",
			http.MethodGet,
			"/stream",
			h.sa.StreamGet,
			false,
		},

		Route{
			"StreamCreate",
			http.MethodPost,
			"/stream",
			h.sa.StreamCreate,
			false,
		},

		Route{
			"CreateServer",
			http.MethodPost,
			"/server",
			h.sa.CreateServer,
			false,
		},
		Route{
			"ServerList",
			http.MethodGet,
			"/server",
			h.sa.ServerList,
			false,
		},
		Route{
			"ServerGet",
			http.MethodGet,
			"/server/{alias}",
			h.sa.ServerGet,
			false,
		},
		Route{
			"ServerUpdate",
			http.MethodPut,
			"/server/{alias}",
			h.sa.ServerUpdate,
			false,
		},
		Route{
			"ServerDelete",
			http.MethodDelete,
			"/server/{alias}",
			h.sa.ServerDelete,
			false,
		},

		Route{
			"StreamReplace",
			http.MethodPut,
			"/stream",
			h.sa.StreamUpdate,
			false,
		},

		Route{
			"StreamPatch",
			http.MethodPatch,
			"/stream",
			h.sa.StreamUpdate,
			false,
		},

		Route{
			"UpdateStatus",
			http.MethodPost,
			"/status",
			h.sa.UpdateStatus,
			false,
		},

		Route{
			"VerificationRequest",
			http.MethodPost,
			"/verification",
			h.sa.VerificationRequest,
			false,
		},

		Route{
			"VerificationRequestSSF",
			http.MethodPost,
			"/verify",
			h.sa.VerificationRequest,
			false,
		},

		Route{
			"WellKnownSsfConfigurationGet",
			http.MethodGet,
			"/.well-known/ssf-configuration",
			h.sa.WellKnownSsfConfigurationGet,
			false,
		},

		Route{
			"WellKnownSsfConfigurationIssuerGet",
			http.MethodGet,
			"/.well-known/ssf-configuration/{issuer}",
			h.sa.WellKnownSsfConfigurationIssuerGet,
			false,
		},
		Route{
			"CreateKey",
			http.MethodPost,
			"/key/{keyName}",
			h.sa.CreateKey,
			false,
		},
		Route{
			"CreateKeyLegacy",
			http.MethodPost,
			"/jwks/{keyName}",
			h.sa.CreateKey,
			false,
		},

		Route{
			"KeyDelete",
			http.MethodDelete,
			"/key/{keyName}",
			h.sa.DeleteKey,
			false,
		},

		Route{
			"JwksJson",
			http.MethodGet,
			"/jwks.json",
			h.sa.JwksJson,
			false,
		},

		Route{
			"JwksIssuers",
			http.MethodGet,
			"/issuers",
			h.sa.JwksIssuers,
			false,
		},

		Route{
			Name:        "JwksSummaries",
			Method:      http.MethodGet,
			Pattern:     "/keys",
			HandlerFunc: h.sa.GetSummaries,
			IsIdQuery:   false,
		},

		Route{
			"JwksJsonTenant",
			http.MethodGet,
			"/jwks/{keyName}",
			h.sa.JwksJsonIssuer,
			false,
		},

		Route{
			"PollEvents",
			http.MethodPost,
			"/poll/{id}",
			h.sa.PollEvents,
			false,
		},

		// SSTP is registered without a method restriction so that any non-POST
		// method on /sstp/{id} reaches the handler and returns an explicit 405
		// (gorilla/mux otherwise 404s an unmatched method on a method-pinned
		// route). The handler enforces POST-only (PRD #154 Q19, Q21.a).
		Route{
			"ReceiveSstpEvent",
			"",
			"/sstp/{id}",
			h.sa.ReceiveSstpEvent,
			false,
		},

		Route{
			"WakeTransmitter",
			http.MethodPost,
			"/_cluster/wake-transmitter",
			h.sa.WakeTransmitter,
			false,
		},

		// SSTP cluster wake-up routes (PRD #154 Q11.1, Q11.2, #167). Kept separate
		// from wake-transmitter for telemetry separation; same SPIFFE/HMAC auth.
		Route{
			"WakeSstpClient",
			http.MethodPost,
			"/_cluster/wake-sstp-client",
			h.sa.WakeSstpClient,
			false,
		},
		Route{
			"WakeSstpServer",
			http.MethodPost,
			"/_cluster/wake-sstp-server",
			h.sa.WakeSstpServer,
			false,
		},

		Route{
			"ProtectedResourceMetadata",
			http.MethodGet,
			"/.well-known/oauth-protected-resource",
			h.sa.ProtectedResourceMetadata,
			false,
		},
		Route{
			"Introspect",
			http.MethodPost,
			"/introspect",
			h.sa.IntrospectHandler,
			false,
		},
		Route{
			"Revoke",
			http.MethodPost,
			"/revoke",
			h.sa.RevokeHandler,
			false,
		},
		Route{
			"TokenRevoke",
			http.MethodDelete,
			"/token/{jti}",
			h.sa.TokenRevokeHandler,
			false,
		},
		Route{
			"TokenList",
			http.MethodGet,
			"/token",
			h.sa.TokenListHandler,
			false,
		},
	}
	return routes
}
