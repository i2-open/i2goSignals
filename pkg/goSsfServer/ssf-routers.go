package goSsfServer

import (
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
	sa     *SsfApplication
}

type Routes []Route

func NewRouter(application *SsfApplication) *HttpRouter {
	httpRouter := HttpRouter{
		router: mux.NewRouter().StrictSlash(true),
		sa:     application,
	}

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
			"JwksJsonTenant",
			http.MethodGet,
			"/jwks/{keyName}",
			h.sa.JwksJsonIssuer,
			false,
		},

		Route{
			"JwksJsonIssuerDelete",
			http.MethodDelete,
			"/jwks/{keyName}",
			h.sa.DeleteJwksIssuerKey,
			false,
		},
		Route{
			"KeyDelete",
			http.MethodDelete,
			"/key/{keyName}",
			h.sa.DeleteJwksIssuerKey,
			false,
		},

		Route{
			"PollEvents",
			http.MethodPost,
			"/poll/{id}",
			h.sa.PollEvents,
			false,
		},

		Route{
			"ProtectedResourceMetadata",
			http.MethodGet,
			"/.well-known/oauth-protected-resource",
			h.sa.ProtectedResourceMetadata,
			false,
		},
	}
	return routes
}
