/*
 * Stream Management API for OpenID Shared Security Events
 *
 * [OpenID Spec](https://openid.net/specs/openid-sse-framework-1_0.html#management)  HTTP API to be implemented by Event Transmitters. This API can be used by Event Receivers to query and update the Event Stream configuration and status, to add and remove subjects, and to trigger verification.
 *
 * API version: 1.0.0
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */
package server

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Route struct {
	Name        string
	Method      string
	Pattern     string
	HandlerFunc http.HandlerFunc
}

type HttpRouter struct {
	router *mux.Router
	sa     *SignalsApplication
}

type Routes []Route

func NewRouter(application *SignalsApplication) *HttpRouter {
	httpRouter := HttpRouter{
		router: mux.NewRouter().StrictSlash(true),
		sa:     application,
	}

	// Add the Prometheus middleware first so logging happens inside
	httpRouter.router.Use(PrometheusHttpMiddleware)
	// httpRouter.router.Use()
	routes := httpRouter.getRoutes()

	for _, route := range routes {
		var handler http.Handler
		handler = route.HandlerFunc
		handler = application.Logger(handler, route.Name)

		httpRouter.router.
			Methods(route.Method).
			Path(route.Pattern).
			Name(route.Name).
			Handler(handler)
	}

	// Add prometheus handler at metrics endpoint
	httpRouter.router.Path("/metrics").Handler(promhttp.Handler())

	return &httpRouter
}

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
		},

		Route{
			"Register",
			http.MethodPost,
			"/register",
			h.sa.Register,
		},

		Route{
			"TriggerEvent",
			strings.ToUpper("Post"),
			"/trigger-event",
			h.sa.TriggerEvent,
		},

		Route{
			"ReceivePushEvent",
			strings.ToUpper("Post"),
			"/events",
			h.sa.ReceivePushEvent,
		},

		Route{
			"AddSubject",
			strings.ToUpper("Post"),
			"/add-subject",
			h.sa.AddSubject,
		},

		Route{
			"GetStatus",
			strings.ToUpper("Get"),
			"/status",
			h.sa.GetStatus,
		},

		Route{
			"RemoveSubject",
			strings.ToUpper("Post"),
			"/remove-subject",
			h.sa.RemoveSubject,
		},

		Route{
			"StreamDelete",
			strings.ToUpper("Delete"),
			"/stream",
			h.sa.StreamDelete,
		},

		Route{
			"StreamGet",
			strings.ToUpper("Get"),
			"/stream",
			h.sa.StreamGet,
		},

		Route{
			"StreamPost",
			strings.ToUpper("Post"),
			"/stream",
			h.sa.StreamPost,
		},

		Route{
			"UpdateStatus",
			strings.ToUpper("Post"),
			"/status",
			h.sa.UpdateStatus,
		},

		Route{
			"VerificationRequest",
			strings.ToUpper("Post"),
			"/verification",
			h.sa.VerificationRequest,
		},

		Route{
			"WellKnownSseConfigurationGet",
			strings.ToUpper("Get"),
			"/.well-known/sse-configuration",
			h.sa.WellKnownSseConfigurationGet,
		},

		Route{
			"WellKnownSseConfigurationIssuerGet",
			strings.ToUpper("Get"),
			"/.well-known/sse-configuration/{issuer}",
			h.sa.WellKnownSseConfigurationIssuerGet,
		},

		Route{
			"JwksJson",
			strings.ToUpper("Get"),
			"/jwks.json",
			h.sa.JwksJson,
		},

		Route{
			"JwksJsonTenant",
			strings.ToUpper("Get"),
			"/jwks/{issuer}",
			h.sa.JwksJsonIssuer,
		},

		Route{
			"PollEvents",
			strings.ToUpper("Post"),
			"/poll",
			h.sa.PollEvents,
		},
	}
	return routes
}
