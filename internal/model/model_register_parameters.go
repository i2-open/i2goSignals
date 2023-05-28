/*
 * Stream Management API for OpenID Shared Security Events
 *
 * [OpenID Spec](https://openid.net/specs/openid-sse-framework-1_0.html#management)  HTTP API to be implemented by Event Transmitters. This API can be used by Event Receivers to query and update the Event Stream configuration and status, to add and remove subjects, and to trigger verification.
 *
 * API version: 1.0.0
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */
package model

type RegisterParameters struct {
	// The audience claim to be used for all events on this stream.
	Audience      []string `json:"audience"`
	Issuer        string   // TODO: Empty Issuer shall mean accept any?
	IssuerJWKSUrl string
	Inbound       *bool    `json:"inbound,omitempty"`
	RouteMode     string   // One of RouteModeImport | RouteModeFoward | RouteModePublish
	Method        string   // Either DeliveryPoll (default) or DeliveryPush
	EventUrl      string   // For when the i2gosignals server is a stream client and using Polling (RF8936), or the client delivery endpoint for Push (RFC8935)
	EventAuth     string   // The authorization parameter for Polling using RFC8936, or the client auth token for HTTP Push delivery
	EventUris     []string // These are the inbound event uris that are being delivered.
}
