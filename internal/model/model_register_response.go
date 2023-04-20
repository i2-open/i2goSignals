/*
 * Stream Management API for OpenID Shared Security Events
 *
 * [OpenID Spec](https://openid.net/specs/openid-sse-framework-1_0.html#management)  HTTP API to be implemented by Event Transmitters. This API can be used by Event Receivers to query and update the Event Stream configuration and status, to add and remove subjects, and to trigger verification.
 *
 * API version: 1.0.0
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */
package model

type RegisterResponse struct {
	// The Bearer Token that the receiver will need to use for all Stream Management API calls that require authorization.
	Token   string `json:"token"`
	PushUrl string `json:"pushUrl,omitempty"`
	Inbound *bool  `json:"inbound,omitempty"`
}
