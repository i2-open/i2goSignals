package model

// AuthorizationServerMetadata is the subset of RFC 8414 OAuth 2.0 Authorization
// Server Metadata that goSignals serves at /.well-known/oauth-authorization-server
// to describe its OWN partial authorization-server surface.
//
// goSignals is a resource server that delegates the OAuth authorization and token
// grant to an external authorization server (ADR 0001). When such a server (e.g.
// Keycloak) is configured, the discovery endpoint reflects THAT server's metadata
// verbatim and this type is not used. This type is emitted only when no external
// authorization server is configured, advertising the token-management surface
// goSignals implements directly: token introspection, revocation, client
// registration, and its JWKS.
//
// It deliberately omits authorization_endpoint and token_endpoint — goSignals runs
// neither — so the document never advertises a grant capability it cannot honor.
type AuthorizationServerMetadata struct {
	Issuer                string   `json:"issuer"`
	JwksUri               string   `json:"jwks_uri,omitempty"`
	IntrospectionEndpoint string   `json:"introspection_endpoint,omitempty"`
	RevocationEndpoint    string   `json:"revocation_endpoint,omitempty"`
	RegistrationEndpoint  string   `json:"registration_endpoint,omitempty"`
	ScopesSupported       []string `json:"scopes_supported,omitempty"`
}
