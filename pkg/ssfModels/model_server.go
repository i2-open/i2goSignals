package model

import (
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
)

/* Model Server provides a definition of a GoServer or SSF server endpoint and the necessary credential used to access it.
For example, the OAuth client credentials and authorization server needed to obtain an access token.
*/

const (
	ServerTypeGosignals = "gosignals"
	ServerTypeSsf       = "ssf"
	AuthModeToken       = "token"
	AuthModeSts         = "sts"    // AuthModeSts is used when exchanging an administrative token for a new access token
	AuthModeClient      = "client" // AuthModeClient is used to indicate the client credential is used to obtain an access token for the server
	AuthModeIaT         = "iat"
	AuthModeSpiffe      = "spiffe" // AuthModeSpiffe uses SPIFFE X.509-SVIDs for mutual TLS authentication
)

// SpiffeConfig holds the SPIFFE identity information needed to establish a
// mutually authenticated TLS connection with a remote SSF or goSignals server.
// Either SpiffeID or TrustDomain must be set; SpiffeID takes precedence when both are provided.
type SpiffeConfig struct {
	// TrustDomain of the remote server's SPIFFE trust domain.
	// Authorizes any SVID that belongs to this trust domain.
	// Example: "partner.example.com"
	TrustDomain string `bson:"trustDomain,omitempty" json:"trustDomain,omitempty"`

	// SpiffeID is the exact SPIFFE ID of the remote server to authorize.
	// Takes precedence over TrustDomain when set.
	// Example: "spiffe://partner.example.com/workload/ssf-server"
	SpiffeID string `bson:"spiffeId,omitempty" json:"spiffeId,omitempty"`
}

// DeepCopy returns a deep copy of the SpiffeConfig.
func (s *SpiffeConfig) DeepCopy() *SpiffeConfig {
	if s == nil {
		return nil
	}
	res := *s
	return &res
}

type Server struct {
	Id                  bson.ObjectID      `bson:"_id,omitempty" json:"id"`
	Alias               string             // Alias is a unique user-friendly name for the server
	Type                string             // Type is one of ServerTypeGosignals or ServerTypeSsf
	Host                string             // Url of signals server root
	ClientToken         *string            // Used to administer streams (scope admin) within a project
	RefreshToken        *string            // RefreshToken is used in OAuth scenarios to refresh a token
	TokenExpires        *time.Time         // TimeExpires is the time the ClientToken expires
	IatToken            *string            // IaT is used to register new client (Initial Access Token)
	OAuthClientConfig   *OAuthClientConfig // Used for OAuth2 token exchange flows
	SpiffeConfig        *SpiffeConfig      // Used for SPIFFE X.509-SVID mutual TLS authentication
	ProjectId           string
	ServerConfiguration *TransmitterConfiguration
	OfflineMode         bool   `json:"OfflineMode"`              // OfflineMode indicates if the server is in offline or not accessible
	OfflineError        string `json:"OfflineError"`             // OfflineError is the error message if the server is offline
	TLSCertificate      string `json:"TLSCertificate,omitempty"` // PEM-encoded certificate for self-signed cert support
	TLSSkipVerify       bool   `json:"TLSSkipVerify,omitempty"`  // If true, skip certificate verification (not recommended for production)
}

type OAuthClientConfig struct {
	TokenURL     string // OAuth2 token endpoint capable of RFC8693 token exchange
	ClientID     string // ClientID is the client identifier used to obtain an access token
	ClientSecret string // ClientSecret is the client secret used to obtain an access token
	// Optional audience or resource param names depend on AS; not used by default
	Audience string   // The expected audience for the token
	Resource string   // Resource is an optional default protected resource mask. Can be overridden per call.
	Scopes   []string // Scopes required to post events and manage streams for SSF capability
}

// GetAuthMode returns the type of authentication mode used to access the server.
// Priority order: SPIFFE > OAuth Client Credentials > Initial Access Token > Static Token > STS.
func (s *Server) GetAuthMode() string {
	if s.SpiffeConfig != nil {
		return AuthModeSpiffe
	}
	if s.OAuthClientConfig != nil {
		return AuthModeClient
	}
	if s.IatToken != nil && *s.IatToken != "" {
		return AuthModeIaT
	}
	if s.ClientToken != nil && *s.ClientToken != "" {
		return AuthModeToken
	}
	return AuthModeSts
}

// HasAdminCredential checks if the server definition uses Admin credentials to generate access via STS. If true,
// it means that the server can only be administered via goSignalsAdminServer. To allow goSignals to access and manage
// an SSF stream, it must have a token credential or use the OAuth2 Client Credential flow.
func (s *Server) HasAdminCredential() bool {
	if s.GetAuthMode() == AuthModeSts {
		return true
	}
	return false
}

func (s *Server) DeepCopy() *Server {
	if s == nil {
		return nil
	}
	res := *s
	if s.ClientToken != nil {
		tmp := *s.ClientToken
		res.ClientToken = &tmp
	}
	if s.RefreshToken != nil {
		tmp := *s.RefreshToken
		res.RefreshToken = &tmp
	}
	if s.TokenExpires != nil {
		tmp := *s.TokenExpires
		res.TokenExpires = &tmp
	}
	if s.IatToken != nil {
		tmp := *s.IatToken
		res.IatToken = &tmp
	}
	if s.OAuthClientConfig != nil {
		res.OAuthClientConfig = s.OAuthClientConfig.DeepCopy()
	}
	if s.SpiffeConfig != nil {
		res.SpiffeConfig = s.SpiffeConfig.DeepCopy()
	}
	if s.ServerConfiguration != nil {
		res.ServerConfiguration = s.ServerConfiguration.DeepCopy()
	}
	return &res
}

func (o *OAuthClientConfig) DeepCopy() *OAuthClientConfig {
	if o == nil {
		return nil
	}
	res := *o
	if o.Scopes != nil {
		res.Scopes = make([]string, len(o.Scopes))
		copy(res.Scopes, o.Scopes)
	}
	return &res
}
