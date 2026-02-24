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
)

type Server struct {
	Id                  bson.ObjectID      `bson:"_id,omitempty" json:"id"`
	Alias               string             // Alias is a unique user-friendly name for the server
	Type                string             // Type is one of ServerTypeGosignals or ServerTypeSsf
	AuthMode            string             // AuthMode is one of AuthModeToken or AuthModeSts
	Host                string             // Url of signals server root
	ClientToken         *string            // Used to administer streams (scope admin) within a project
	RefreshToken        *string            // RefreshToken is used in OAuth scenarios to refresh a token
	TokenExpires        *time.Time         // TimeExpires is the time the ClientToken expires
	IatToken            *string            // IaT is used to register new client (Initial Access Token)
	OAuthClientConfig   *OAuthClientConfig // Used for OAuth2 token exchange flows
	ProjectId           string
	ServerConfiguration *TransmitterConfiguration
	OfflineMode         bool   `json:"OfflineMode"`  // OfflineMode indicates if the server is in offline or not accessible
	OfflineError        string `json:"OfflineError"` // OfflineError is the error message if the server is offline
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
