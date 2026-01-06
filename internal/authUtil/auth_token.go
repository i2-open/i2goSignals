package authUtil

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	mathRand "math/rand"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/MicahParks/keyfunc"
	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/mux"
	"github.com/i2-open/i2goSignals/internal/model"
	"github.com/i2-open/i2goSignals/pkg/goSet"
)

var authLog = log.New(os.Stdout, "AUTH:   ", log.Ldate|log.Ltime)

type AuthContext struct {
	StreamId  string
	ProjectId string
	Eat       *EventAuthToken
}

type AuthIssuer struct {
	TokenIssuer  string
	PrivateKey   *rsa.PrivateKey
	PublicKey    *keyfunc.JWKS
	OAuthPubKeys []*keyfunc.JWKS
	// OAuth Token
	OAuthServer []string // OAuth Authorization Server identifiers

}

// GetOAuthServers checks the environment variable OAUTH_SERVERS for OAuth Authorization server discovery endpoints
func (a *AuthIssuer) GetOAuthServers() []string {
	if a.OAuthServer == nil {
		as_env := os.Getenv("OAUTH_SERVERS")
		if as_env == "" {
			return nil
		}
		urls := strings.Split(as_env, ",")
		for i := range urls {
			urls[i] = strings.TrimSpace(strings.Trim(urls[i], "\"'"))
		}
		a.OAuthServer = urls
	}
	return a.OAuthServer
}

// oidcDiscovery represents a minimal subset of the OpenID Provider Configuration
// as defined in https://openid.net/specs/openid-connect-discovery-1_0.html
type oidcDiscovery struct {
	JWKSURI string `json:"jwks_uri"`
}

// loadOAuthJWKS resolves JWKS from all configured OAuth/OIDC servers via their discovery documents
// and caches them in AuthIssuer.OAuthPubKeys for later validation.
func (a *AuthIssuer) loadOAuthJWKS() error {
	var err error
	if a.OAuthPubKeys != nil && len(a.OAuthPubKeys) > 0 {
		return nil
	}
	servers := a.GetOAuthServers()
	if len(servers) == 0 {
		return errors.New("no OAUTH_SERVERS configured")
	}
	jwksList := make([]*keyfunc.JWKS, 0, len(servers))
	for _, srv := range servers {
		// Expect srv to be the discovery URL (e.g., .../.well-known/openid-configuration)
		// Fetch discovery doc
		var resp *http.Response
		resp, err = http.Get(srv)
		if err != nil {
			authLog.Printf("Failed to fetch OIDC discovery from %s: %v", srv, err)
			continue
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			authLog.Printf("Failed to read OIDC discovery from %s: %v", srv, err)
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			authLog.Printf("OIDC discovery HTTP %d from %s: %s", resp.StatusCode, srv, string(body))
			continue
		}
		var disc oidcDiscovery
		if err := json.Unmarshal(body, &disc); err != nil {
			authLog.Printf("Failed to parse OIDC discovery from %s: %v", srv, err)
			continue
		}
		if disc.JWKSURI == "" {
			authLog.Printf("OIDC discovery missing jwks_uri at %s", srv)
			continue
		}
		jwks, err := keyfunc.Get(disc.JWKSURI, keyfunc.Options{})
		if err != nil {
			authLog.Printf("Failed to load JWKS from %s: %v", disc.JWKSURI, err)
			continue
		}
		jwksList = append(jwksList, jwks)
	}
	if len(jwksList) == 0 && err == nil {
		return fmt.Errorf("failed to load JWKS from any configured OAUTH_SERVERS")
	}
	a.OAuthPubKeys = jwksList
	return err
}

// IssueProjectIat issues a new registration token. If authCtx is nil, a new project is generated. If an authCtx is asserted,
// then a new iat is issued for the identified project (AuthContext.ProjectId).
func (a *AuthIssuer) IssueProjectIat(authCtx *AuthContext) (string, error) {
	exp := time.Now().AddDate(0, 0, 90)

	projectId := generateAlias(4)
	if authCtx != nil {
		projectId = authCtx.ProjectId
	}
	eat := EventAuthToken{
		ProjectId: projectId,
		Scopes:    []string{ScopeRegister},
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(exp),
			Audience:  []string{a.TokenIssuer},
			Issuer:    a.TokenIssuer,
			ID:        goSet.GenerateJti(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, eat)
	token.Header["typ"] = "jwt"
	token.Header["kid"] = a.TokenIssuer
	return token.SignedString(a.PrivateKey)
}

func (a *AuthIssuer) IssueStreamClientToken(client model.SsfClient, projectId string, admin bool) (string, error) {
	exp := time.Now().AddDate(0, 0, 90)

	scopes := []string{ScopeStreamMgmt}
	if admin { // 'admin' allows creation and deletion instead of just update
		scopes = []string{ScopeStreamAdmin, ScopeStreamMgmt}
	}
	eat := EventAuthToken{
		ProjectId: projectId,
		Scopes:    scopes,
		ClientId:  client.Id.Hex(),
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(exp),
			Audience:  []string{a.TokenIssuer},
			Issuer:    a.TokenIssuer,
			ID:        goSet.GenerateJti(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, eat)
	token.Header["typ"] = "jwt"
	token.Header["kid"] = a.TokenIssuer
	return token.SignedString(a.PrivateKey)
}

func (a *AuthIssuer) IssueStreamToken(streamId string, projectId string) (string, error) {
	exp := time.Now().AddDate(0, 0, 90)

	eat := EventAuthToken{
		StreamIds: []string{streamId},
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(exp),
			Audience:  []string{a.TokenIssuer},
			Issuer:    a.TokenIssuer,
			ID:        goSet.GenerateJti(),
		},
	}
	if projectId != "" {
		eat.ProjectId = projectId
	}
	eat.Scopes = []string{ScopeEventDelivery}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, eat)
	token.Header["typ"] = "jwt"
	token.Header["kid"] = a.TokenIssuer
	return token.SignedString(a.PrivateKey)
}

// ValidateAuthorization evaluates the authorization header and checks to see if the correct scope is asserted.
// Returns streamId (if available) and http status.  200 OK means authorized
func (a *AuthIssuer) ValidateAuthorization(r *http.Request, scopes []string) (*AuthContext, int) {
	authorization := r.Header.Get("Authorization")

	// first look for stream id as a query
	queries := r.URL.Query()

	id := queries["stream_id"]

	streamRequested := ""

	if id != nil && len(id) > 0 {
		streamRequested = id[0]
	} else {
		// check for stream id in the path
		params := mux.Vars(r)
		val, exist := params["id"]
		if exist {
			streamRequested = val
		}
	}

	// otherwise fallback to the token
	if authorization == "" {
		// return streamRequested, http.StatusUnauthorized

		return nil, http.StatusUnauthorized
	}

	parts := strings.Split(authorization, " ")
	if len(parts) < 2 {
		return nil, http.StatusUnauthorized
	}
	if parts[0] == "Bearer" {

		tkn, err := a.ParseAuthTokenVerbose(parts[1], false)
		if err == nil && tkn.IsAuthorized(streamRequested, scopes) {
			return &AuthContext{
				StreamId:  streamRequested,
				ProjectId: tkn.ProjectId,
				Eat:       tkn,
			}, http.StatusOK
		}
		// Try validating against configured OAuth servers as a fallback
		if authCtx, ok := a.validateOAuthToken(parts[1], streamRequested, scopes); ok {
			return authCtx, http.StatusOK
		}
		if err != nil {
			authLog.Printf("Authorization invalid: [%v]", err)
		}
		return nil, http.StatusUnauthorized
	}
	authLog.Printf("Received invalid authorization: %s\n", parts[0])
	return nil, http.StatusUnauthorized

}

// ValidateAuthorizationAny validates the Authorization header against either a locally issued token
// or any configured OAuth/OIDC servers defined in OAUTH_SERVERS. It returns 200 OK when authorized.
func (a *AuthIssuer) ValidateAuthorizationAny(r *http.Request, scopes []string) (*AuthContext, int) {
	authorization := r.Header.Get("Authorization")

	// first look for stream id as a query
	queries := r.URL.Query()
	id := queries["stream_id"]
	streamRequested := ""
	if id != nil && len(id) > 0 {
		streamRequested = id[0]
	} else {
		// check for stream id in the path
		params := mux.Vars(r)
		val, exist := params["id"]
		if exist {
			streamRequested = val
		}
	}

	if authorization == "" {
		return nil, http.StatusUnauthorized
	}
	parts := strings.Split(authorization, " ")
	if len(parts) < 2 || parts[0] != "Bearer" {
		return nil, http.StatusUnauthorized
	}

	// Try local token first
	if tkn, err := a.ParseAuthTokenVerbose(parts[1], false); err == nil && tkn.IsAuthorized(streamRequested, scopes) {
		return &AuthContext{StreamId: streamRequested, ProjectId: tkn.ProjectId, Eat: tkn}, http.StatusOK
	}

	// Try OAuth servers
	if authCtx, ok := a.validateOAuthToken(parts[1], streamRequested, scopes); ok {
		return authCtx, http.StatusOK
	}
	return nil, http.StatusUnauthorized
}

// validateOAuthToken attempts to validate the token using configured OAuth/OIDC servers.
// Returns an AuthContext when token roles match accepted scopes.
func (a *AuthIssuer) validateOAuthToken(tokenString string, streamRequested string, scopesAccepted []string) (*AuthContext, bool) {
	if err := a.loadOAuthJWKS(); err != nil {
		return nil, false
	}
	tokenString = strings.TrimSpace(tokenString)
	for _, jwks := range a.OAuthPubKeys {
		token, err := jwt.ParseWithClaims(tokenString, &OidcClaims{}, jwks.Keyfunc)
		if err != nil {
			authLog.Printf("Not validated with key %v: %v\n", jwks.KIDs(), err)
			continue
		}
		if claims, ok := token.Claims.(*OidcClaims); ok && token.Valid {
			// Map OIDC realm roles to our scopes by simple name match (case-insensitive)
			hasScopes := []string{}
			if claims.RealmAccess.Roles != nil {
				hasScopes = claims.RealmAccess.Roles
			}
			if claims.Scope != "" {
				hasScopes = append(hasScopes, strings.Split(claims.Scope, " ")...)
			}
			if oidcRolesMatchScopes(hasScopes, scopesAccepted) {
				// External tokens don't carry our ProjectId or stream restrictions; accept scope-based access
				return &AuthContext{
					StreamId:  streamRequested,
					ProjectId: "",
					Eat:       nil,
				}, true
			}
		}
	}
	return nil, false
}

func oidcRolesMatchScopes(roles []string, scopesAccepted []string) bool {
	for _, accepted := range scopesAccepted {
		for _, role := range roles {
			if strings.EqualFold(role, ScopeRoot) {
				return true
			}
			if strings.EqualFold(role, accepted) {
				return true
			}
		}
	}
	return false
}

// ParseAuthToken parses and validates an internally issued event authorization token. An *EventAuthToken is only returned if the token was validated otherwise nil
func (a *AuthIssuer) ParseAuthToken(tokenString string) (*EventAuthToken, error) {
	return a.ParseAuthTokenVerbose(tokenString, true)
}

// ParseAuthTokenVerbose parses and validates an internally issued event authorization token. An *EventAuthToken is only returned if the token was validated otherwise nil
// When verbose is false, it does not log "Error validating token"
func (a *AuthIssuer) ParseAuthTokenVerbose(tokenString string, verbose bool) (*EventAuthToken, error) {
	if a.PublicKey == nil {
		return nil, errors.New("ERROR: No public key provided to validate authorization token.")
	}

	// In case of cut/paste error, trim extra spaces
	tokenString = strings.TrimSpace(tokenString)

	valid := true
	token, err := jwt.ParseWithClaims(tokenString, &EventAuthToken{}, a.PublicKey.Keyfunc)
	if err != nil {
		if verbose {
			authLog.Printf("Error validating token: %s", err.Error())
		}
		valid = false
	}
	if token != nil && (token.Header["typ"] != "jwt" && token.Header["typ"] != "JWT") {
		if verbose {
			authLog.Printf("token is not an authorization token (JWT)")
		}
		return nil, errors.New("token type is not an authorization token (`jwt`)")
	}

	// jsonByte, _ := json.MarshalIndent(token.Claims, "", "  ")
	// claimString := string(jsonByte)
	// authLog.Println(claimString)
	if token != nil {
		if claims, ok := token.Claims.(*EventAuthToken); ok && valid {
			return claims, nil
		}
	}

	return nil, err
}

const (
	ScopeStreamMgmt    = "stream"
	ScopeEventDelivery = "event"
	ScopeStreamAdmin   = "admin"
	ScopeRegister      = "reg"
	ScopeRoot          = "root"
	StreamAny          = "any"
)

// EventAuthToken is an internally issued token used for stream management by SSF clients.
type EventAuthToken struct {
	StreamIds []string `json:"streams,omitempty"`
	ProjectId string   `json:"project_id"`
	Scopes    []string `json:"roles,omitempty"`
	ClientId  string   `json:"client_id,omitempty"`
	jwt.RegisteredClaims
	OAuthScope string `json:"scope,omitempty"`
}

// IsScopeMatch checks both Event token scopes array and oauth style space delimited scope claim
func (t *EventAuthToken) IsScopeMatch(scopesAccepted []string) bool {
	oauthScope := t.OAuthScope
	oauthScopes := strings.Split(oauthScope, " ")
	for _, acceptedScope := range scopesAccepted {
		for _, scope := range t.Scopes {
			if strings.EqualFold(scope, ScopeRoot) {
				return true
			}
			if strings.EqualFold(scope, acceptedScope) {
				return true
			}

		}
		for _, scope := range oauthScopes {
			if strings.
				EqualFold(scope, ScopeRoot) {
				return true
			}
			if strings.EqualFold(scope, acceptedScope) {
				return true
			}
		}

	}
	return false
}

func (t *EventAuthToken) IsAuthorized(streamId string, scopesAccepted []string) bool {

	scopeMatch := t.IsScopeMatch(scopesAccepted)
	if streamId == "" {
		// Cases where streamId is not needed
		return scopeMatch
	}
	// if no value for streamId is in the token, assume any stream is ok
	if len(t.StreamIds) == 0 {
		return scopeMatch
	}

	// Auth restricts stream Id.  Check for a match
	for _, v := range t.StreamIds {
		if strings.EqualFold(v, streamId) || strings.EqualFold(v, StreamAny) {
			return scopeMatch
		}
	}

	return false
}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const (
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

var src = mathRand.NewSource(time.Now().UnixNano())

func generateAlias(n int) string {
	sb := strings.Builder{}
	sb.Grow(n)
	// A src.Int63() generates 63 random bits, enough for letterIdxMax characters!
	for i, cache, remain := n-1, src.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			sb.WriteByte(letterBytes[idx])
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return sb.String()
}

// OidcClaims represents the claims from an OIDC token (from Keycloak)
type OidcClaims struct {
	Email             string `json:"email"`
	PreferredUsername string `json:"preferred_username"`
	Name              string `json:"name"`
	GivenName         string `json:"given_name"`
	FamilyName        string `json:"family_name"`
	Scope             string `json:"scope"`
	RealmAccess       struct {
		Roles []string `json:"roles"`
	} `json:"realm_access"`
	jwt.RegisteredClaims
}

// ValidateOidcToken validates an OIDC token from Keycloak and returns the claims
// This is used by the adminUI to authenticate users
func (a *AuthIssuer) ValidateOidcToken(tokenString string) (*OidcClaims, error) {
	if a.PublicKey == nil {
		return nil, errors.New("ERROR: No public key provided to validate OIDC token.")
	}

	// In case of cut/paste error, trim extra spaces
	tokenString = strings.TrimSpace(tokenString)

	valid := true
	token, err := jwt.ParseWithClaims(tokenString, &OidcClaims{}, a.PublicKey.Keyfunc)
	if err != nil {
		authLog.Printf("Error validating OIDC token: %s", err.Error())
		valid = false
	}

	if claims, ok := token.Claims.(*OidcClaims); ok && valid {
		return claims, nil
	}

	return nil, err
}

// ValidateOidcAuthorizationMiddleware is middleware to validate OIDC tokens from adminUI
func (a *AuthIssuer) ValidateOidcAuthorizationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorization := r.Header.Get("Authorization")

		if authorization == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		parts := strings.Split(authorization, " ")
		if len(parts) < 2 || parts[0] != "Bearer" {
			http.Error(w, "Invalid authorization header", http.StatusUnauthorized)
			return
		}

		claims, err := a.ValidateOidcToken(parts[1])
		if err != nil {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// Add user info to request context for downstream handlers
		r.Header.Set("X-User-Email", claims.Email)
		r.Header.Set("X-User-Name", claims.PreferredUsername)

		next.ServeHTTP(w, r)
	})
}
