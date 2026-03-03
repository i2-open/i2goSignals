package authUtil

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	mathRand "math/rand"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/MicahParks/keyfunc"
	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/mux"
	"github.com/i2-open/i2goSignals/pkg/authSupport"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/logger"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/i2-open/i2goSignals/pkg/tlsSupport"
	"github.com/i2-open/i2goSignals/pkg/wellKnownSupport"
)

var authLog = logger.Sub("AUTH")

type AuthContext struct {
	StreamId  string
	ProjectId string
	Eat       *authSupport.EventAuthToken
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
	client := &http.Client{Timeout: 10 * time.Second}
	tlsSupport.CheckCaInstalled(client)
	for _, srv := range servers {
		// Expect srv to be the discovery URL (e.g., .../.well-known/openid-configuration)
		disc, err := wellKnownSupport.Fetch[wellKnownSupport.OIDCConfiguration](context.Background(), client, srv)
		if err != nil {
			authLog.Error("Failed to fetch OIDC discovery", "srv", srv, "error", err)
			continue
		}

		if disc.JWKSURI == "" {
			authLog.Error("OIDC discovery missing jwks_uri", "srv", srv)
			continue
		}
		jwks, err := keyfunc.Get(disc.JWKSURI, keyfunc.Options{
			Client: client,
		})
		if err != nil {
			authLog.Error("Failed to load JWKS", "jwks_uri", disc.JWKSURI, "error", err)
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
	eat := authSupport.EventAuthToken{
		ProjectId: projectId,
		Scopes:    []string{authSupport.ScopeRegister},
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

	scopes := []string{authSupport.ScopeStreamMgmt}
	if admin { // 'admin' allows creation and deletion instead of just update
		scopes = []string{authSupport.ScopeStreamAdmin, authSupport.ScopeStreamMgmt}
	}
	eat := authSupport.EventAuthToken{
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

	eat := authSupport.EventAuthToken{
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
	eat.Scopes = []string{authSupport.ScopeEventDelivery}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, eat)
	token.Header["typ"] = "jwt"
	token.Header["kid"] = a.TokenIssuer
	return token.SignedString(a.PrivateKey)
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
		// check for stream id in the path or captured by mux
		params := mux.Vars(r)
		val, exist := params["id"]
		if exist {
			streamRequested = val
		} else {
			val, exist = params["stream_id"]
			if exist {
				streamRequested = val
			}
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
	if tkn, err := a.ParseAuthTokenVerbose(parts[1], false); err == nil {
		if tkn.IsAuthorized(streamRequested, scopes) {
			return &AuthContext{StreamId: streamRequested, ProjectId: tkn.ProjectId, Eat: tkn}, http.StatusOK
		}
		return nil, http.StatusForbidden
	}

	// Try OAuth servers
	return a.validateOAuthToken(parts[1], streamRequested, scopes)
}

// validateOAuthToken attempts to validate the token using configured OAuth/OIDC servers.
// Returns an AuthContext when token roles match accepted scopes.
func (a *AuthIssuer) validateOAuthToken(tokenString string, streamRequested string, scopesAccepted []string) (*AuthContext, int) {
	if err := a.loadOAuthJWKS(); err != nil {
		return nil, http.StatusUnauthorized
	}
	tokenString = strings.TrimSpace(tokenString)
	isAuthorized := false
	for _, jwks := range a.OAuthPubKeys {
		token, err := jwt.ParseWithClaims(tokenString, &authSupport.OidcClaims{}, jwks.Keyfunc)
		if err != nil {
			authLog.Debug("Not validated with key", "kids", jwks.KIDs(), "error", err)
			continue
		}
		if claims, ok := token.Claims.(*authSupport.OidcClaims); ok && token.Valid {
			isAuthorized = true
			// Map OIDC realm roles to our scopes by simple name match (case-insensitive)
			var hasScopes []string
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
				}, http.StatusOK
			}
		}
	}
	if isAuthorized {
		return nil, http.StatusForbidden
	}
	return nil, http.StatusUnauthorized
}

func oidcRolesMatchScopes(roles []string, scopesAccepted []string) bool {
	for _, accepted := range scopesAccepted {
		for _, role := range roles {
			if strings.EqualFold(role, authSupport.ScopeRoot) {
				return true
			}
			if strings.EqualFold(role, accepted) {
				return true
			}
		}
	}
	return false
}

// ParseAuthToken parses and validates an internally issued event authorization token. An *authSupport.EventAuthToken is only returned if the token was validated otherwise nil
func (a *AuthIssuer) ParseAuthToken(tokenString string) (*authSupport.EventAuthToken, error) {
	return a.ParseAuthTokenVerbose(tokenString, true)
}

// ParseAuthTokenVerbose parses and validates an internally issued event authorization token. An *authSupport.EventAuthToken is only returned if the token was validated otherwise nil
// When verbose is false, it does not log "Error validating token"
func (a *AuthIssuer) ParseAuthTokenVerbose(tokenString string, verbose bool) (*authSupport.EventAuthToken, error) {
	if a.PublicKey == nil {
		return nil, errors.New("ERROR: No public key provided to validate authorization token.")
	}

	// In case of cut/paste error, trim extra spaces
	tokenString = strings.TrimSpace(tokenString)

	valid := true
	token, err := jwt.ParseWithClaims(tokenString, &authSupport.EventAuthToken{}, a.PublicKey.Keyfunc)
	if err != nil {
		if verbose {
			authLog.Error("Error validating token", "error", err)
		}
		valid = false
	}
	if token != nil && (token.Header["typ"] != "jwt" && token.Header["typ"] != "JWT") {
		if verbose {
			authLog.Error("token is not an authorization token (JWT)")
		}
		return nil, errors.New("token type is not an authorization token (`jwt`)")
	}

	// jsonByte, _ := json.MarshalIndent(token.Claims, "", "  ")
	// claimString := string(jsonByte)
	// authLog.Println(claimString)
	if token != nil {
		if claims, ok := token.Claims.(*authSupport.EventAuthToken); ok && valid {
			return claims, nil
		}
	}

	return nil, err
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

// ValidateOidcToken validates an OIDC token from Keycloak and returns the claims
// This is used by the adminUI to authenticate users
func (a *AuthIssuer) ValidateOidcToken(tokenString string) (*authSupport.OidcClaims, error) {
	validator := authSupport.NewTokenValidator(a.PublicKey)
	return validator.ValidateOidcToken(tokenString)
}

// ValidateOidcAuthorizationMiddleware is middleware to validate OIDC tokens from adminUI
func (a *AuthIssuer) ValidateOidcAuthorizationMiddleware(next http.Handler) http.Handler {
	validator := authSupport.NewTokenValidator(a.PublicKey)
	return validator.ValidateOidcAuthorizationMiddleware(next)
}
