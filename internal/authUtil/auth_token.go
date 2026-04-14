package authUtil

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	mathRand "math/rand"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/MicahParks/keyfunc/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"github.com/i2-open/i2goSignals/pkg/authSupport"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/logger"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/i2-open/i2goSignals/pkg/tlsSupport"
	"github.com/i2-open/i2goSignals/pkg/wellKnownSupport"
)

const AuthContextKey = "AuthContext"

var authLog = logger.Sub("AUTH")

type AuthContext struct {
	StreamId      string
	ProjectId     string
	Eat           *authSupport.EventAuthToken
	IsOAuthClient bool
}

type AuthIssuer struct {
	mu           sync.RWMutex
	TokenIssuer  string
	TokenKid     string
	PrivateKey   *rsa.PrivateKey
	PublicKey    *keyfunc.JWKS
	OAuthPubKeys []*keyfunc.JWKS
	// OAuth Token
	OAuthServer  []string                 // OAuth Authorization Server identifiers
	TokenTracker authSupport.TokenTracker // Tracker for revocation
}

func (a *AuthIssuer) UpdateTokenKey(issuer string, kid string, privateKey *rsa.PrivateKey, publicKey *keyfunc.JWKS) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.TokenIssuer = issuer
	a.TokenKid = kid
	a.PrivateKey = privateKey
	a.PublicKey = publicKey
	privReady := privateKey != nil
	pubReady := publicKey != nil
	var pubKids []string
	if publicKey != nil {
		pubKids = publicKey.KIDs()
	}
	authLog.Debug("UpdateTokenKey", "issuer", issuer, "kid", kid, "privateKey", privReady, "publicKey", pubReady, "jwksKids", pubKids)
}

// IsReady returns true when both the signing key and verification key are loaded.
func (a *AuthIssuer) IsReady() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.PrivateKey != nil && a.PublicKey != nil
}

// GetOAuthServers checks the environment variable OAUTH_SERVERS for OAuth Authorization server discovery endpoints
func (a *AuthIssuer) GetOAuthServers() []string {
	a.mu.RLock()
	if a.OAuthServer != nil {
		defer a.mu.RUnlock()
		return a.OAuthServer
	}
	a.mu.RUnlock()

	a.mu.Lock()
	defer a.mu.Unlock()

	if a.OAuthServer != nil {
		return a.OAuthServer
	}

	as_env := os.Getenv("OAUTH_SERVERS")
	if as_env == "" {
		return nil
	}
	urls := strings.Split(as_env, ",")
	for i := range urls {
		urls[i] = strings.TrimSpace(strings.Trim(urls[i], "\"'"))
	}
	a.OAuthServer = urls
	return a.OAuthServer
}

// loadOAuthJWKS resolves JWKS from all configured OAuth/OIDC servers via their discovery documents
// and caches them in AuthIssuer.OAuthPubKeys for later validation.
func (a *AuthIssuer) loadOAuthJWKS() error {
	servers := a.GetOAuthServers()
	if len(servers) == 0 {
		return nil
	}

	a.mu.RLock()
	// If all servers are already loaded, return early
	if a.OAuthPubKeys != nil && len(a.OAuthPubKeys) == len(servers) {
		a.mu.RUnlock()
		return nil
	}
	a.mu.RUnlock()

	a.mu.Lock()
	defer a.mu.Unlock()

	// Check again under write lock
	if a.OAuthPubKeys != nil && len(a.OAuthPubKeys) == len(servers) {
		return nil
	}

	jwksList := make([]*keyfunc.JWKS, 0, len(servers))
	var lastErr error

	client := &http.Client{Timeout: 10 * time.Second}
	tlsSupport.CheckCaInstalled(client)
	for _, srv := range servers {
		// Expect srv to be the discovery URL (e.g., .../.well-known/openid-configuration)
		disc, err := wellKnownSupport.Fetch[wellKnownSupport.OIDCConfiguration](context.Background(), client, srv)
		if err != nil {
			authLog.Error("Failed to fetch OIDC discovery", "srv", srv, "error", err)
			lastErr = err
			continue
		}

		if disc.JWKSURI == "" {
			authLog.Error("OIDC discovery missing jwks_uri", "srv", srv)
			lastErr = fmt.Errorf("OIDC discovery missing jwks_uri for %s", srv)
			continue
		}

		// Use background refresh and refresh on unknown KID to handle transient startup issues and key rotation
		jwks, err := keyfunc.Get(disc.JWKSURI, keyfunc.Options{
			Client: client,
			RefreshErrorHandler: func(err error) {
				authLog.Error("JWKS background refresh failed", "jwks_uri", disc.JWKSURI, "error", err)
			},
			RefreshInterval:   time.Hour,
			RefreshRateLimit:  time.Second,
			RefreshTimeout:    time.Second * 30,
			RefreshUnknownKID: true,
		})
		if err != nil {
			authLog.Error("Failed to load JWKS", "jwks_uri", disc.JWKSURI, "error", err)
			lastErr = err
			continue
		}
		jwksList = append(jwksList, jwks)
	}

	if len(jwksList) == 0 {
		if lastErr != nil {
			return lastErr
		}
		return fmt.Errorf("failed to load JWKS from any configured OAUTH_SERVERS")
	}

	a.OAuthPubKeys = jwksList
	return lastErr
}

// IssueProjectIat issues a new registration token. If authCtx is nil, a new project is generated. If an authCtx is asserted,
// then a new iat is issued for the identified project (AuthContext.ProjectId).
func (a *AuthIssuer) IssueProjectIat(authCtx *AuthContext) (string, error) {
	exp := time.Now().AddDate(0, 0, 90)

	projectId := generateAlias(4)
	if authCtx != nil {
		projectId = authCtx.ProjectId
	}

	a.mu.RLock()
	issuer := a.TokenIssuer
	kid := a.TokenKid
	if kid == "" {
		kid = issuer
	}
	privateKey := a.PrivateKey
	a.mu.RUnlock()

	clientId := ""
	if authCtx != nil && authCtx.Eat != nil {
		clientId = authCtx.Eat.ClientId
	}
	subject := ""
	if authCtx != nil && authCtx.Eat != nil {
		subject = authCtx.Eat.Subject
	}

	eat := authSupport.EventAuthToken{
		ProjectId: projectId,
		Roles:     []string{authSupport.ScopeRegister},
		ClientId:  clientId,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   subject,
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(exp),
			Audience:  []string{issuer},
			Issuer:    issuer,
			ID:        goSet.GenerateJti(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, eat)
	token.Header["typ"] = "jwt"
	token.Header["kid"] = kid

	authLog.Debug("IssueProjectIat signing", "issuer", issuer, "kid", kid, "privateKeyNil", privateKey == nil, "projectId", projectId)
	signed, err := token.SignedString(privateKey)
	if err != nil {
		authLog.Error("IssueProjectIat signing failed", "kid", kid, "error", err)
	} else if a.TokenTracker != nil {
		_ = a.TokenTracker.TrackToken(context.Background(), &eat, model.TokenTypeIAT)
	}
	return signed, err
}

func (a *AuthIssuer) IssueStreamClientToken(client model.SsfClient, projectId string, admin bool) (string, error) {
	exp := time.Now().AddDate(0, 0, 90)

	scopes := []string{authSupport.ScopeStreamMgmt}
	if admin { // 'admin' allows creation and deletion instead of just update
		scopes = []string{authSupport.ScopeStreamAdmin, authSupport.ScopeStreamMgmt}
	}

	a.mu.RLock()
	issuer := a.TokenIssuer
	kid := a.TokenKid
	if kid == "" {
		kid = issuer
	}
	privateKey := a.PrivateKey
	a.mu.RUnlock()

	eat := authSupport.EventAuthToken{
		ProjectId: projectId,
		Roles:     scopes,
		ClientId:  client.Id.Hex(),
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(exp),
			Audience:  []string{issuer},
			Issuer:    issuer,
			ID:        goSet.GenerateJti(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, eat)
	token.Header["typ"] = "jwt"
	token.Header["kid"] = kid

	signed, err := token.SignedString(privateKey)
	if err == nil && a.TokenTracker != nil {
		_ = a.TokenTracker.TrackToken(context.Background(), &eat, model.TokenTypeStream)
	}
	return signed, err
}

func (a *AuthIssuer) IssueStreamToken(streamId string, projectId string, session *AuthContext) (string, error) {
	exp := time.Now().AddDate(0, 0, 90)

	a.mu.RLock()
	issuer := a.TokenIssuer
	kid := a.TokenKid
	if kid == "" {
		kid = issuer
	}
	privateKey := a.PrivateKey
	a.mu.RUnlock()

	eat := authSupport.EventAuthToken{
		StreamIds: []string{streamId},
		ProjectId: projectId,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(exp),
			Audience:  []string{issuer},
			Issuer:    issuer,
			ID:        goSet.GenerateJti(),
		},
	}
	if projectId != "" {
		eat.ProjectId = projectId
	}
	eat.Roles = []string{authSupport.ScopeEventDelivery}
	if session != nil {
		if session.Eat != nil {
			eat.ClientId = session.Eat.ClientId
			eat.Subject, _ = session.Eat.GetSubject()
		}

	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, eat)
	token.Header["typ"] = "jwt"
	token.Header["kid"] = kid

	signed, err := token.SignedString(privateKey)
	if err == nil && a.TokenTracker != nil {
		_ = a.TokenTracker.TrackToken(context.Background(), &eat, model.TokenTypeStream)
	}
	return signed, err
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
	if len(parts) < 2 || strings.ToLower(parts[0]) != "bearer" {
		return nil, http.StatusUnauthorized
	}

	// Try local token first
	if tkn, err := a.ParseAuthTokenVerbose(parts[1], false); err == nil {
		if tkn.IsAuthorized(streamRequested, scopes) {
			return &AuthContext{StreamId: streamRequested, ProjectId: tkn.ProjectId, Eat: tkn, IsOAuthClient: false}, http.StatusOK
		}
		return nil, http.StatusForbidden
	}

	// Try OAuth servers
	return a.validateOAuthToken(parts[1], streamRequested, scopes)
}

// validateOAuthToken attempts to validate the token using configured OAuth/OIDC servers.
// Returns an AuthContext when token roles match accepted scopes.
func (a *AuthIssuer) validateOAuthToken(tokenString string, streamRequested string, scopesAccepted []string) (*AuthContext, int) {
	loadErr := a.loadOAuthJWKS()

	a.mu.RLock()
	pubKeys := a.OAuthPubKeys
	a.mu.RUnlock()

	if len(pubKeys) == 0 {
		if loadErr != nil && len(a.GetOAuthServers()) > 0 {
			return nil, http.StatusServiceUnavailable
		}
		return nil, http.StatusUnauthorized
	}

	tokenString = strings.TrimSpace(tokenString)
	isAuthorized := false

	a.mu.RLock()
	pubKeys = a.OAuthPubKeys
	a.mu.RUnlock()

	isMissingKID := false
	for _, jwks := range pubKeys {
		token, err := jwt.ParseWithClaims(tokenString, &authSupport.OidcClaims{}, jwks.Keyfunc)
		if err != nil {
			if strings.Contains(err.Error(), "key ID was not found") {
				isMissingKID = true
			}
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
					StreamId:      streamRequested,
					ProjectId:     "",
					Eat:           nil,
					IsOAuthClient: true,
				}, http.StatusOK
			}
		}
	}
	if isAuthorized {
		return nil, http.StatusForbidden
	}
	if loadErr != nil || isMissingKID {
		reason := "OAuth token validation failed"
		if loadErr != nil {
			reason += " while some JWKS failed to load"
		} else {
			reason += " because Key ID was not found in JWKS (refresh may be in progress)"
		}
		authLog.Warn(reason, "error", loadErr)
		return nil, http.StatusServiceUnavailable
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
	// If the public key is not yet loaded (server still starting up or in the middle
	// of a MongoDB reconnect), wait up to 1 second for it to become available before
	// giving up. This avoids 503 responses during the brief window between service
	// start and successful key initialization.
	a.mu.RLock()
	pubKey := a.PublicKey
	a.mu.RUnlock()
	if pubKey == nil {
		deadline := time.Now().Add(time.Second)
		for time.Now().Before(deadline) {
			time.Sleep(100 * time.Millisecond)
			a.mu.RLock()
			pubKey = a.PublicKey
			a.mu.RUnlock()
			if pubKey != nil {
				break
			}
		}
	}
	if pubKey == nil {
		return nil, errors.New("ERROR: No public key provided to validate authorization token.")
	}

	// In case of cut/paste error, trim extra spaces
	tokenString = strings.TrimSpace(tokenString)

	// Extract kid from token header for debug logging (parse header only, no sig check)
	var tokenKid string
	if parts := strings.Split(tokenString, "."); len(parts) >= 1 {
		if hdrBytes, err2 := base64.RawURLEncoding.DecodeString(parts[0]); err2 == nil {
			var hdr map[string]interface{}
			if err2 = json.Unmarshal(hdrBytes, &hdr); err2 == nil {
				if k, ok := hdr["kid"].(string); ok {
					tokenKid = k
				}
			}
		}
	}
	authLog.Debug("ParseAuthTokenVerbose", "tokenKid", tokenKid, "jwksKids", pubKey.KIDs())

	valid := true
	token, err := jwt.ParseWithClaims(tokenString, &authSupport.EventAuthToken{}, pubKey.Keyfunc)
	if err != nil {
		if verbose {
			authLog.Error("Error validating token", "tokenKid", tokenKid, "jwksKids", pubKey.KIDs(), "error", err)
		} else {
			authLog.Debug("Local token validation failed", "tokenKid", tokenKid, "jwksKids", pubKey.KIDs(), "error", err)
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
			if a.TokenTracker != nil {
				revoked, _ := a.TokenTracker.IsRevoked(context.Background(), claims.ID)
				if revoked {
					return nil, errors.New("token has been revoked")
				}
			}
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

func ConvertProject(projectId string) *AuthContext {
	return &AuthContext{
		ProjectId: projectId,
	}
}
