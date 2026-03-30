package authSupport

import (
	"errors"
	"net/http"
	"strings"

	"github.com/MicahParks/keyfunc/v2"
	"github.com/golang-jwt/jwt/v5"
)

// OidcClaims represents the claims from an OIDC token (e.g., from Keycloak)
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

// TokenValidator provides methods to validate JWT and OIDC tokens.
type TokenValidator struct {
	PublicKey *keyfunc.JWKS
}

// NewTokenValidator creates a new TokenValidator with the provided public key.
func NewTokenValidator(publicKey *keyfunc.JWKS) *TokenValidator {
	return &TokenValidator{PublicKey: publicKey}
}

// ValidateOidcToken validates an OIDC token and returns the claims.
func (v *TokenValidator) ValidateOidcToken(tokenString string) (*OidcClaims, error) {
	if v.PublicKey == nil {
		return nil, errors.New("no public key provided to validate OIDC token")
	}

	tokenString = strings.TrimSpace(tokenString)

	token, err := jwt.ParseWithClaims(tokenString, &OidcClaims{}, v.PublicKey.Keyfunc)
	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*OidcClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New("invalid token")
}

// ValidateOidcAuthorizationMiddleware is middleware to validate OIDC tokens from Authorization header.
func (v *TokenValidator) ValidateOidcAuthorizationMiddleware(next http.Handler) http.Handler {
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

		claims, err := v.ValidateOidcToken(parts[1])
		if err != nil {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// Add user info to request context for downstream handlers
		// In a real application, you might want to use context.WithValue
		r.Header.Set("X-User-Email", claims.Email)
		r.Header.Set("X-User-Name", claims.PreferredUsername)

		next.ServeHTTP(w, r)
	})
}
