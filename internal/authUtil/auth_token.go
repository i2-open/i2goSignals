package authUtil

import (
	"crypto/rsa"
	"errors"
	"log"
	mathRand "math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/MicahParks/keyfunc"
	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/mux"
	"github.com/independentid/i2goSignals/internal/model"
	"github.com/independentid/i2goSignals/pkg/goSet"
)

type AuthContext struct {
	StreamId  string
	ProjectId string
	Eat       *EventAuthToken
}

type AuthIssuer struct {
	TokenIssuer string
	PrivateKey  *rsa.PrivateKey
	PublicKey   *keyfunc.JWKS
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

		return nil, http.StatusOK // For testing purposes only
	}
	parts := strings.Split(authorization, " ")
	if len(parts) < 2 {
		return nil, http.StatusUnauthorized
	}
	if parts[0] == "Bearer" {

		tkn, err := a.ParseAuthToken(parts[1])
		if err != nil {
			log.Printf("Authorization invalid: [%s]\n", err.Error())
			return nil, http.StatusUnauthorized
		}
		if tkn.IsAuthorized(streamRequested, scopes) {
			return &AuthContext{
				StreamId:  streamRequested,
				ProjectId: tkn.ProjectId,
				Eat:       tkn,
			}, http.StatusOK
		}
		return nil, http.StatusUnauthorized
	}
	log.Printf("Received invalid authorization: %s\n", parts[0])
	return nil, http.StatusUnauthorized

}

// ParseAuthToken parses and validates an authorization token. An *EventAuthToken is only returned if the token was validated otherwise nil
func (a *AuthIssuer) ParseAuthToken(tokenString string) (*EventAuthToken, error) {
	if a.PublicKey == nil {
		return nil, errors.New("ERROR: No public key provided to validate authorization token.")
	}

	// In case of cut/paste error, trim extra spaces
	tokenString = strings.TrimSpace(tokenString)

	valid := true
	token, err := jwt.ParseWithClaims(tokenString, &EventAuthToken{}, a.PublicKey.Keyfunc)
	if err != nil {
		log.Printf("Error validating token: %s", err.Error())
		valid = false
	}
	if token.Header["typ"] != "jwt" {
		log.Printf("token is not an authorization token (JWT)")
		return nil, errors.New("token type is not an authorization token (`jwt`)")
	}

	// jsonByte, _ := json.MarshalIndent(token.Claims, "", "  ")
	// claimString := string(jsonByte)
	// log.Println(claimString)
	if claims, ok := token.Claims.(*EventAuthToken); ok && valid {
		return claims, nil
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

type EventAuthToken struct {
	StreamIds []string `json:"sid,omitempty"`
	ProjectId string   `json:"project_id"`
	Scopes    []string `json:"roles,omitempty"`
	ClientId  string   `json:"client_id,omitempty"`
	jwt.RegisteredClaims
}

func (t *EventAuthToken) IsScopeMatch(scopesAccepted []string) bool {

	for _, acceptedScope := range scopesAccepted {
		for _, scope := range t.Scopes {
			if strings.EqualFold(scope, ScopeRoot) {
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
