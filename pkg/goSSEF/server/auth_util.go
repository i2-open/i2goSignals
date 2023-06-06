package server

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/MicahParks/keyfunc"
	"github.com/golang-jwt/jwt/v4"
)

func (sa *SignalsApplication) CheckAdminAuthorized(w http.ResponseWriter, r *http.Request, pubKey *keyfunc.JWKS) bool {
	authz := r.Header.Get("Authorization")

	if authz == "" {
		w.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return false
	}

	parts := strings.Split(authz, " ")
	if len(parts) < 2 {
		w.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	}
	switch parts[0] {
	case "Bearer":
		if pubKey == nil {
			w.WriteHeader(http.StatusForbidden) // bearer tokens are not configured for admin
			return false
		}
		token, err := ParseAuthToken(parts[1], pubKey)
		if err != nil {
			log.Printf("Authorization invalid: [%s]\n", err.Error())
			w.WriteHeader(http.StatusUnauthorized)
			return false
		}
		roles := token.Roles
		for _, role := range roles {
			if strings.EqualFold(sa.AdminRole, role) {
				return true
			}
		}

	case "Basic":
		user, pwd, ok := r.BasicAuth()
		if ok {
			if strings.EqualFold(sa.AdminUser, user) && sa.AdminPwd == pwd {
				return true
			}
		}
	}
	w.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
	http.Error(w, "Unauthorized", http.StatusUnauthorized)
	return false
}

func ValidateAuthorization(r *http.Request, pubKey *keyfunc.JWKS) (string, int) {
	authz := r.Header.Get("Authorization")
	if authz == "" {
		return "", http.StatusUnauthorized
	}
	fmt.Sprintf("Authorization: %s", authz)
	parts := strings.Split(authz, " ")
	if parts[0] == "Bearer" {

		tkn, err := ParseAuthToken(parts[1], pubKey)
		if err != nil {
			log.Printf("Authorization invalid: [%s]\n", err.Error())
			return "", http.StatusUnauthorized
		}
		return tkn.StreamId, http.StatusOK
	}
	log.Printf("Received invalid authorization: %s\n", parts[0])
	return "", http.StatusUnauthorized

}

func ParseAuthToken(tokenString string, issuerPublicJwks *keyfunc.JWKS) (*EventAuthToken, error) {
	if issuerPublicJwks == nil {
		return nil, errors.New("ERROR: No public key provided to validate authorization token.")
	}
	token, err := jwt.ParseWithClaims(tokenString, &EventAuthToken{}, issuerPublicJwks.Keyfunc)
	if err != nil {
		log.Printf("Error validating token: %s", err.Error())
	}
	if token.Header["typ"] != "jwt" {
		log.Printf("token is not an authorization token (JWT)")
		return nil, errors.New("token type is not an authorization token (`jwt`)")
	}

	// jsonByte, _ := json.MarshalIndent(token.Claims, "", "  ")
	// claimString := string(jsonByte)
	// log.Println(claimString)
	if claims, ok := token.Claims.(*EventAuthToken); ok && token.Valid {
		return claims, nil
	}

	return nil, err
}

type EventAuthToken struct {
	StreamId string   `json:"sid"`
	Roles    []string `json:"roles,omitempty"`
	jwt.RegisteredClaims
}
