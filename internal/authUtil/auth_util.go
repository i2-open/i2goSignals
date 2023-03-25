package authUtil

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"

	"github.com/MicahParks/keyfunc"
	"github.com/golang-jwt/jwt/v4"
)

func ValidateAuthorization(r *http.Request, pubKey *keyfunc.JWKS) (string, int) {
	authz := r.Header.Get("Authorization")
	if authz == "" {
		return "", http.StatusUnauthorized
	}

	parts := strings.Split(authz, " ")
	if parts[0] == "Bearer" {

		tkn, err := ParseAuthToken(parts[1], pubKey)
		if err != nil {
			log.Printf("Authorization invalid: [%s]\n", err.Error())
			return "", http.StatusUnauthorized
		}
		return tkn.StreamId, http.StatusOK
	}
	log.Printf("Received invalid authorization type: [%s]\n", parts[0])
	return "", http.StatusUnauthorized

}

func ParseAuthToken(tokenString string, issuerPublicJwks *keyfunc.JWKS) (*EventAuthToken, error) {
	token, err := jwt.ParseWithClaims(tokenString, &EventAuthToken{}, issuerPublicJwks.Keyfunc)
	if err != nil {
		log.Printf("Error validating token: %s", err.Error())
	}
	if token.Header["typ"] != "jwt" {
		log.Printf("token is not an authorization token (JWT)")
		return nil, errors.New("token type is not an authorization token (`jwt`)")
	}

	jsonByte, _ := json.MarshalIndent(token.Claims, "", "  ")
	claimString := string(jsonByte)
	log.Println(claimString)
	if claims, ok := token.Claims.(*EventAuthToken); ok && token.Valid {
		return claims, nil
	}
	return nil, err
}

type EventAuthToken struct {
	StreamId string `json:"sid"`
	jwt.RegisteredClaims
}
