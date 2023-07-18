package goSet

import (
	"context"
	"log"
	"time"

	"github.com/MicahParks/keyfunc"
)

func GetJwks(jwksUrl string) (*keyfunc.JWKS, error) {
	keyOptions := keyfunc.Options{
		Ctx: context.Background(),
		RefreshErrorHandler: func(err error) {
			log.Printf("There was an error with the jwt.Keyfunc\nError: %s", err.Error())
		},
		RefreshInterval:   time.Hour,
		RefreshRateLimit:  time.Minute * 5,
		RefreshTimeout:    time.Second * 10,
		RefreshUnknownKID: true,
	}

	if jwksUrl == "" {
		return nil, nil
	}
	log.Printf("Loading JWKS key from: %s", jwksUrl)
	return keyfunc.Get(jwksUrl, keyOptions)
}
