package goSet

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/MicahParks/keyfunc/v2"
	"github.com/i2-open/i2goSignals/pkg/tlsSupport"
)

func GetJwks(jwksUrl string) (*keyfunc.JWKS, error) {
	keyOptions := keyfunc.Options{
		Ctx: context.Background(),
		RefreshErrorHandler: func(err error) {
			log.Printf("There was an error with the jwt.Keyfunc\nError: %s", err.Error())
		},
		RefreshInterval:   time.Hour,
		RefreshRateLimit:  time.Minute * 5,
		RefreshTimeout:    time.Second * 60,
		RefreshUnknownKID: true,
	}

	// If SPIFFE is enabled, we use the Resilient transport to allow fetching
	// JWKS from both internal SPIFFE nodes and external HTTPS endpoints.
	if tlsSupport.SpiffeEnabled() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		x509Source, err := tlsSupport.NewX509Source(ctx)
		if err == nil {
			// Note: We leak x509Source here if we don't close it, but keyfunc
			// doesn't provide an easy way to close the client. Since this is
			// usually called once per startup or per stream, it's manageable.
			// Ideally we would pass a shared x509Source.
			transport, err := tlsSupport.NewResilientMTLSClientTransport(x509Source)
			if err == nil {
				keyOptions.Client = &http.Client{
					Transport: transport,
					Timeout:   time.Second * 30,
				}
			}
		}
	}

	if jwksUrl == "" {
		return nil, nil
	}
	log.Printf("Loading JWKS key from: %s", jwksUrl)

	return keyfunc.Get(jwksUrl, keyOptions)
}
