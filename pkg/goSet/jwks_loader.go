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
	return GetJwksWithClient(jwksUrl, nil)
}

// GetJwksWithClient is like GetJwks but uses the supplied http.Client when
// non-nil. Receiver streams pass a client whose TLS config honors the stream's
// transmitter TLS settings (tx_tls_skip_verify / tx_tls_certificate) so the
// issuer JWKS can be fetched from a transmitter presenting a self-signed
// certificate. When client is nil, behavior is unchanged (SPIFFE transport when
// enabled, otherwise keyfunc's default client).
//
// It is also the AKP-aware loader: keyfunc skips `kty:"AKP"` entries, so after
// the set is fetched its raw bytes are re-scanned for RFC 9964 ML-DSA keys. If
// any are present the JWKS is re-created with them supplied as keyfunc given
// keys, which keyfunc merges back in on every background refresh. The re-fetch
// costs one extra request and only happens for a transmitter that actually
// publishes a PQ key — a JWKS with no AKP entry takes the original path
// untouched.
func GetJwksWithClient(jwksUrl string, client *http.Client) (*keyfunc.JWKS, error) {
	jwks, err := getJwks(jwksUrl, client, nil)
	if err != nil || jwks == nil {
		return jwks, err
	}
	akp, err := AKPGivenKeys(jwks.RawJWKS())
	if err != nil {
		// The set parsed well enough for keyfunc; refusing it here would lose
		// working RSA keys over an AKP entry the receiver may not even need.
		jwksLog.Warn("Could not scan JWKS for RFC 9964 AKP keys", "url", jwksUrl, "error", err)
		return jwks, nil
	}
	if len(akp) == 0 {
		return jwks, nil
	}
	jwks.EndBackground()
	return getJwks(jwksUrl, client, akp)
}

// getJwks is the keyfunc.Get call shared by both passes of GetJwksWithClient.
// givenKeys is nil on the first pass and carries the AKP keys on the second.
func getJwks(jwksUrl string, client *http.Client, givenKeys map[string]keyfunc.GivenKey) (*keyfunc.JWKS, error) {
	keyOptions := keyfunc.Options{
		GivenKeys: givenKeys,
		Ctx:       context.Background(),
		RefreshErrorHandler: func(err error) {
			log.Printf("There was an error with the jwt.Keyfunc\nError: %s", err.Error())
		},
		RefreshInterval:   time.Hour,
		RefreshRateLimit:  time.Minute * 5,
		RefreshTimeout:    time.Second * 60,
		RefreshUnknownKID: true,
	}

	if client != nil {
		keyOptions.Client = client
	} else if tlsSupport.SpiffeEnabled() {
		// If SPIFFE is enabled, we use the Resilient transport to allow fetching
		// JWKS from both internal SPIFFE nodes and external HTTPS endpoints.
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
