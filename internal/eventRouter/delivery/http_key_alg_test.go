package delivery

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Spec #114: a push stream with no signing_alg re-signs with the method of the
// key it was handed (the issuer's newest of any type), so an ES256 key yields
// an ES256 SET under its kid; a pinned alg still decides.
func TestHTTPAdapter_EmptySigningAlgSignsWithTheKeysType(t *testing.T) {
	var mu sync.Mutex
	var bodies []string
	receiver := httptest.NewServer(captureBody(&bodies, &mu))
	defer receiver.Close()

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	rsaKey, rsaKid := newTestKey(t)

	for _, tc := range []struct {
		name, signingAlg, kid, wantAlg string
		key                            crypto.Signer
	}{
		{"empty alg, EC key", "", "kid-es", "ES256", ecKey},
		{"empty alg, RSA key", "", rsaKid, "RS256", rsaKey},
		{"pinned ES256", "ES256", "kid-es", "ES256", ecKey},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stream := newPublishStream(receiver.URL + "/events")
			stream.StreamConfiguration.SigningAlg = tc.signingAlg
			req := PushRequest{Stream: stream, Event: newEventRecord(), Key: tc.key, Kid: tc.kid}
			out := NewHTTPAdapter(nil, nil).Deliver(context.Background(), req)
			require.NoError(t, out.SignErr)

			parsed, _, err := jwt.NewParser().ParseUnverified(out.JWS, jwt.MapClaims{})
			require.NoError(t, err)
			assert.Equal(t, tc.wantAlg, parsed.Header["alg"])
			assert.Equal(t, tc.kid, parsed.Header["kid"])
		})
	}
}
