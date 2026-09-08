package services

// End-to-end ES256 round trip (i2goSignals#284).
//
// The acceptance criterion this file exists for: "a stream created with
// signing_alg: ES256 signs and is verified end to end across push, poll and
// SSTP; existing RS256 streams are byte-identical in behaviour."
//
// Every hop is the production code path, the same way the ML-DSA round trip
// does it: KeyService mints and publishes, GetSigner + goSet.SigningMethodFor
// pick the signer the router would pick, goSet.JWS produces the wire string the
// delivery adapters produce, and the three receivers are their own public entry
// points rather than a shared helper that only resembles them.

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/goSetPoll"
	"github.com/i2-open/i2goSignals/pkg/goSetPush"
	"github.com/i2-open/i2goSignals/pkg/goSetSstp"
)

const es256Alg = "ES256"

func TestES256RoundTrip_TransmitterToJWKSToEveryReceiver(t *testing.T) {
	ctx := context.Background()
	svc, _ := newMLDSATestService(t)
	require.NoError(t, err0(svc.EnsureSigningKeyForAlg(ctx, rtIssuer, es256Alg, "")))

	ecSET := transmit(t, svc, es256Alg)

	// The wire token announces ES256...
	header := decodeJOSEHeader(t, ecSET)
	assert.Equal(t, es256Alg, header["alg"])
	assert.Equal(t, "secevent+jwt", header["typ"])

	// ...and the JWKS carries the RSA and the EC key, so a receiver can resolve
	// its kid without the issuer having rotated anything away.
	jwks := receiverJWKS(t, svc)
	require.Len(t, jwks.KIDs(), 2)

	t.Run("push receiver", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/events", strings.NewReader(ecSET))
		req.Header.Set("Content-Type", "application/secevent+jwt")

		received, deliveryErr := goSetPush.ParseReceivedSET(req, goSetPush.ReceiverConfig{
			JWKS:              jwks,
			ExpectedIssuer:    rtIssuer,
			ExpectedAudiences: []string{rtAudience},
			RequireSignature:  true,
		})
		require.Nil(t, deliveryErr)
		assert.Equal(t, rtIssuer, received.Token.Issuer)
	})

	t.Run("poll receiver", func(t *testing.T) {
		jti := mustJTI(t, ecSET)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"sets": map[string]string{jti: ecSET}})
		}))
		defer server.Close()

		resp, status, err := goSetPoll.Poll(context.Background(), goSetPoll.PollRequest{ReturnImmediately: true},
			goSetPoll.ReceiverConfig{
				EndpointURL:       server.URL,
				JWKS:              jwks,
				ExpectedIssuer:    rtIssuer,
				ExpectedAudiences: []string{rtAudience},
				RequireSignature:  true,
			})
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, status)
		require.Empty(t, resp.Errors, "an ES256-signed SET must not land in the poll error map")
		require.Contains(t, resp.ParsedSETs, jti)
		assert.Equal(t, rtIssuer, resp.ParsedSETs[jti].Issuer)
	})

	t.Run("sstp inbound", func(t *testing.T) {
		verified, err := goSetSstp.VerifySET(ecSET, goSetSstp.VerifyConfig{
			JWKS:              jwks,
			ExpectedIssuer:    rtIssuer,
			ExpectedAudiences: []string{rtAudience},
			RequireSignature:  true,
		})
		require.NoError(t, err)
		assert.Equal(t, rtIssuer, verified.Issuer)
	})
}

// TestES256RoundTrip_AnRS256StreamOnTheSameIssuerIsUnaffected is the other half
// of the opt-in promise, and the acceptance criterion that RS256 stays the
// default: turning one stream to ES256 must be invisible to every other stream
// of the same issuer, including to a receiver holding the pre-opt-in JWKS.
func TestES256RoundTrip_AnRS256StreamOnTheSameIssuerIsUnaffected(t *testing.T) {
	ctx := context.Background()
	svc, _ := newMLDSATestService(t)

	before := transmit(t, svc, "")
	beforeHeader := decodeJOSEHeader(t, before)
	beforeJWKS := receiverJWKS(t, svc)
	require.NoError(t, err0(svc.EnsureSigningKeyForAlg(ctx, rtIssuer, es256Alg, "")))
	after := transmit(t, svc, "")

	// Same alg, same kid, same key: nothing about the RS256 stream moved.
	afterHeader := decodeJOSEHeader(t, after)
	assert.Equal(t, beforeHeader, afterHeader)
	assert.Equal(t, "RS256", afterHeader["alg"])

	// A receiver holding the JWKS from BEFORE the opt-in still verifies the
	// RS256 stream's tokens.
	_, err := goSet.Parse(after, beforeJWKS)
	assert.NoError(t, err)

	// And a receiver on the widened JWKS verifies it too.
	_, err = goSet.Parse(after, receiverJWKS(t, svc))
	assert.NoError(t, err)
}

// TestES256RoundTrip_TheRSAKidCannotVerifyTheECStream pins the kid separation.
// Both keys live in one JWKS under one issuer, so a receiver resolving the
// wrong kid must fail rather than silently accept.
func TestES256RoundTrip_TheRSAKidCannotVerifyTheECStream(t *testing.T) {
	ctx := context.Background()
	svc, _ := newMLDSATestService(t)
	require.NoError(t, err0(svc.EnsureSigningKeyForAlg(ctx, rtIssuer, es256Alg, "")))

	key, _, err := svc.GetSigner(ctx, rtIssuer, es256Alg)
	require.NoError(t, err)

	set := goSet.CreateSet(nil, rtIssuer, []string{rtAudience})
	// The RSA key's kid is the issuer name; claiming it for an EC signature is
	// the algorithm-confusion shape the pinned given keys exist to refuse.
	set.Kid = rtIssuer
	method, err := goSet.SigningMethodFor(es256Alg)
	require.NoError(t, err)
	mismatched, err := set.JWS(method, key)
	require.NoError(t, err)

	_, err = goSet.Parse(mismatched, receiverJWKS(t, svc))
	assert.Error(t, err)
}

// TestES256RoundTrip_SignerIsSelectedByAlgorithmNotRecency: the EC record is the
// newer one, so a store that picked "newest" would hand an RS256 stream a key
// RS256 cannot use.
func TestES256RoundTrip_SignerIsSelectedByAlgorithmNotRecency(t *testing.T) {
	ctx := context.Background()
	svc, _ := newMLDSATestService(t)
	require.NoError(t, err0(svc.EnsureSigningKeyForAlg(ctx, rtIssuer, es256Alg, "")))

	ecKey, ecKid, err := svc.GetSigner(ctx, rtIssuer, es256Alg)
	require.NoError(t, err)
	assert.IsType(t, &ecdsa.PrivateKey{}, ecKey)

	rsaKey, rsaKid, err := svc.GetSigner(ctx, rtIssuer, "")
	require.NoError(t, err)
	assert.NotEqual(t, ecKid, rsaKid, "the two keys must be published under distinct kids")
	assert.NotEqual(t, ecKey, rsaKey)
}
