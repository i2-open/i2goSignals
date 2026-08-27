package services

// End-to-end RFC 9964 round trip (i2goSignals#278).
//
// The acceptance criterion this file exists for: "stream opted into ML-DSA-65 →
// transmitter emits SET with alg: ML-DSA-65 → JWKS shows both keys → receiver
// (push + poll + SSTP inbound) verifies; a second stream on the same issuer
// left at RS256 is byte-identical to before."
//
// Every hop is the production code path: KeyService mints and publishes,
// GetSigner + goSet.SigningMethodFor pick the signer the router would pick,
// goSet.JWS produces the wire string the delivery adapters produce, and the
// three receivers are their own public entry points, not a shared helper that
// only resembles them.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/MicahParks/keyfunc/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/goSet/mldsa"
	"github.com/i2-open/i2goSignals/pkg/goSetPoll"
	"github.com/i2-open/i2goSignals/pkg/goSetPush"
	"github.com/i2-open/i2goSignals/pkg/goSetSstp"
)

const (
	rtIssuer   = "https://tx.example.com"
	rtAudience = "https://rx.example.com"
)

// transmit is one full transmit hop for a stream configured with signingAlg:
// resolve the issuer's signer for that algorithm, then sign.
func transmit(t *testing.T, svc *KeyService, signingAlg string) string {
	t.Helper()
	key, kid, err := svc.GetSigner(context.Background(), rtIssuer, signingAlg)
	require.NoError(t, err)

	set := goSet.CreateSet(nil, rtIssuer, []string{rtAudience})
	set.AddEventPayload("urn:example:event:a", map[string]string{"detail": "round-trip"})
	set.Kid = kid

	method, err := goSet.SigningMethodFor(signingAlg)
	require.NoError(t, err)
	signed, err := set.JWS(method, key)
	require.NoError(t, err)
	return signed
}

// receiverJWKS is the receive-side trust anchor: the issuer's published JWKS,
// loaded exactly as a receiver stream loads it.
func receiverJWKS(t *testing.T, svc *KeyService) *keyfunc.JWKS {
	t.Helper()
	doc := svc.GetPublicJWKS(context.Background(), rtIssuer)
	require.NotNil(t, doc)
	jwks, err := goSet.NewJwksWithAKP(*doc)
	require.NoError(t, err)
	return jwks
}

func TestMLDSARoundTrip_TransmitterToJWKSToEveryReceiver(t *testing.T) {
	ctx := context.Background()
	svc, _ := newMLDSATestService(t)
	require.NoError(t, err0(svc.EnsureSigningKeyForAlg(ctx, rtIssuer, mldsa.Alg, "")))

	pqSET := transmit(t, svc, mldsa.Alg)

	// The wire token announces the post-quantum algorithm...
	header := decodeJOSEHeader(t, pqSET)
	assert.Equal(t, mldsa.Alg, header["alg"])
	assert.Equal(t, "secevent+jwt", header["typ"])

	// ...and the JWKS carries both keys, so a receiver can resolve its kid.
	jwks := receiverJWKS(t, svc)
	require.Len(t, jwks.KIDs(), 2)

	t.Run("push receiver", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/events", strings.NewReader(pqSET))
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
		jti := mustJTI(t, pqSET)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"sets": map[string]string{jti: pqSET}})
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
		require.Empty(t, resp.Errors, "a PQ-signed SET must not land in the poll error map")
		require.Contains(t, resp.ParsedSETs, jti)
		assert.Equal(t, rtIssuer, resp.ParsedSETs[jti].Issuer)
	})

	t.Run("sstp inbound", func(t *testing.T) {
		verified, err := goSetSstp.VerifySET(pqSET, goSetSstp.VerifyConfig{
			JWKS:              jwks,
			ExpectedIssuer:    rtIssuer,
			ExpectedAudiences: []string{rtAudience},
			RequireSignature:  true,
		})
		require.NoError(t, err)
		assert.Equal(t, rtIssuer, verified.Issuer)
	})
}

// TestMLDSARoundTrip_AnRS256StreamOnTheSameIssuerIsUnaffected is the other half
// of the opt-in promise: turning one stream post-quantum must be invisible to
// every other stream of the same issuer.
func TestMLDSARoundTrip_AnRS256StreamOnTheSameIssuerIsUnaffected(t *testing.T) {
	ctx := context.Background()
	svc, _ := newMLDSATestService(t)

	before := transmit(t, svc, "")
	beforeHeader := decodeJOSEHeader(t, before)
	beforeJWKS := receiverJWKS(t, svc)
	require.NoError(t, err0(svc.EnsureSigningKeyForAlg(ctx, rtIssuer, mldsa.Alg, "")))
	after := transmit(t, svc, "")

	// Same alg, same kid, same key: nothing about the RS256 stream moved.
	afterHeader := decodeJOSEHeader(t, after)
	assert.Equal(t, beforeHeader, afterHeader)
	assert.Equal(t, "RS256", afterHeader["alg"])

	// And a receiver holding the JWKS from BEFORE the opt-in still verifies the
	// RS256 stream's tokens — the classical key was neither rotated nor moved.
	_, err := goSet.Parse(after, beforeJWKS)
	assert.NoError(t, err)

	// A receiver on the widened JWKS verifies it too.
	_, err = goSet.Parse(after, receiverJWKS(t, svc))
	assert.NoError(t, err)
}

func TestMLDSARoundTrip_AnUnknownKidStillFails(t *testing.T) {
	ctx := context.Background()
	svc, _ := newMLDSATestService(t)
	require.NoError(t, err0(svc.EnsureSigningKeyForAlg(ctx, rtIssuer, mldsa.Alg, "")))

	// A PQ-signed SET from an issuer this receiver does not publish a key for
	// must fail, not fall through to some other AKP key in the set.
	strangerKey, err := mldsa.GenerateKey()
	require.NoError(t, err)
	set := goSet.CreateSet(nil, rtIssuer, []string{rtAudience})
	set.Kid = "some-other-issuer-ML-DSA-65-1"
	stranger, err := set.JWS(mldsa.SigningMethodMLDSA65, strangerKey)
	require.NoError(t, err)

	_, err = goSet.Parse(stranger, receiverJWKS(t, svc))
	assert.Error(t, err)
}

func base64RawURLDecode(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

func decodeJOSEHeader(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	require.Len(t, parts, 3)
	raw, err := base64RawURLDecode(parts[0])
	require.NoError(t, err)
	var header map[string]any
	require.NoError(t, json.Unmarshal(raw, &header))
	return header
}

func mustJTI(t *testing.T, token string) string {
	t.Helper()
	set, err := goSet.Peek(token)
	require.NoError(t, err)
	require.NotEmpty(t, set.ID)
	return set.ID
}
