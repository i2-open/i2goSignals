package services

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// rsaPublicJWKSBytes renders a minimal, standards-valid JWKS document for the
// public half of an RSA key under the given kid.
func rsaPublicJWKSBytes(t *testing.T, kid string, pub *rsa.PublicKey) []byte {
	t.Helper()
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
	doc := map[string]any{
		"keys": []map[string]any{
			{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid, "n": n, "e": e},
		},
	}
	b, err := json.Marshal(doc)
	require.NoError(t, err)
	return b
}

// TestCreateStream_FreeFormJwksUri_EndToEnd is the SSF §7.2.4 regression guard the
// issue (#207 Scope A) requires: a transmitter whose jwks_uri lives on an entirely
// different host AND path from its iss must be honored end to end —
// registration → key fetch → SET verify — with nothing silently coupling iss to
// jwks_uri. Earlier coverage proved each leg in isolation; this connects them so
// the property can't regress through a gap between the layers.
//
//   - registration: the real receiver CreateStream runs the §7.2.4 issuer-binding
//     check (issuer == discovery location, so it binds even under strict) and
//     carries the free-form jwks_uri verbatim into the stored stream config — it is
//     never derived from iss.
//   - key fetch: the JWKS loads from that free-form URL (a different host from iss).
//   - SET verify: a SET signed under iss (NOT the jwks host) verifies against the
//     keys fetched from the free-form jwks_uri.
//
// If anyone "fixes" the code to require iss == jwks_uri, one of these legs breaks.
func TestCreateStream_FreeFormJwksUri_EndToEnd(t *testing.T) {
	// A transmitter signing key whose public JWKS is served on a SEPARATE host.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	const kid = "free-form-e2e-key"

	// JWKS host: a second server at a path deliberately unrelated to any issuer.
	jwksMux := http.NewServeMux()
	jwksMux.HandleFunc("/keys/not-the-issuer.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(rsaPublicJWKSBytes(t, kid, &key.PublicKey))
	})
	jwksServer := httptest.NewServer(jwksMux)
	defer jwksServer.Close()
	freeFormJwksUri := jwksServer.URL + "/keys/not-the-issuer.json"

	// Transmitter host: issuer == discovery location (binds), jwks_uri elsewhere.
	cfg := model.TransmitterConfiguration{JwksUri: freeFormJwksUri}
	txMux := http.NewServeMux()
	txMux.HandleFunc("/.well-known/ssf-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(cfg)
	})
	txMux.HandleFunc("/streams", func(w http.ResponseWriter, r *http.Request) {
		var req model.StreamConfiguration
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		req.Id = "remote-freeform-stream"
		if req.Delivery != nil && req.Delivery.PollTransmitMethod != nil {
			req.Delivery.PollTransmitMethod.EndpointUrl = "http://transmitter.com/poll/x"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(req)
	})
	txServer := httptest.NewServer(txMux)
	defer txServer.Close()
	cfg.ConfigurationEndpoint = txServer.URL + "/streams"
	cfg.Issuer = txServer.URL // issuer == discovery location → clean §7.2.4 binding

	// The jwks_uri must genuinely be a different host than iss for this to mean
	// anything (httptest assigns each server a distinct host:port).
	require.NotEqual(t, txServer.URL, jwksServer.URL, "jwks_uri must be served on a different host than iss")

	token := "test-token"
	server := &model.Server{
		Alias:       "freeform-tx",
		Host:        txServer.URL,
		ClientToken: &token,
		ProjectId:   "test-project",
		StrictSsf:   true, // enforce the binding: a clean binding must pass even under strict
	}

	// --- registration: the real receiver CreateStream path ---
	svc := newStrictTestStreamService(t)
	streamCfg, err := svc.CreateStream(context.Background(), bindingReceiveRequest(), "test-project", server)
	require.NoError(t, err, "a clean issuer binding with a free-form jwks_uri must register even under strict")
	require.Equal(t, freeFormJwksUri, streamCfg.IssuerJWKSUrl,
		"registration must carry the free-form jwks_uri verbatim, never derive it from iss")

	// --- key fetch: load the JWKS from the registered free-form jwks_uri ---
	jwks, err := goSet.GetJwksWithClient(streamCfg.IssuerJWKSUrl, jwksServer.Client())
	require.NoError(t, err, "keys must load from the free-form jwks_uri (a different host from iss)")

	// --- SET verify: a SET issued under iss (different host from jwks) verifies ---
	set := goSet.CreateSet(nil, txServer.URL, []string{"https://receiver.example/"})
	set.Kid = kid
	set.AddEventPayload("https://schemas.openid.net/secevent/risc/event-type/account-enabled", map[string]any{})
	signed, err := set.JWS(jwt.SigningMethodRS256, key)
	require.NoError(t, err)

	parsed, err := goSet.Parse(signed, jwks)
	require.NoError(t, err,
		"a SET whose iss differs from the jwks_uri host must verify against keys fetched from that free-form jwks_uri")
	assert.Equal(t, txServer.URL, parsed.Issuer)
	assert.NotEqual(t, jwksServer.URL, parsed.Issuer, "iss is the transmitter, never the jwks host")
}
