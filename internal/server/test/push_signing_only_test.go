package test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// signingOnlyJWKSBytes renders a minimal, standards-valid JWKS document for the
// public half of an RSA key under the given kid (modeled on rsaPublicJWKSBytes in
// pkg/services/stream_service_jwks_freeform_e2e_test.go).
func signingOnlyJWKSBytes(t *testing.T, kid string, pub *rsa.PublicKey) []byte {
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

func pushSigningOnlySubject() *goSet.EventSubject {
	return &goSet.EventSubject{
		SubjectIdentifier: goSet.SubjectIdentifier{
			Format:                    "scim",
			UniformResourceIdentifier: goSet.UniformResourceIdentifier{Uri: "/Users/signing-only"},
		},
	}
}

// TestPushSigningOnly exercises the #184 signing-only receive posture on the
// RFC8935 push handler (ReceivePushEventHandler, POST /events/{id}). For a
// signing-only receiver stream the SET's JWS signature — not a transport bearer —
// is the trust gate: a bearer is OPTIONAL, but any bearer that IS presented must
// still be valid, and inbound signature verification is mandatory.
func TestPushSigningOnly(t *testing.T) {
	instance, err := createServer(t, "push_signing_only_test", true)
	require.NoError(t, err)
	defer func() {
		if instance.ts != nil {
			instance.ts.Close()
		}
		instance.app.Shutdown()
	}()

	const kid = "test-kid"
	const issuer = "https://issuer.example.com"
	aud := []string{"https://receiver.example.com"}

	// 1. Stand up a JWKS server hosting the public half of the signing key.
	signingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	jwksMux := http.NewServeMux()
	jwksMux.HandleFunc("/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(signingOnlyJWKSBytes(t, kid, &signingKey.PublicKey))
	})
	jwksServer := httptest.NewServer(jwksMux)
	defer jwksServer.Close()
	jwksUrl := jwksServer.URL + "/jwks.json"

	// 2. Create a SigningOnly ReceivePush receiver stream.
	streamConfig := model.StreamConfiguration{
		Iss:             issuer,
		Aud:             aud,
		IssuerJWKSUrl:   jwksUrl,
		SigningOnly:     true,
		EventsSupported: []string{"*"},
		RouteMode:       model.RouteModeImport,
		Delivery: &model.OneOfStreamConfigurationDelivery{
			PushReceiveMethod: &model.PushReceiveMethod{
				Method: model.ReceivePush,
			},
		},
	}
	body, _ := json.Marshal(streamConfig)
	req, _ := http.NewRequest(http.MethodPost, instance.ts.URL+"/stream", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+instance.streamMgmtToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := instance.client.Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	var created model.StreamConfiguration
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&created))
	resp.Body.Close()
	require.NotEmpty(t, created.Id)
	require.True(t, created.SigningOnly, "created stream must persist the signing-only posture")
	endpoint := created.Delivery.PushReceiveMethod.EndpointUrl
	require.NotEmpty(t, endpoint, "created push receiver must expose an /events/{id} endpoint")

	// signedSet builds and signs a SET for the given key and issuer, always tagging
	// the JWS with kid=test-kid so the JWKS lookup resolves to the configured key.
	signedSet := func(t *testing.T, key *rsa.PrivateKey, iss string) string {
		t.Helper()
		set := goSet.CreateSet(pushSigningOnlySubject(), iss, aud)
		set.Kid = kid
		set.AddEventPayload("https://schemas.openid.net/secevent/risc/event-type/account-disabled",
			map[string]interface{}{"reason": "signing-only test"})
		signed, err := set.JWS(jwt.SigningMethodRS256, key)
		require.NoError(t, err)
		return signed
	}

	// postSet POSTs a SET to the signing-only push endpoint, optionally with a bearer.
	postSet := func(t *testing.T, token, authHeader string) *http.Response {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(token))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/secevent+jwt")
		if authHeader != "" {
			req.Header.Set("Authorization", authHeader)
		}
		resp, err := instance.client.Do(req)
		require.NoError(t, err)
		return resp
	}

	type errBody struct {
		Err string `json:"err"`
	}
	decodeErr := func(t *testing.T, resp *http.Response) errBody {
		t.Helper()
		var eb errBody
		raw, _ := io.ReadAll(resp.Body)
		require.NoError(t, json.Unmarshal(raw, &eb))
		return eb
	}

	// (a) No Authorization header + SET signed by the JWKS key -> 202 Accepted.
	t.Run("NoAuth_GoodSignature_Accepted", func(t *testing.T) {
		resp := postSet(t, signedSet(t, signingKey, issuer), "")
		defer resp.Body.Close()
		assert.Equal(t, http.StatusAccepted, resp.StatusCode,
			"a good per-SET signature is the trust gate; no bearer is required for a signing-only stream")
	})

	// (b) No Authorization header + SET signed by a DIFFERENT (attacker) key ->
	// 400 jws_signature_failed.
	t.Run("NoAuth_BadSignature_Rejected", func(t *testing.T) {
		attackerKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		resp := postSet(t, signedSet(t, attackerKey, issuer), "")
		defer resp.Body.Close()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		assert.Equal(t, "jws_signature_failed", decodeErr(t, resp).Err)
	})

	// (c) Authorization header present but invalid + a GOOD SET -> rejected at the
	// request level with authentication_failed (a presented bearer is NOT bypassed).
	// Note: the RFC8935 push handler writes all delivery errors with HTTP 400
	// (goSetPush.WriteDeliveryError), so the status is 400, not 401.
	t.Run("InvalidBearer_NotBypassed", func(t *testing.T) {
		resp := postSet(t, signedSet(t, signingKey, issuer), "Bearer not-a-real-token")
		defer resp.Body.Close()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		assert.Equal(t, "authentication_failed", decodeErr(t, resp).Err,
			"a presented-but-invalid bearer must be rejected, never bypassed by the signing-only posture")
	})

	// (d) No Authorization header + a good-signature SET whose iss != stream Iss ->
	// 400 invalid_issuer (iss/aud are still validated under the signing-only posture).
	t.Run("NoAuth_WrongIssuer_Rejected", func(t *testing.T) {
		resp := postSet(t, signedSet(t, signingKey, "https://attacker.example.com"), "")
		defer resp.Body.Close()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		assert.Equal(t, "invalid_issuer", decodeErr(t, resp).Err)
	})

	// (e) Forward (FW) route mode. The signing-only posture is RouteMode-agnostic at
	// the receive gate — verification happens on receive and the FW router relays the
	// original token downstream unchanged (no re-sign; PB would re-sign). So a
	// signing-only FW receiver accepts a validly-signed SET with no bearer, exactly
	// like IM (criterion #10).
	t.Run("ForwardMode_GoodSignature_Accepted", func(t *testing.T) {
		fwConfig := model.StreamConfiguration{
			Iss:             issuer,
			Aud:             aud,
			IssuerJWKSUrl:   jwksUrl,
			SigningOnly:     true,
			EventsSupported: []string{"*"},
			RouteMode:       model.RouteModeForward,
			Delivery: &model.OneOfStreamConfigurationDelivery{
				PushReceiveMethod: &model.PushReceiveMethod{Method: model.ReceivePush},
			},
		}
		fwBody, _ := json.Marshal(fwConfig)
		fwReq, _ := http.NewRequest(http.MethodPost, instance.ts.URL+"/stream", bytes.NewReader(fwBody))
		fwReq.Header.Set("Authorization", "Bearer "+instance.streamMgmtToken)
		fwReq.Header.Set("Content-Type", "application/json")
		fwResp, err := instance.client.Do(fwReq)
		require.NoError(t, err)
		require.Equal(t, http.StatusCreated, fwResp.StatusCode)
		var fwCreated model.StreamConfiguration
		require.NoError(t, json.NewDecoder(fwResp.Body).Decode(&fwCreated))
		fwResp.Body.Close()
		require.Equal(t, model.RouteModeForward, fwCreated.RouteMode)
		require.True(t, fwCreated.SigningOnly)

		post, err := http.NewRequest(http.MethodPost,
			fwCreated.Delivery.PushReceiveMethod.EndpointUrl,
			strings.NewReader(signedSet(t, signingKey, issuer)))
		require.NoError(t, err)
		post.Header.Set("Content-Type", "application/secevent+jwt")
		gotResp, err := instance.client.Do(post)
		require.NoError(t, err)
		defer gotResp.Body.Close()
		assert.Equal(t, http.StatusAccepted, gotResp.StatusCode,
			"a signing-only FW receiver accepts a validly-signed SET with no bearer, same as IM")
	})
}
