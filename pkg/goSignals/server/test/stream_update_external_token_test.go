package test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/MicahParks/keyfunc/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/i2-open/i2goSignals/internal/authUtil"
	"github.com/i2-open/i2goSignals/pkg/authSupport"
	"github.com/i2-open/i2goSignals/pkg/httpSupport"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
)

func TestStreamUpdate_ExternalToken(t *testing.T) {
	instance, err := createServer(t, "external_token_test_db", true)
	assert.NoError(t, err)
	defer instance.app.Shutdown()
	defer instance.ts.Close()

	// 1. Generate RSA key pair for external "OAuth" server
	oauthPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	// 2. Create a JWKS for this key
	n := base64.RawURLEncoding.EncodeToString(oauthPrivateKey.N.Bytes())
	jwksJSON := []byte(fmt.Sprintf(`{"keys":[{"kty":"RSA","kid":"external","n":"%s","e":"AQAB"}]}`, n))
	jwks, err := keyfunc.NewJSON(jwksJSON)
	assert.NoError(t, err)

	// Set OAuthPubKeys on the auth issuer
	instance.app.Auth.OAuthPubKeys = []*keyfunc.JWKS{jwks}

	// Create OIDC Claims that match our scopes
	claims := &authSupport.OidcClaims{
		Scope: authSupport.ScopeStreamMgmt,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "external-issuer",
			Subject:   "test-user",
			Audience:  jwt.ClaimStrings{"goSignals"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}
	// Sign with oauthPrivateKey
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "external"
	tokenString, err := token.SignedString(oauthPrivateKey)
	assert.NoError(t, err)

	// 3. Create a stream to update - use empty project ID to match external token context
	transConfig := model.StreamConfiguration{
		Aud: []string{"test.example.com"},
		Iss: "DEFAULT",
	}
	config, err := instance.provider.CreateStream(transConfig, authUtil.ConvertProject(""))
	assert.NoError(t, err)

	// 4. Prepare update request
	config.EventsRequested = config.EventsSupported
	bodyBytes, _ := json.Marshal(config)
	// Add stream_id to query to populate authCtx.StreamId
	streamUrl := fmt.Sprintf("http://%s/stream?stream_id=%s", instance.host, config.Id)
	req, err := http.NewRequest(http.MethodPut, streamUrl, bytes.NewReader(bodyBytes))
	assert.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+tokenString)

	// This should NOT panic and should return 200 OK
	resp, err := instance.client.Do(req)
	assert.NoError(t, err)
	defer httpSupport.HandleRespClose(resp)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}
