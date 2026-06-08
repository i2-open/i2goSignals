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
	"github.com/i2-open/i2goSignals/pkg/authSupport"
	"github.com/i2-open/i2goSignals/pkg/httpSupport"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
)

// TestStreamUpdate_Issue114_AdminTokenRealProject reproduces issue #114:
// a project/admin-scoped credential that is not a per-stream EAT (here an
// external OAuth/STS token, as goSignalsAdmin uses) names the target stream
// in ?stream_id= and should be able to update it. The stream is created the
// normal way (owned by a real project), unlike TestStreamUpdate_ExternalToken
// which side-steps the bug by creating the stream with an empty project.
func TestStreamUpdate_Issue114_AdminTokenRealProject(t *testing.T) {
	instance, err := createServer(t, "issue114_test_db", true)
	assert.NoError(t, err)
	defer instance.app.Shutdown()
	defer instance.ts.Close()

	// External "OAuth" server key + JWKS, as goSignalsAdmin's STS would have.
	oauthPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)
	n := base64.RawURLEncoding.EncodeToString(oauthPrivateKey.N.Bytes())
	jwksJSON := []byte(fmt.Sprintf(`{"keys":[{"kty":"RSA","kid":"external","n":"%s","e":"AQAB"}]}`, n))
	jwks, err := keyfunc.NewJSON(jwksJSON)
	assert.NoError(t, err)
	instance.app.Auth.OAuthPubKeys = []*keyfunc.JWKS{jwks}

	claims := &authSupport.OidcClaims{
		Scope: authSupport.ScopeStreamMgmt,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "external-issuer",
			Subject:   "gosignals-admin",
			Audience:  jwt.ClaimStrings{"goSignals"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "external"
	tokenString, err := token.SignedString(oauthPrivateKey)
	assert.NoError(t, err)

	// Create a stream owned by a real project (the normal case).
	transConfig := model.StreamConfiguration{
		Aud: []string{"test.example.com"},
		Iss: "DEFAULT",
	}
	config, err := instance.CreateStream(transConfig, authSupport.ConvertProject(instance.projectId))
	assert.NoError(t, err)
	assert.NotEmpty(t, instance.projectId, "stream must be owned by a real project")

	// Update it, naming the stream in ?stream_id=.
	config.EventsRequested = config.EventsSupported
	bodyBytes, _ := json.Marshal(config)
	streamUrl := fmt.Sprintf("http://%s/stream?stream_id=%s", instance.host, config.Id)
	req, err := http.NewRequest(http.MethodPut, streamUrl, bytes.NewReader(bodyBytes))
	assert.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+tokenString)

	resp, err := instance.client.Do(req)
	assert.NoError(t, err)
	defer httpSupport.HandleRespClose(resp)

	assert.Equal(t, http.StatusOK, resp.StatusCode,
		"admin-scoped token must update a stream named by ?stream_id= regardless of stream project ownership")
}
