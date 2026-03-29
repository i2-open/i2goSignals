package test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type LoadKeyExtensionSuite struct {
	suite.Suite
	ssf *ssfInstance
}

func (suite *LoadKeyExtensionSuite) SetupSuite() {
	ssf, err := createServer(suite.T(), "loadkey_extension_test", true)
	assert.NoError(suite.T(), err)
	suite.ssf = ssf
}

func (suite *LoadKeyExtensionSuite) TearDownSuite() {
	if suite.ssf != nil {
		suite.ssf.app.Shutdown()
	}
}

func (suite *LoadKeyExtensionSuite) TestLoadKeyConflict() {
	issuer := "conflict-test.com"
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	pemData := suite.getPem(privateKey)

	url := fmt.Sprintf("http://%s/key/%s", suite.ssf.host, issuer)

	// 1. Load first key
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(pemData))
	req.Header.Set("Content-Type", "application/x-pem-file")
	req.Header.Set("Authorization", "Bearer "+suite.ssf.streamMgmtToken)

	resp, err := suite.ssf.client.Do(req)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)

	// 2. Load same issuer again without force - should fail with 409
	req, _ = http.NewRequest(http.MethodPost, url, bytes.NewReader(pemData))
	req.Header.Set("Content-Type", "application/x-pem-file")
	req.Header.Set("Authorization", "Bearer "+suite.ssf.streamMgmtToken)

	resp, err = suite.ssf.client.Do(req)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), http.StatusConflict, resp.StatusCode)
}

func (suite *LoadKeyExtensionSuite) TestLoadKeyForceReplace() {
	issuer := "replace-test.com"
	privateKey1, _ := rsa.GenerateKey(rand.Reader, 2048)
	pemData1 := suite.getPem(privateKey1)

	url := fmt.Sprintf("http://%s/key/%s", suite.ssf.host, issuer)

	// 1. Load first key
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(pemData1))
	req.Header.Set("Content-Type", "application/x-pem-file")
	req.Header.Set("Authorization", "Bearer "+suite.ssf.streamMgmtToken)
	resp, _ := suite.ssf.client.Do(req)
	assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)

	// 2. Load with force=replace
	privateKey2, _ := rsa.GenerateKey(rand.Reader, 2048)
	pemData2 := suite.getPem(privateKey2)
	req, _ = http.NewRequest(http.MethodPost, url+"?force=replace", bytes.NewReader(pemData2))
	req.Header.Set("Content-Type", "application/x-pem-file")
	req.Header.Set("Authorization", "Bearer "+suite.ssf.streamMgmtToken)
	resp, err := suite.ssf.client.Do(req)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)

	// Verify it replaced (only one key should exist)
	summaries, err := suite.ssf.provider.ListSummaries()
	assert.NoError(suite.T(), err)
	found := false
	for _, s := range summaries {
		if s.KeyName == issuer {
			assert.Equal(suite.T(), 0, s.Rotations, "Should have 0 rotations after replace")
			found = true
		}
	}
	assert.True(suite.T(), found)
}

func (suite *LoadKeyExtensionSuite) TestLoadKeyForceRotate() {
	issuer := "rotate-test.com"
	privateKey1, _ := rsa.GenerateKey(rand.Reader, 2048)
	pemData1 := suite.getPem(privateKey1)

	url := fmt.Sprintf("http://%s/key/%s", suite.ssf.host, issuer)

	// 1. Load first key
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(pemData1))
	req.Header.Set("Content-Type", "application/x-pem-file")
	req.Header.Set("Authorization", "Bearer "+suite.ssf.streamMgmtToken)
	resp, _ := suite.ssf.client.Do(req)
	assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)

	// 2. Load with force=rotate
	privateKey2, _ := rsa.GenerateKey(rand.Reader, 2048)
	pemData2 := suite.getPem(privateKey2)
	req, _ = http.NewRequest(http.MethodPost, url+"?force=rotate", bytes.NewReader(pemData2))
	req.Header.Set("Content-Type", "application/x-pem-file")
	req.Header.Set("Authorization", "Bearer "+suite.ssf.streamMgmtToken)
	resp, err := suite.ssf.client.Do(req)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)

	// Verify it rotated (two keys should exist for this issuer)
	summaries, err := suite.ssf.provider.ListSummaries()
	assert.NoError(suite.T(), err)
	found := false
	for _, s := range summaries {
		if s.KeyName == issuer {
			assert.Equal(suite.T(), 1, s.Rotations, "Should have 1 rotation after rotate")
			found = true
		}
	}
	assert.True(suite.T(), found)
}

func (suite *LoadKeyExtensionSuite) TestLoadKeyUseParameter() {
	issuerSig := "use-sig-test.com"
	issuerEnc := "use-enc-test.com"
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	pemData := suite.getPem(privateKey)

	// 1. Test use=sig (default)
	urlSig := fmt.Sprintf("http://%s/key/%s?use=sig", suite.ssf.host, issuerSig)
	req, _ := http.NewRequest(http.MethodPost, urlSig, bytes.NewReader(pemData))
	req.Header.Set("Content-Type", "application/x-pem-file")
	req.Header.Set("Authorization", "Bearer "+suite.ssf.streamMgmtToken)
	resp, _ := suite.ssf.client.Do(req)
	assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)

	// Verify use in JWKS
	jwksUrlSig := fmt.Sprintf("http://%s/jwks/%s", suite.ssf.host, issuerSig)
	resp, _ = suite.ssf.client.Get(jwksUrlSig)
	var jwksSig map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&jwksSig)
	keysSig := jwksSig["keys"].([]interface{})
	assert.Equal(suite.T(), "sig", keysSig[0].(map[string]interface{})["use"])

	// 2. Test use=enc
	urlEnc := fmt.Sprintf("http://%s/key/%s?use=enc", suite.ssf.host, issuerEnc)
	req, _ = http.NewRequest(http.MethodPost, urlEnc, bytes.NewReader(pemData))
	req.Header.Set("Content-Type", "application/x-pem-file")
	req.Header.Set("Authorization", "Bearer "+suite.ssf.streamMgmtToken)
	resp, _ = suite.ssf.client.Do(req)
	assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)

	// Verify use in JWKS
	jwksUrlEnc := fmt.Sprintf("http://%s/jwks/%s", suite.ssf.host, issuerEnc)
	resp, _ = suite.ssf.client.Get(jwksUrlEnc)
	var jwksEnc map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&jwksEnc)
	keysEnc := jwksEnc["keys"].([]interface{})
	assert.Equal(suite.T(), "enc", keysEnc[0].(map[string]interface{})["use"])

	// 3. Test invalid use
	urlInvalid := fmt.Sprintf("http://%s/key/%s?use=invalid", suite.ssf.host, "invalid-use")
	req, _ = http.NewRequest(http.MethodPost, urlInvalid, bytes.NewReader(pemData))
	req.Header.Set("Content-Type", "application/x-pem-file")
	req.Header.Set("Authorization", "Bearer "+suite.ssf.streamMgmtToken)
	resp, _ = suite.ssf.client.Do(req)
	assert.Equal(suite.T(), http.StatusBadRequest, resp.StatusCode)
}

func (suite *LoadKeyExtensionSuite) getPem(key *rsa.PrivateKey) []byte {
	pkcs8Bytes, _ := x509.MarshalPKCS8PrivateKey(key)
	pemBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkcs8Bytes,
	}
	return pem.EncodeToMemory(pemBlock)
}

func TestLoadKeyExtensionSuite(t *testing.T) {
	suite.Run(t, new(LoadKeyExtensionSuite))
}
