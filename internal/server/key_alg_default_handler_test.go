package server

// Spec #114 (i2goSignals#370) on POST /key/{keyName}: every minting response
// carries a Key-Id header naming the new key's kid, and a request with no
// ?alg= mints the server's default key type (I2SIG_KEY_ALG, ES256 unless set).

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/pem"
	"net/http"
	"net/http/httptest"

	"github.com/i2-open/i2goSignals/internal/providers/dbProviders"
	"github.com/i2-open/i2goSignals/pkg/services"
)

// withDefaultKeyAlg rebuilds the suite's application with I2SIG_KEY_ALG=alg
// ("" unsets it to the built-in ES256 default).
func (s *KeyAlgHandlerSuite) withDefaultKeyAlg(alg string) {
	s.T().Setenv(services.KeyAlgEnvVar, alg)
	s.T().Setenv("I2SIG_STORE_MEM_DIRECTORY", s.T().TempDir())
	persistence, err := dbProviders.OpenPersistence("memorydb:", "keyalg-default-test")
	s.Require().NoError(err)
	s.Require().NoError(persistence.KeyService.InitializeTokenKey(context.Background(), "DEFAULT"))
	s.app = newTestApplication(persistence)
	s.app.DefIssuer = "DEFAULT"
}

// pemHeaders is the header map of the response body's first PEM block.
func (s *KeyAlgHandlerSuite) pemHeaders(rr *httptest.ResponseRecorder) map[string]string {
	block, _ := pem.Decode(rr.Body.Bytes())
	s.Require().NotNil(block, rr.Body.String())
	return block.Headers
}

func (s *KeyAlgHandlerSuite) newestKidOf(keyName, alg string) string {
	_, kid, err := s.app.KeyService.GetSigner(context.Background(), keyName, alg)
	s.Require().NoError(err)
	return kid
}

func (s *KeyAlgHandlerSuite) TestNoAlgCreatesTheDefaultKeyTypeES256() {
	s.withDefaultKeyAlg("")
	rr := s.post("https://default-alg.example", s.adminToken(), "", nil, "")
	s.Require().Equal(http.StatusCreated, rr.Code, rr.Body.String())
	s.IsType(&ecdsa.PrivateKey{}, s.privateKeyFrom(rr))
	keys := s.jwks("https://default-alg.example")
	s.Len(keys["EC"], 1)
	s.Empty(keys["RSA"])

	// An explicit alg overrides the default.
	rr = s.post("https://explicit-alg.example", s.adminToken(), "alg=RS256", nil, "")
	s.Require().Equal(http.StatusCreated, rr.Code, rr.Body.String())
	s.IsType(&rsa.PrivateKey{}, s.privateKeyFrom(rr))
}

func (s *KeyAlgHandlerSuite) TestCreateAndReplaceCarryKeyIdAndNoPEMHeaders() {
	s.withDefaultKeyAlg("")
	admin := s.adminToken()

	rr := s.post(keyAlgIssuer, admin, "", nil, "")
	s.Require().Equal(http.StatusCreated, rr.Code, rr.Body.String())
	created := rr.Header().Get("Key-Id")
	s.Equal(s.newestKidOf(keyAlgIssuer, "ES256"), created)
	s.Empty(s.pemHeaders(rr), "the create body carries no PEM header (i2scim reads it raw)")

	rr = s.post(keyAlgIssuer, admin, "force=replace", nil, "")
	s.Require().Equal(http.StatusCreated, rr.Code, rr.Body.String())
	replaced := rr.Header().Get("Key-Id")
	s.NotEmpty(replaced)
	s.NotEqual(created, replaced)
	s.Equal(s.newestKidOf(keyAlgIssuer, "ES256"), replaced)
	s.Empty(s.pemHeaders(rr))

	// An RSA create names its kid too: the key name, as RSA kids always are.
	rr = s.post(keyAlgIssuer, admin, "alg=RS256", nil, "")
	s.Require().Equal(http.StatusCreated, rr.Code, rr.Body.String())
	s.Equal(keyAlgIssuer, rr.Header().Get("Key-Id"))
}

func (s *KeyAlgHandlerSuite) TestRotateCarriesKeyIdOfTheNewKey() {
	s.withDefaultKeyAlg("")
	admin := s.adminToken()
	s.Require().Equal(http.StatusCreated, s.post(keyAlgIssuer, admin, "", nil, "").Code)
	before := s.newestKidOf(keyAlgIssuer, "ES256")

	rr := s.post(keyAlgIssuer, admin, "force=rotate", nil, "")
	s.Require().Equal(http.StatusOK, rr.Code, rr.Body.String())
	rotated := rr.Header().Get("Key-Id")
	s.NotEqual(before, rotated)
	s.Equal(s.newestKidOf(keyAlgIssuer, "ES256"), rotated, "a no-alg rotate rotates the default type")
	s.Equal(rotated, s.pemHeaders(rr)["kid"], "the rotate body keeps its kid PEM header")
}
