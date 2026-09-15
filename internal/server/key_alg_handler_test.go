package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/i2-open/i2goSignals/internal/providers/dbProviders"
	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/suite"
)

// KeyAlgHandlerSuite exercises POST /key/{keyName}?alg= (i2goSignals#314):
// create, rotate and replace each act on one signature algorithm and leave the
// keyName's keys of other algorithms alone. The key scope rules of ADR 0006 are
// unchanged whatever the algorithm.
type KeyAlgHandlerSuite struct {
	suite.Suite
	app *SignalsApplication
}

func TestKeyAlgHandlerSuite(t *testing.T) {
	suite.Run(t, new(KeyAlgHandlerSuite))
}

const keyAlgIssuer = "https://keyalg.example"

func (s *KeyAlgHandlerSuite) SetupTest() {
	// A directory of the test's own: the default config/keyalg-test is shared by
	// every test and every run, and a provider's save loop leaves the keys there.
	s.T().Setenv("I2SIG_STORE_MEM_DIRECTORY", s.T().TempDir())
	persistence, err := dbProviders.OpenPersistence("memorydb:", "keyalg-test")
	s.Require().NoError(err)
	s.Require().NoError(persistence.KeyService.InitializeTokenKey(context.Background(), "DEFAULT"))
	s.app = newTestApplication(persistence)
	s.app.DefIssuer = "DEFAULT"
}

func (s *KeyAlgHandlerSuite) adminToken() string {
	client := model.SsfClient{Id: model.NewRecordId(), ProjectIds: []string{"proj-A"}}
	tok, err := s.app.GetAuth().IssueStreamClientToken(client, "proj-A", true, "")
	s.Require().NoError(err)
	return tok
}

// post issues POST /key/{keyName}?{query} through the CreateKey handler.
func (s *KeyAlgHandlerSuite) post(keyName, bearer, query string, body []byte, contentType string) *httptest.ResponseRecorder {
	target := "/key/" + keyName
	if query != "" {
		target += "?" + query
	}
	r := httptest.NewRequest(http.MethodPost, target, bytes.NewReader(body))
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	r = mux.SetURLVars(r, map[string]string{"keyName": keyName})
	rr := httptest.NewRecorder()
	s.app.CreateKey(rr, r)
	return rr
}

// jwk is the part of a published JWK these tests look at.
type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	N   string `json:"n"`
}

// jwks returns keyName's published JWKS grouped by key type: RSA (RS256), EC
// (ES256) and AKP (ML-DSA-65).
func (s *KeyAlgHandlerSuite) jwks(keyName string) map[string][]jwk {
	raw := s.app.KeyService.GetPublicJWKS(context.Background(), keyName)
	s.Require().NotNil(raw)
	var doc struct {
		Keys []jwk `json:"keys"`
	}
	s.Require().NoError(json.Unmarshal(*raw, &doc))
	out := map[string][]jwk{}
	for _, k := range doc.Keys {
		out[k.Kty] = append(out[k.Kty], k)
	}
	return out
}

func kidsOf(keys []jwk) []string {
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, k.Kid)
	}
	return out
}

// privateKeyFrom parses the PKCS#8 PEM a create or rotate returns.
func (s *KeyAlgHandlerSuite) privateKeyFrom(rr *httptest.ResponseRecorder) any {
	block, _ := pem.Decode(rr.Body.Bytes())
	s.Require().NotNil(block, "response must carry a PEM: %s", rr.Body.String())
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	s.Require().NoError(err)
	return key
}

// seed creates keyName's RS256, ES256 and ML-DSA-65 keys through the endpoint.
func (s *KeyAlgHandlerSuite) seed(keyName string) {
	admin := s.adminToken()
	for _, q := range []string{"", "alg=ES256", "alg=ML-DSA-65"} {
		rr := s.post(keyName, admin, q, nil, "")
		s.Require().Equal(http.StatusCreated, rr.Code, "seed %q: %s", q, rr.Body.String())
	}
}

func (s *KeyAlgHandlerSuite) keyStatus(keyName, kid string) string {
	summary, err := s.app.KeyService.GetKeySummary(context.Background(), keyName)
	s.Require().NoError(err)
	for _, st := range summary.KeyStates {
		if st.Kid == kid {
			return st.Status
		}
	}
	s.FailNow("kid not found", kid)
	return ""
}

func (s *KeyAlgHandlerSuite) TestCreateWithAlgAddsAKeyAlongsideRS256() {
	admin := s.adminToken()

	rr := s.post(keyAlgIssuer, admin, "", nil, "")
	s.Require().Equal(http.StatusCreated, rr.Code, rr.Body.String())
	s.IsType(&rsa.PrivateKey{}, s.privateKeyFrom(rr))

	rr = s.post(keyAlgIssuer, admin, "alg=ES256", nil, "")
	s.Require().Equal(http.StatusCreated, rr.Code, rr.Body.String())
	s.IsType(&ecdsa.PrivateKey{}, s.privateKeyFrom(rr))

	rr = s.post(keyAlgIssuer, admin, "alg=ML-DSA-65", nil, "")
	s.Require().Equal(http.StatusCreated, rr.Code, rr.Body.String())
	s.IsType(&mldsa.PrivateKey{}, s.privateKeyFrom(rr))

	keys := s.jwks(keyAlgIssuer)
	s.Equal([]string{keyAlgIssuer}, kidsOf(keys["RSA"]), "the RS256 key is untouched")
	s.Len(keys["EC"], 1, "the ES256 key is published")
	s.Len(keys["AKP"], 1, "the ML-DSA-65 key is published")
}

func (s *KeyAlgHandlerSuite) TestUnsupportedAlgIs400() {
	admin := s.adminToken()
	s.Require().Equal(http.StatusCreated, s.post(keyAlgIssuer, admin, "", nil, "").Code)

	for _, q := range []string{"alg=HS256", "alg=es256", "alg=RSA", "alg=HS256&force=rotate", "alg=HS256&rotate", "alg=HS256&force=replace"} {
		rr := s.post(keyAlgIssuer, admin, q, nil, "")
		s.Equal(http.StatusBadRequest, rr.Code, "%q: %s", q, rr.Body.String())
	}
	keys := s.jwks(keyAlgIssuer)
	s.Equal([]string{keyAlgIssuer}, kidsOf(keys["RSA"]), "a rejected request changes nothing")
	s.Empty(keys["EC"])
	s.Empty(keys["AKP"])

	rr := s.post("https://brand-new.example", admin, "alg=HS256", nil, "")
	s.Equal(http.StatusBadRequest, rr.Code)
	names, err := s.app.KeyService.ListKeyNames(context.Background())
	s.Require().NoError(err)
	s.NotContains(names, "https://brand-new.example")
}

func (s *KeyAlgHandlerSuite) TestNoAlgOnANewKeyNameCreatesRS256AsToday() {
	admin := s.adminToken()
	for _, name := range []string{"https://no-alg.example", "https://explicit-rs256.example"} {
		q := ""
		if name == "https://explicit-rs256.example" {
			q = "alg=RS256"
		}
		rr := s.post(name, admin, q, nil, "")
		s.Require().Equal(http.StatusCreated, rr.Code, rr.Body.String())
		s.IsType(&rsa.PrivateKey{}, s.privateKeyFrom(rr))
		keys := s.jwks(name)
		s.Equal([]string{name}, kidsOf(keys["RSA"]), "the kid is the key name, as today")
		s.Empty(keys["EC"])
		s.Empty(keys["AKP"])
	}
}

func (s *KeyAlgHandlerSuite) TestCreateConflictIsPerAlgorithm() {
	ctx := context.Background()
	admin := s.adminToken()
	s.Require().Equal(http.StatusCreated, s.post(keyAlgIssuer, admin, "", nil, "").Code)

	s.Equal(http.StatusCreated, s.post(keyAlgIssuer, admin, "alg=ES256", nil, "").Code,
		"an RS256 key does not block an ES256 key")
	s.Equal(http.StatusConflict, s.post(keyAlgIssuer, admin, "alg=ES256", nil, "").Code)
	s.Equal(http.StatusConflict, s.post(keyAlgIssuer, admin, "", nil, "").Code)
	s.Equal(http.StatusConflict, s.post(keyAlgIssuer, admin, "alg=RS256", nil, "").Code)

	ecKid := s.jwks(keyAlgIssuer)["EC"][0].Kid
	_, _, err := s.app.KeyService.SetKeyStatus(ctx, keyAlgIssuer, ecKid, interfaces.KeyStatusSuspended)
	s.Require().NoError(err)
	s.Equal(http.StatusConflict, s.post(keyAlgIssuer, admin, "alg=ES256", nil, "").Code,
		"a suspended key is not revoked, so it still conflicts")

	_, _, err = s.app.KeyService.SetKeyStatus(ctx, keyAlgIssuer, ecKid, interfaces.KeyStatusRevoked)
	s.Require().NoError(err)
	s.Equal(http.StatusCreated, s.post(keyAlgIssuer, admin, "alg=ES256", nil, "").Code,
		"after a revoke with no replacement a plain create works")
	ec := s.jwks(keyAlgIssuer)["EC"]
	s.Require().Len(ec, 1)
	s.NotEqual(ecKid, ec[0].Kid)

	_, _, err = s.app.KeyService.SetKeyStatus(ctx, keyAlgIssuer, keyAlgIssuer, interfaces.KeyStatusRevoked)
	s.Require().NoError(err)
	s.Equal(http.StatusCreated, s.post(keyAlgIssuer, admin, "", nil, "").Code,
		"the same holds for RS256")
	rsaKeys := s.jwks(keyAlgIssuer)["RSA"]
	s.Require().Len(rsaKeys, 1)
	s.NotEqual(keyAlgIssuer, rsaKeys[0].Kid, "the new RS256 key does not overwrite the revoked record's kid")
	_, signingKid, err := s.app.KeyService.GetSigner(ctx, keyAlgIssuer, "RS256")
	s.Require().NoError(err)
	s.Equal(rsaKeys[0].Kid, signingKid)
}

func (s *KeyAlgHandlerSuite) TestRotateWithAlgAddsAKeyAndKeepsThePreviousActive() {
	for _, tc := range []struct{ alg, kty string }{{"ES256", "EC"}, {"ML-DSA-65", "AKP"}} {
		s.Run(tc.alg, func() {
			s.SetupTest()
			admin := s.adminToken()
			s.seed(keyAlgIssuer)
			before := s.jwks(keyAlgIssuer)
			previous := before[tc.kty][0].Kid

			rr := s.post(keyAlgIssuer, admin, "force=rotate&alg="+tc.alg, nil, "")
			s.Require().Equal(http.StatusOK, rr.Code, rr.Body.String())
			block, _ := pem.Decode(rr.Body.Bytes())
			s.Require().NotNil(block)
			newKid := block.Headers["kid"]
			s.NotEmpty(newKid)

			after := s.jwks(keyAlgIssuer)
			s.ElementsMatch([]string{previous, newKid}, kidsOf(after[tc.kty]), "the previous key stays in the JWKS")
			s.Equal(interfaces.KeyStatusActive, s.keyStatus(keyAlgIssuer, previous), "the previous key stays active")
			for kty, keys := range before {
				if kty != tc.kty {
					s.Equal(keys, after[kty], "%s keys are untouched", kty)
				}
			}

			rr = s.post(keyAlgIssuer, admin, "rotate&alg="+tc.alg, nil, "")
			s.Require().Equal(http.StatusOK, rr.Code, rr.Body.String())
			s.Len(s.jwks(keyAlgIssuer)[tc.kty], 3, "?rotate acts on the algorithm too")
		})
	}
}

func (s *KeyAlgHandlerSuite) TestRotateWithNoAlgRotatesRS256Only() {
	admin := s.adminToken()
	s.seed(keyAlgIssuer)
	before := s.jwks(keyAlgIssuer)

	rr := s.post(keyAlgIssuer, admin, "force=rotate", nil, "")
	s.Require().Equal(http.StatusOK, rr.Code, rr.Body.String())

	after := s.jwks(keyAlgIssuer)
	s.Len(after["RSA"], 2)
	s.Contains(kidsOf(after["RSA"]), keyAlgIssuer)
	s.Equal(before["EC"], after["EC"])
	s.Equal(before["AKP"], after["AKP"])
}

func (s *KeyAlgHandlerSuite) TestReplaceWithAlgLeavesTheOtherAlgorithms() {
	admin := s.adminToken()
	s.seed(keyAlgIssuer)
	before := s.jwks(keyAlgIssuer)

	rr := s.post(keyAlgIssuer, admin, "force=replace&alg=ES256", nil, "")
	s.Require().Equal(http.StatusCreated, rr.Code, rr.Body.String())
	s.IsType(&ecdsa.PrivateKey{}, s.privateKeyFrom(rr))

	after := s.jwks(keyAlgIssuer)
	s.Equal(before["RSA"], after["RSA"], "the RS256 key is left in place")
	s.Equal(before["AKP"], after["AKP"], "the ML-DSA-65 key is left in place")
	s.Require().Len(after["EC"], 1, "the ES256 key is replaced, not added to")
	s.NotEqual(before["EC"][0].Kid, after["EC"][0].Kid)
}

func (s *KeyAlgHandlerSuite) TestPlainReplaceLeavesES256AndMLDSAKeys() {
	admin := s.adminToken()
	s.seed(keyAlgIssuer)
	before := s.jwks(keyAlgIssuer)

	rr := s.post(keyAlgIssuer, admin, "force=replace", nil, "")
	s.Require().Equal(http.StatusCreated, rr.Code, rr.Body.String())

	after := s.jwks(keyAlgIssuer)
	s.Equal(before["EC"], after["EC"], "a plain replace no longer deletes the ES256 key")
	s.Equal(before["AKP"], after["AKP"], "a plain replace no longer deletes the ML-DSA-65 key")
	s.Require().Len(after["RSA"], 1)
	s.Equal(keyAlgIssuer, after["RSA"][0].Kid)
	s.NotEqual(before["RSA"][0].N, after["RSA"][0].N, "the RS256 key material is new")
}

func (s *KeyAlgHandlerSuite) TestKeyLoadReplaceLeavesNonRSAKeys() {
	admin := s.adminToken()
	s.seed(keyAlgIssuer)
	before := s.jwks(keyAlgIssuer)

	uploaded, pemBody := rsaPrivateKeyPEM(s.T())
	rr := s.post(keyAlgIssuer, admin, "force=replace", pemBody, "application/x-pem-file")
	s.Require().Equal(http.StatusOK, rr.Code, rr.Body.String())

	after := s.jwks(keyAlgIssuer)
	s.Equal(before["EC"], after["EC"], "a key load replace leaves the ES256 key")
	s.Equal(before["AKP"], after["AKP"], "a key load replace leaves the ML-DSA-65 key")
	s.Require().Len(after["RSA"], 1)
	s.Equal(base64.RawURLEncoding.EncodeToString(uploaded.N.Bytes()), after["RSA"][0].N, "the uploaded RSA key replaced the old one")
}

func (s *KeyAlgHandlerSuite) TestKeyLoadConflictUsesTheUploadedKeysAlgorithm() {
	admin := s.adminToken()
	s.Require().Equal(http.StatusCreated, s.post(keyAlgIssuer, admin, "alg=ES256", nil, "").Code)

	_, pemBody := rsaPrivateKeyPEM(s.T())
	rr := s.post(keyAlgIssuer, admin, "", pemBody, "application/x-pem-file")
	s.Equal(http.StatusOK, rr.Code, "an ES256 key does not block loading an RSA key: %s", rr.Body.String())

	_, pemBody = rsaPrivateKeyPEM(s.T())
	rr = s.post(keyAlgIssuer, admin, "", pemBody, "application/x-pem-file")
	s.Equal(http.StatusConflict, rr.Code, "an RSA key blocks loading another without force")
}

// TestKeyScopeCreatesAnyAlgButNeverRotatesOrReplaces pins ADR 0006 across the
// algorithms: a key-scoped (bootstrap) caller may create a key of any
// algorithm, and gets 403 for rotate or replace whatever the algorithm.
func (s *KeyAlgHandlerSuite) TestKeyScopeCreatesAnyAlgButNeverRotatesOrReplaces() {
	s.T().Setenv("I2SIG_BOOTSTRAP_TOKEN", "s3cret-bootstrap")
	const boot = "s3cret-bootstrap"

	for _, alg := range []string{"", "RS256", "ES256", "ML-DSA-65"} {
		q := ""
		if alg != "" {
			q = "alg=" + alg
		}
		rr := s.post(keyAlgIssuer, boot, q, nil, "")
		if alg == "RS256" {
			s.Equal(http.StatusConflict, rr.Code, "the no-alg create already made the RS256 key")
		} else {
			s.Equal(http.StatusCreated, rr.Code, "key scope may create alg %q: %s", alg, rr.Body.String())
		}
	}
	before := s.jwks(keyAlgIssuer)

	for _, alg := range []string{"", "RS256", "ES256", "ML-DSA-65", "HS256"} {
		suffix := ""
		if alg != "" {
			suffix = "&alg=" + alg
		}
		for _, takeover := range []string{"force=rotate", "rotate", "force=replace"} {
			rr := s.post(keyAlgIssuer, boot, takeover+suffix, nil, "")
			s.Equal(http.StatusForbidden, rr.Code, "key scope must not %s alg %q", takeover, alg)
		}
	}
	s.Equal(before, s.jwks(keyAlgIssuer), "a refused takeover changes nothing")
}

// TestNonRSAKeysOnTheTokenIssuerKeepAuthWorking: auth tokens are signed RS256,
// so creating or rotating an ES256 or ML-DSA-65 key under the token issuer's
// name must not swap the auth signing key.
func (s *KeyAlgHandlerSuite) TestNonRSAKeysOnTheTokenIssuerKeepAuthWorking() {
	admin := s.adminToken()
	s.Require().Equal(http.StatusCreated, s.post("DEFAULT", admin, "alg=ES256", nil, "").Code)
	s.Require().Equal(http.StatusOK, s.post("DEFAULT", admin, "force=rotate&alg=ES256", nil, "").Code)
	s.Require().Equal(http.StatusCreated, s.post("DEFAULT", admin, "alg=ML-DSA-65", nil, "").Code)

	rr := s.post(keyAlgIssuer, s.adminToken(), "", nil, "")
	s.Equal(http.StatusCreated, rr.Code, "a token issued after the change still authorizes: %s", rr.Body.String())
	rr = s.post("https://second.example", admin, "", nil, "")
	s.Equal(http.StatusCreated, rr.Code, "a token issued before the change still authorizes: %s", rr.Body.String())
}

// TestStreamCreate_SigningAlgNeedsTheOperatorsKey is the operator flow once
// streams stop creating keys: the stream is refused until the key for its
// signing_alg is created through POST /key, and the refusal creates nothing.
func (s *ServerProvisioningAuthzSuite) TestStreamCreate_SigningAlgNeedsTheOperatorsKey() {
	const iss = "http://transmitter.example.com" // holds an RS256 key only
	cfg := model.StreamStateRecord{}
	cfg.Iss = iss
	cfg.Aud = []string{"http://receiver.example.com"}
	cfg.SigningAlg = "ES256"
	cfg.Delivery = &model.OneOfStreamConfigurationDelivery{
		PollTransmitMethod: &model.PollTransmitMethod{Method: model.DeliveryPoll},
	}
	body, _ := json.Marshal(cfg)

	rr := s.do(s.app.StreamCreate, http.MethodPost, "/stream", s.streamToken("proj-A"), body, nil)
	s.Equal(http.StatusBadRequest, rr.Code, rr.Body.String())
	s.Contains(rr.Body.String(), "no active signing key for issuer "+iss+" (ES256)")
	_, _, err := s.app.KeyService.GetSigner(context.Background(), iss, "ES256")
	s.ErrorIs(err, interfaces.ErrKeyNotFound, "a refused stream create leaves no ES256 key behind")

	rr = s.do(s.app.CreateKey, http.MethodPost, "/key/"+iss+"?alg=ES256", s.adminToken("proj-A"), nil, map[string]string{"keyName": iss})
	s.Require().Equal(http.StatusCreated, rr.Code, rr.Body.String())

	rr = s.do(s.app.StreamCreate, http.MethodPost, "/stream", s.streamToken("proj-A"), body, nil)
	s.Equal(http.StatusCreated, rr.Code, rr.Body.String())
}

func rsaPrivateKeyPEM(t *testing.T) (*rsa.PublicKey, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return &key.PublicKey, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}
