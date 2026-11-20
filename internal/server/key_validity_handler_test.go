package server

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
)

// Issue #318: a signing key loaded with its certificate takes the certificate's
// validity period; a generated or cert-less private key takes its creation time
// plus a lifetime (the lifetime query parameter, else the global default).

// keyStates returns keyName's per-kid states from the key listing.
func (s *KeyAlgHandlerSuite) keyStates(keyName string) []interfaces.KeyState {
	sums, err := s.app.KeyService.ListSummaries(context.Background())
	s.Require().NoError(err)
	var out []interfaces.KeyState
	for _, sum := range sums {
		if sum.KeyName == keyName {
			out = append(out, sum.KeyStates...)
		}
	}
	return out
}

// certFor issues a certificate for pub valid from nb to na, signed by a
// throwaway RSA CA (so any key type can be certified).
func certFor(t *testing.T, pub crypto.PublicKey, nb, na time.Time) []byte {
	t.Helper()
	ca, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "key-validity-test"},
		NotBefore:    nb,
		NotAfter:     na,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, ca)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func pkcs8PEM(t *testing.T, key any) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// TestKeyLoadBundleTakesTheCertificatesValidity: a private key plus its
// certificate loads a signing key whose not_before/not_after are the
// certificate's, for each supported algorithm.
func (s *KeyAlgHandlerSuite) TestKeyLoadBundleTakesTheCertificatesValidity() {
	admin := s.adminToken()
	nb := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	na := nb.Add(90 * 24 * time.Hour)

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	s.Require().NoError(err)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	s.Require().NoError(err)
	pqKey, err := mldsa.GenerateKey(mldsa.MLDSA65())
	s.Require().NoError(err)

	for name, key := range map[string]crypto.Signer{"RS256": rsaKey, "ES256": ecKey, "ML-DSA-65": pqKey} {
		issuer := "https://bundle-" + name + ".example"
		body := append(pkcs8PEM(s.T(), key), certFor(s.T(), key.Public(), nb, na)...)
		rr := s.post(issuer, admin, "", body, "application/x-pem-file")
		s.Require().Equal(http.StatusOK, rr.Code, "%s bundle: %s", name, rr.Body.String())

		states := s.keyStates(issuer)
		s.Require().Len(states, 1, name)
		s.Equal(interfaces.KeyStatusActive, states[0].Status, name)
		s.True(nb.Equal(states[0].NotBefore), "%s not_before is the certificate's: %v", name, states[0].NotBefore)
		s.True(na.Equal(states[0].NotAfter), "%s not_after is the certificate's: %v", name, states[0].NotAfter)

		signer, _, err := s.app.KeyService.GetSigner(context.Background(), issuer, name)
		s.Require().NoError(err, name)
		s.True(key.Public().(interface{ Equal(crypto.PublicKey) bool }).Equal(signer.Public()), "%s: the uploaded key signs", name)
	}
}

// TestKeyLoadBundleWithAnExpiredCertificateIsExpired: the key loads, and the
// listing shows it expired; it is never selected for signing.
func (s *KeyAlgHandlerSuite) TestKeyLoadBundleWithAnExpiredCertificateIsExpired() {
	admin := s.adminToken()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	s.Require().NoError(err)
	na := time.Now().Add(-time.Hour)
	body := append(pkcs8PEM(s.T(), key), certFor(s.T(), key.Public(), na.Add(-24*time.Hour), na)...)
	const issuer = "https://expired-bundle.example"

	rr := s.post(issuer, admin, "", body, "application/x-pem-file")
	s.Require().Equal(http.StatusOK, rr.Code, rr.Body.String())

	states := s.keyStates(issuer)
	s.Require().Len(states, 1)
	s.Equal(interfaces.KeyStatusExpired, states[0].Status)
	_, _, err = s.app.KeyService.GetSigner(context.Background(), issuer, "ES256")
	s.ErrorIs(err, interfaces.ErrKeyNotFound)
}

// TestKeyLoadBundleWithAMismatchedCertificateIs400: a certificate for another
// key is refused, and nothing is stored.
func (s *KeyAlgHandlerSuite) TestKeyLoadBundleWithAMismatchedCertificateIs400() {
	admin := s.adminToken()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	s.Require().NoError(err)
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	s.Require().NoError(err)
	body := append(pkcs8PEM(s.T(), key), certFor(s.T(), other.Public(), time.Now().Add(-time.Hour), time.Now().Add(time.Hour))...)
	const issuer = "https://mismatch.example"

	rr := s.post(issuer, admin, "", body, "application/x-pem-file")
	s.Equal(http.StatusBadRequest, rr.Code)
	s.Contains(rr.Body.String(), "does not match")
	s.Empty(s.keyStates(issuer), "nothing is stored")
}

// TestKeyLoadUnsupportedKeyTypeIs400NamingIt: an Ed25519 key is refused with
// a 400 naming the type.
func (s *KeyAlgHandlerSuite) TestKeyLoadUnsupportedKeyTypeIs400NamingIt() {
	admin := s.adminToken()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	s.Require().NoError(err)

	rr := s.post("https://ed25519.example", admin, "", pkcs8PEM(s.T(), key), "application/x-pem-file")
	s.Equal(http.StatusBadRequest, rr.Code)
	s.Contains(rr.Body.String(), "Ed25519")
}

// TestKeyLoadCertlessPrivateKeyTakesALifetime: a private key without a
// certificate is valid from its load for the lifetime query parameter, else the
// global default; "never" means no expiry, and a bad value is a 400.
func (s *KeyAlgHandlerSuite) TestKeyLoadCertlessPrivateKeyTakesALifetime() {
	admin := s.adminToken()
	for _, tc := range []struct {
		query string
		want  time.Duration
	}{
		{"", 180 * 24 * time.Hour},
		{"lifetime=7d", 7 * 24 * time.Hour},
		{"lifetime=never", 0},
	} {
		issuer := "https://certless-" + tc.query + ".example"
		_, body := rsaPrivateKeyPEM(s.T())
		rr := s.post(issuer, admin, tc.query, body, "application/x-pem-file")
		s.Require().Equal(http.StatusOK, rr.Code, "%q: %s", tc.query, rr.Body.String())
		states := s.keyStates(issuer)
		s.Require().Len(states, 1)
		if tc.want == 0 {
			s.True(states[0].NotAfter.IsZero(), "%q: no expiry", tc.query)
			continue
		}
		s.WithinDuration(time.Now().Add(tc.want), states[0].NotAfter, time.Minute, "%q: valid from the load for the lifetime", tc.query)
	}

	_, body := rsaPrivateKeyPEM(s.T())
	rr := s.post("https://certless-bad.example", admin, "lifetime=soon", body, "application/x-pem-file")
	s.Equal(http.StatusBadRequest, rr.Code)
	s.Empty(s.keyStates("https://certless-bad.example"))
}

// TestKeyCreateAndRotateTakeALifetime: the create and rotate endpoints take
// the lifetime query parameter too.
func (s *KeyAlgHandlerSuite) TestKeyCreateAndRotateTakeALifetime() {
	admin := s.adminToken()
	const issuer = "https://lifetime-create.example"

	rr := s.post(issuer, admin, "alg=ES256&lifetime=10d", nil, "")
	s.Require().Equal(http.StatusCreated, rr.Code, rr.Body.String())
	states := s.keyStates(issuer)
	s.Require().Len(states, 1)
	s.WithinDuration(time.Now().Add(10*24*time.Hour), states[0].NotAfter, time.Minute)
	created := states[0].Kid

	rr = s.post(issuer, admin, "alg=ES256&force=rotate&lifetime=2d", nil, "")
	s.Require().Equal(http.StatusOK, rr.Code, rr.Body.String())
	states = s.keyStates(issuer)
	s.Require().Len(states, 2)
	for _, st := range states {
		if st.Kid != created {
			s.WithinDuration(time.Now().Add(2*24*time.Hour), st.NotAfter, time.Minute, "the rotated key has the requested lifetime")
		}
	}

	s.Equal(http.StatusBadRequest, s.post(issuer, admin, "alg=ES256&force=rotate&lifetime=-1d", nil, "").Code)
	s.Equal(http.StatusBadRequest, s.post("https://lifetime-bad.example", admin, "lifetime=x", nil, "").Code)
}

// TestKeyLoadJwksUriFetchFailureIs400 pins the missing return after the 400:
// a jwks_uri that cannot be fetched is a 400 and stores nothing (it used to fall
// through and dereference the nil JWKS).
func (s *KeyAlgHandlerSuite) TestKeyLoadJwksUriFetchFailureIs400() {
	admin := s.adminToken()
	dead := httptest.NewServer(http.NotFoundHandler())
	s.T().Cleanup(dead.Close)
	const issuer = "https://jwks-uri-fail.example"

	body := []byte(`{"jwks_uri":"` + dead.URL + `/jwks.json"}`)
	rr := s.post(issuer, admin, "", body, "application/json")
	s.Equal(http.StatusBadRequest, rr.Code, rr.Body.String())
	s.Empty(s.keyStates(issuer))
}

// TestKeyLoadCertificateOnlyAcceptsEveryVerificationKeyType: a certificate
// uploaded without its private key registers its public key for verification,
// whether RSA, EC P-256 or ML-DSA-65, as PEM or as application/pkix-cert DER.
// The key is published in the issuer's JWKS and never signs.
func (s *KeyAlgHandlerSuite) TestKeyLoadCertificateOnlyAcceptsEveryVerificationKeyType() {
	admin := s.adminToken()
	nb := time.Now().Add(-time.Hour)
	na := nb.Add(24 * time.Hour)

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	s.Require().NoError(err)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	s.Require().NoError(err)
	pqKey, err := mldsa.GenerateKey(mldsa.MLDSA65())
	s.Require().NoError(err)

	cases := map[string]struct {
		key crypto.Signer
		kty string
	}{
		"RS256":     {rsaKey, `"kty":"RSA"`},
		"ES256":     {ecKey, `"kty":"EC"`},
		"ML-DSA-65": {pqKey, `"kty":"AKP"`},
	}
	for name, c := range cases {
		certPEM := certFor(s.T(), c.key.Public(), nb, na)
		block, _ := pem.Decode(certPEM)
		for contentType, body := range map[string][]byte{"application/x-pem-file": certPEM, "application/pkix-cert": block.Bytes} {
			issuer := "https://cert-only-" + name + "-" + contentType[len("application/"):] + ".example"
			rr := s.post(issuer, admin, "", body, contentType)
			s.Require().Equal(http.StatusOK, rr.Code, "%s %s: %s", name, contentType, rr.Body.String())

			s.Len(s.keyStates(issuer), 1, "%s %s", name, contentType)
			jwks := s.app.KeyService.GetPublicJWKS(context.Background(), issuer)
			s.Require().NotNil(jwks, "%s %s", name, contentType)
			s.Contains(string(*jwks), c.kty, "%s %s: published for verification", name, contentType)
			_, _, err := s.app.KeyService.GetSigner(context.Background(), issuer, name)
			s.ErrorIs(err, interfaces.ErrKeyNotFound, "%s %s: verification only", name, contentType)
		}
	}
}

// TestKeyLoadCertificateOnlyUnsupportedKeyTypeIs400NamingIt: a certificate for
// an Ed25519 key, uploaded without its private key, is refused with a 400 naming
// the type, and nothing is stored.
func (s *KeyAlgHandlerSuite) TestKeyLoadCertificateOnlyUnsupportedKeyTypeIs400NamingIt() {
	admin := s.adminToken()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	s.Require().NoError(err)
	certPEM := certFor(s.T(), pub, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	block, _ := pem.Decode(certPEM)

	for contentType, body := range map[string][]byte{"application/x-pem-file": certPEM, "application/pkix-cert": block.Bytes} {
		issuer := "https://cert-only-ed25519-" + contentType[len("application/"):] + ".example"
		rr := s.post(issuer, admin, "", body, contentType)
		s.Equal(http.StatusBadRequest, rr.Code, contentType)
		s.Contains(rr.Body.String(), "Ed25519", contentType)
		s.Empty(s.keyStates(issuer), "%s: nothing is stored", contentType)
	}
}
