package goSetSstp_test

// Focused unit tests for VerifySETX5C (ADR-0064). The verifier is promoted
// verbatim in semantics from enterprise internal/controlset/verify_x5c.go
// but the payload is a SET (goSet.SecurityEventToken), not the enterprise
// Envelope. These tests pin every classification the pkg's four sentinels
// distinguish so a regression is easy to spot.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/url"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/i2-open/i2goSignals/pkg/goSetSstp"
)

const (
	x5cIssuerURN = "urn:i2sig:tenant:t:server:s"
	x5cAudience  = "urn:i2sig:tenant:t:admin:a:instance:i"
)

// TestX5C_HappyPath — a chain that validates to the CA + a leaf URI-SAN
// URN that matches iss verifies cleanly.
func TestX5C_HappyPath(t *testing.T) {
	fx := newX5CFixture(t)
	tok := fx.signSET(t, x5cIssuerURN, []string{x5cAudience}, fx.leafChain, fx.leafKey)
	got, err := goSetSstp.VerifySETX5C(tok, goSetSstp.X5CConfig{Roots: fx.roots, ExpectedAudiences: []string{x5cAudience}})
	if err != nil {
		t.Fatalf("VerifySETX5C: %v", err)
	}
	if got.Issuer != x5cIssuerURN {
		t.Errorf("Issuer = %q, want %q", got.Issuer, x5cIssuerURN)
	}
	if got.Token == nil || got.Raw == "" {
		t.Errorf("VerifiedSET missing Token or Raw: %+v", got)
	}
}

// TestX5C_ForeignCARejected — a chain that does not validate to any root
// is ErrUnknownKey.
func TestX5C_ForeignCARejected(t *testing.T) {
	fx := newX5CFixture(t)
	rogueCA := newX5CCA(t, "rogue")
	rogueChain := rogueCA.leaf(t, fx.leafKey.Public(), x5cIssuerURN)
	tok := fx.signSET(t, x5cIssuerURN, []string{x5cAudience}, rogueChain, fx.leafKey)
	_, err := goSetSstp.VerifySETX5C(tok, goSetSstp.X5CConfig{Roots: fx.roots, ExpectedAudiences: []string{x5cAudience}})
	if !errors.Is(err, goSetSstp.ErrUnknownKey) {
		t.Errorf("VerifySETX5C foreign-CA = %v, want ErrUnknownKey", err)
	}
}

// TestX5C_URISANMismatch — SET iss != leaf URI-SAN URN ⇒
// ErrIssuerCertMismatch (ADR-0064 D1).
func TestX5C_URISANMismatch(t *testing.T) {
	fx := newX5CFixture(t)
	// SET iss is a URN the leaf does NOT vouch for.
	tok := fx.signSET(t, "urn:i2sig:tenant:t:server:LIAR", []string{x5cAudience}, fx.leafChain, fx.leafKey)
	_, err := goSetSstp.VerifySETX5C(tok, goSetSstp.X5CConfig{Roots: fx.roots, ExpectedAudiences: []string{x5cAudience}})
	if !errors.Is(err, goSetSstp.ErrIssuerCertMismatch) {
		t.Errorf("VerifySETX5C URI-SAN mismatch = %v, want ErrIssuerCertMismatch", err)
	}
}

// TestX5C_ExpiredLeafRejected — a leaf outside its NotBefore/NotAfter
// window is ErrUnknownKey (the chain does not validate at time.Now).
func TestX5C_ExpiredLeafRejected(t *testing.T) {
	fx := newX5CFixture(t)
	expiredChain := fx.ca.leafInWindow(t, fx.leafKey.Public(), x5cIssuerURN, time.Now().Add(-time.Hour), time.Now().Add(-5*time.Minute))
	tok := fx.signSET(t, x5cIssuerURN, []string{x5cAudience}, expiredChain, fx.leafKey)
	_, err := goSetSstp.VerifySETX5C(tok, goSetSstp.X5CConfig{Roots: fx.roots, ExpectedAudiences: []string{x5cAudience}})
	if !errors.Is(err, goSetSstp.ErrUnknownKey) {
		t.Errorf("VerifySETX5C expired-leaf = %v, want ErrUnknownKey", err)
	}
}

// TestX5C_EmptyExpectedAudiencesIsError — the promoted-verifier semantics:
// empty ExpectedAudiences would accept any aud, which is a
// misconfiguration ⇒ ErrWrongAudience.
func TestX5C_EmptyExpectedAudiencesIsError(t *testing.T) {
	fx := newX5CFixture(t)
	tok := fx.signSET(t, x5cIssuerURN, []string{x5cAudience}, fx.leafChain, fx.leafKey)
	_, err := goSetSstp.VerifySETX5C(tok, goSetSstp.X5CConfig{Roots: fx.roots})
	if !errors.Is(err, goSetSstp.ErrWrongAudience) {
		t.Errorf("VerifySETX5C empty ExpectedAudiences = %v, want ErrWrongAudience", err)
	}
}

// TestX5C_WrongAudience — a well-formed cert-chain but the SET's aud is
// not in the accepted set ⇒ ErrWrongAudience.
func TestX5C_WrongAudience(t *testing.T) {
	fx := newX5CFixture(t)
	tok := fx.signSET(t, x5cIssuerURN, []string{"urn:some:other"}, fx.leafChain, fx.leafKey)
	_, err := goSetSstp.VerifySETX5C(tok, goSetSstp.X5CConfig{Roots: fx.roots, ExpectedAudiences: []string{x5cAudience}})
	if !errors.Is(err, goSetSstp.ErrWrongAudience) {
		t.Errorf("VerifySETX5C wrong-aud = %v, want ErrWrongAudience", err)
	}
}

// TestX5C_NilRoots — Roots nil is a hard misconfiguration ⇒ ErrUnknownKey.
func TestX5C_NilRoots(t *testing.T) {
	fx := newX5CFixture(t)
	tok := fx.signSET(t, x5cIssuerURN, []string{x5cAudience}, fx.leafChain, fx.leafKey)
	_, err := goSetSstp.VerifySETX5C(tok, goSetSstp.X5CConfig{ExpectedAudiences: []string{x5cAudience}})
	if !errors.Is(err, goSetSstp.ErrUnknownKey) {
		t.Errorf("VerifySETX5C nil-Roots = %v, want ErrUnknownKey", err)
	}
}

// TestX5C_MalformedToken — parse failure ⇒ ErrBadSignature.
func TestX5C_MalformedToken(t *testing.T) {
	fx := newX5CFixture(t)
	_, err := goSetSstp.VerifySETX5C("not.a.jws", goSetSstp.X5CConfig{Roots: fx.roots, ExpectedAudiences: []string{x5cAudience}})
	if !errors.Is(err, goSetSstp.ErrBadSignature) {
		t.Errorf("VerifySETX5C malformed = %v, want ErrBadSignature", err)
	}
}

// ---- fixture --------------------------------------------------------

type x5cFixture struct {
	ca        *x5cCA
	roots     *x509.CertPool
	leafKey   *ecdsa.PrivateKey
	leafChain []*x509.Certificate
}

func newX5CFixture(t *testing.T) *x5cFixture {
	t.Helper()
	ca := newX5CCA(t, "x5c-test-ca")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	chain := ca.leaf(t, key.Public(), x5cIssuerURN)
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	return &x5cFixture{ca: ca, roots: pool, leafKey: key, leafChain: chain}
}

// signSET builds an x5c-signed SET-shaped JWS. Payload fields cover the
// SET claims VerifySETX5C reads (iss, aud, jti, iat).
func (f *x5cFixture) signSET(t *testing.T, iss string, aud []string, chain []*x509.Certificate, key *ecdsa.PrivateKey) string {
	t.Helper()
	// SET payload as a plain claims map (matching goSet.SecurityEventToken
	// on the wire). Marshal-then-sign is what the enterprise Signer does
	// too — the pkg does not export a signer (that stays consumer-owned).
	payload := map[string]any{
		"iss":    iss,
		"aud":    aud,
		"jti":    "jti-1",
		"iat":    time.Now().Unix(),
		"events": map[string]any{"https://example/event/x": map[string]any{}},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	rawCerts := make([]string, len(chain))
	for i, c := range chain {
		rawCerts[i] = certBase64(c)
	}
	opts := (&jose.SignerOptions{}).WithType("secevent+jwt").WithHeader("kid", "kid")
	// Attach the x5c chain to the protected header.
	opts = opts.WithHeader("x5c", rawCerts)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, opts)
	if err != nil {
		t.Fatal(err)
	}
	jws, err := signer.Sign(body)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := jws.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// certBase64 returns the standard base64 (no PEM headers) encoding of a
// cert's DER bytes — the wire encoding of an x5c header element per RFC
// 7515 §4.1.6.
func certBase64(c *x509.Certificate) string {
	return base64.StdEncoding.EncodeToString(c.Raw)
}

type x5cCA struct {
	cert *x509.Certificate
	priv *ecdsa.PrivateKey
}

func newX5CCA(t *testing.T, cn string) *x5cCA {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &x5cCA{cert: cert, priv: priv}
}

var x5cSerial int64 = 1000

func (ca *x5cCA) leaf(t *testing.T, pub any, urn string) []*x509.Certificate {
	return ca.leafInWindow(t, pub, urn, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
}

func (ca *x5cCA) leafInWindow(t *testing.T, pub any, urn string, notBefore, notAfter time.Time) []*x509.Certificate {
	t.Helper()
	u, err := url.Parse(urn)
	if err != nil {
		t.Fatal(err)
	}
	x5cSerial++
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(x5cSerial),
		Subject:      pkix.Name{CommonName: urn},
		URIs:         []*url.URL{u},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, pub, ca.priv)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return []*x509.Certificate{cert, ca.cert}
}
