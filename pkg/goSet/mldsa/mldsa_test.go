package mldsa_test

import (
	cryptomldsa "crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/i2-open/i2goSignals/pkg/goSet/mldsa"
)

// RFC 9964 signing method (i2goSignals#278).
//
// FIPS 204 ships no fixed sign/verify test vectors that a JWS implementation
// could pin the way RFC 7515 appendix vectors pin RS256: ML-DSA signing is
// randomized, so two correct signers disagree byte-for-byte over the same
// message and key. What is pinnable — and what these tests pin — is everything
// around that: the alg name, the sizes FIPS 204 fixes for ML-DSA-65, the
// round-trip through golang-jwt's own Parse, and the rejections. The
// interoperability check that a *fixed* vector would give is instead obtained
// from crypto/mldsa itself, which runs the ACVP and Wycheproof vectors in the
// standard library's own test suite.

func testKey(t *testing.T) *cryptomldsa.PrivateKey {
	t.Helper()
	sk, err := mldsa.GenerateKey()
	require.NoError(t, err)
	return sk
}

func TestSigningMethod_AlgIsTheRFC9964Name(t *testing.T) {
	assert.Equal(t, "ML-DSA-65", mldsa.SigningMethodMLDSA65.Alg())
	assert.Equal(t, "ML-DSA-65", mldsa.Alg)
}

func TestSigningMethod_IsRegisteredWithGolangJWT(t *testing.T) {
	// Registration is what lets jwt.Parse resolve the alg from a token header.
	// Without it a PQ-signed SET fails as "signing method not available" before
	// any key is consulted, and goSet.AllowedAlgs's entry would be inert.
	got := jwt.GetSigningMethod(mldsa.Alg)
	require.NotNil(t, got, "ML-DSA-65 must be registered via jwt.RegisterSigningMethod")
	assert.Equal(t, mldsa.Alg, got.Alg())
}

func TestSignVerify_RoundTrips(t *testing.T) {
	sk := testKey(t)
	const signingInput = "eyJhbGciOiJNTC1EU0EtNjUifQ.eyJqdGkiOiJyb3VuZC10cmlwIn0"

	sig, err := mldsa.SigningMethodMLDSA65.Sign(signingInput, sk)
	require.NoError(t, err)
	assert.Len(t, sig, cryptomldsa.MLDSA65SignatureSize,
		"FIPS 204 fixes the ML-DSA-65 signature at 3309 bytes; the ~3.3 KB per SET is why signing_alg is a per-stream opt-in")

	assert.NoError(t, mldsa.SigningMethodMLDSA65.Verify(signingInput, sig, sk.PublicKey()))
}

func TestSign_IsRandomizedSoTwoSignaturesDiffer(t *testing.T) {
	sk := testKey(t)
	first, err := mldsa.SigningMethodMLDSA65.Sign("payload", sk)
	require.NoError(t, err)
	second, err := mldsa.SigningMethodMLDSA65.Sign("payload", sk)
	require.NoError(t, err)

	// FIPS 204's default is a randomized ("hedged") signature. Both verify;
	// neither is a function of the message alone, which is the conservative
	// choice against fault attacks.
	assert.NotEqual(t, first, second)
	assert.NoError(t, mldsa.SigningMethodMLDSA65.Verify("payload", first, sk.PublicKey()))
	assert.NoError(t, mldsa.SigningMethodMLDSA65.Verify("payload", second, sk.PublicKey()))
}

func TestVerify_RejectsATamperedPayload(t *testing.T) {
	sk := testKey(t)
	sig, err := mldsa.SigningMethodMLDSA65.Sign("the-real-payload", sk)
	require.NoError(t, err)

	err = mldsa.SigningMethodMLDSA65.Verify("the-fake-payload", sig, sk.PublicKey())
	assert.ErrorIs(t, err, jwt.ErrSignatureInvalid)
}

func TestVerify_RejectsATamperedSignature(t *testing.T) {
	sk := testKey(t)
	sig, err := mldsa.SigningMethodMLDSA65.Sign("payload", sk)
	require.NoError(t, err)
	sig[0] ^= 0xff

	assert.ErrorIs(t, mldsa.SigningMethodMLDSA65.Verify("payload", sig, sk.PublicKey()), jwt.ErrSignatureInvalid)
}

func TestVerify_RejectsAWrongLengthSignatureBeforeThePrimitive(t *testing.T) {
	sk := testKey(t)
	err := mldsa.SigningMethodMLDSA65.Verify("payload", []byte{1, 2, 3}, sk.PublicKey())
	require.ErrorIs(t, err, jwt.ErrSignatureInvalid)
	assert.Contains(t, err.Error(), "want 3309")
}

func TestSignVerify_RejectAKeyOfAnotherParameterSet(t *testing.T) {
	// The parameter set is part of the algorithm's identity: a header saying
	// ML-DSA-65 must not be satisfiable with an ML-DSA-44 or -87 key.
	for _, params := range []cryptomldsa.Parameters{cryptomldsa.MLDSA44(), cryptomldsa.MLDSA87()} {
		t.Run(params.String(), func(t *testing.T) {
			sk, err := cryptomldsa.GenerateKey(params)
			require.NoError(t, err)

			_, err = mldsa.SigningMethodMLDSA65.Sign("payload", sk)
			require.ErrorIs(t, err, jwt.ErrInvalidKeyType)
			assert.ErrorIs(t, err, mldsa.ErrKeyType)

			err = mldsa.SigningMethodMLDSA65.Verify("payload", make([]byte, cryptomldsa.MLDSA65SignatureSize), sk.PublicKey())
			assert.ErrorIs(t, err, jwt.ErrInvalidKeyType)
		})
	}
}

func TestSignVerify_RejectANonMLDSAKey(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	_, err = mldsa.SigningMethodMLDSA65.Sign("payload", rsaKey)
	assert.ErrorIs(t, err, jwt.ErrInvalidKeyType)

	err = mldsa.SigningMethodMLDSA65.Verify("payload", make([]byte, cryptomldsa.MLDSA65SignatureSize), &rsaKey.PublicKey)
	assert.ErrorIs(t, err, jwt.ErrInvalidKeyType)
}

func TestSign_RejectsAKeyThatIsNotASigner(t *testing.T) {
	_, err := mldsa.SigningMethodMLDSA65.Sign("payload", "a shared secret")
	assert.ErrorIs(t, err, jwt.ErrInvalidKeyType)
}

// TestJWT_RoundTripsThroughGolangJWT is the end-to-end proof that the
// registration, Sign and Verify halves compose into a token golang-jwt itself
// produces and accepts — including the header the parser reads the alg from.
func TestJWT_RoundTripsThroughGolangJWT(t *testing.T) {
	sk := testKey(t)
	token := jwt.NewWithClaims(mldsa.SigningMethodMLDSA65, jwt.MapClaims{"iss": "https://tx.example.com"})
	signed, err := token.SignedString(sk)
	require.NoError(t, err)

	assert.True(t, strings.HasPrefix(signed, "eyJhbGciOiJNTC1EU0EtNjUi"),
		"the JOSE header must announce alg ML-DSA-65")

	parsed, err := jwt.Parse(signed, func(*jwt.Token) (any, error) { return sk.PublicKey(), nil },
		jwt.WithValidMethods([]string{mldsa.Alg}))
	require.NoError(t, err)
	assert.Equal(t, mldsa.Alg, parsed.Header["alg"])
	assert.Equal(t, "https://tx.example.com", parsed.Claims.(jwt.MapClaims)["iss"])
}

// TestJWT_AnRS256HeaderCannotBeVerifiedWithAnMLDSAKey closes the
// algorithm-confusion shape from the other direction: the allow-list pins the
// header, and the method pins the key.
func TestJWT_AnRS256HeaderCannotBeVerifiedWithAnMLDSAKey(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	signed, err := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"iss": "x"}).SignedString(rsaKey)
	require.NoError(t, err)

	sk := testKey(t)
	_, err = jwt.Parse(signed, func(*jwt.Token) (any, error) { return sk.PublicKey(), nil },
		jwt.WithValidMethods([]string{mldsa.Alg}))
	assert.Error(t, err)
}
