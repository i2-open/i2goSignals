// Package mldsa carries this project's RFC 9964 signing method and JWK codec
// for ML-DSA — the FIPS 204 post-quantum signature scheme — so a SET can be
// signed with ML-DSA-65 instead of RSA.
//
// # Why this code is here and not in a dependency
//
// Neither golang-jwt/jwt/v5 nor MicahParks/keyfunc nor MicahParks/jwkset
// understands ML-DSA or the RFC 9964 "AKP" JWK key type; the upstream
// golang-jwt work is open (golang-jwt#508, golang-jwt#519). Everything in this
// package is therefore deliberately shaped to be *deletable*: it plugs into the
// two extension points those libraries already publish — jwt.RegisterSigningMethod
// for the algorithm and keyfunc.NewGivenCustom for the key — so when upstream
// ships, the swap is an import change at the seam and not a rewrite of the
// signing or verification paths. See docs/adr/0034-ml-dsa-set-signing.md.
//
// The signature is the thing to size before adopting this: an ML-DSA-65
// signature is 3309 bytes against RSA-2048's 256, so every SET grows by roughly
// 3.3 KB of base64 on the wire. That is why ML-DSA is a per-stream opt-in
// (StreamConfiguration.signing_alg) rather than a server-wide default.
package mldsa

import (
	"crypto"
	cryptomldsa "crypto/mldsa"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// Alg is the RFC 9964 JWS "alg" value for ML-DSA-65, the parameter set this
// project signs with. ML-DSA-65 (FIPS 204 Category 3, ~AES-192) is chosen over
// ML-DSA-44 for margin and over ML-DSA-87 for signature size; see ADR 0034.
const Alg = "ML-DSA-65"

// KeyType is the RFC 9964 JWK "kty" value shared by every ML-DSA parameter set.
// "AKP" stands for Algorithm Key Pair: unlike "RSA" or "EC" the key type does
// not name a mathematical structure, so the parameter set lives in "alg" and a
// JWK is only fully identified by the pair (kty, alg).
const KeyType = "AKP"

// Params returns the FIPS 204 parameter set this package signs and verifies
// with. It is a function rather than a var because crypto/mldsa.Parameters is
// produced by a call and is safe for concurrent use.
func Params() cryptomldsa.Parameters { return cryptomldsa.MLDSA65() }

// ErrKeyType is returned when a signing or verification key is not an ML-DSA
// key of the expected parameter set. It is deliberately distinct from
// jwt.ErrInvalidKeyType so a caller can tell "wrong algorithm family" from
// "wrong parameter set".
var ErrKeyType = errors.New("mldsa: key is not an ML-DSA-65 key")

// SigningMethodMLDSA implements jwt.SigningMethod over crypto/mldsa.
//
// ML-DSA is not a hash-then-sign scheme: FIPS 204 signs the message itself
// (the scheme does its own internal hashing, domain-separated by a context
// string). That is why Alg carries no digest suffix the way RS256 does, why
// there is no crypto.Hash to configure here, and why Sign passes the JWS
// signing input through verbatim.
type SigningMethodMLDSA struct {
	alg    string
	params cryptomldsa.Parameters
}

// SigningMethodMLDSA65 is the ML-DSA-65 signing method. It is typed as
// jwt.SigningMethod so callers cannot depend on the concrete type surviving the
// eventual swap to an upstream implementation.
var SigningMethodMLDSA65 jwt.SigningMethod = &SigningMethodMLDSA{
	alg:    Alg,
	params: cryptomldsa.MLDSA65(),
}

func init() {
	// Registration is what lets jwt.Parse resolve "ML-DSA-65" from a token
	// header, and therefore what makes goSet.AllowedAlgs's entry effective.
	jwt.RegisterSigningMethod(Alg, func() jwt.SigningMethod { return SigningMethodMLDSA65 })
}

// Alg returns the JWS "alg" header value this method produces and accepts.
func (m *SigningMethodMLDSA) Alg() string { return m.alg }

// Sign produces the ML-DSA signature over the JWS signing input.
//
// key may be any crypto.Signer holding an ML-DSA key of this method's
// parameter set — in practice a *crypto/mldsa.PrivateKey. Taking the interface
// rather than the concrete type keeps this compatible with goSet.JWS, whose
// key parameter is a crypto.Signer so the algorithm choice lives with the
// caller's signing method (see #277).
//
// The signature is randomized (the FIPS 204 default) rather than deterministic:
// a randomized signature is the conservative choice against fault attacks, and
// nothing in this project needs two signings of the same SET to be byte-equal.
func (m *SigningMethodMLDSA) Sign(signingString string, key any) ([]byte, error) {
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("%w: %w: got %T, want a crypto.Signer", jwt.ErrInvalidKeyType, ErrKeyType, key)
	}
	if err := m.checkPublic(signer.Public()); err != nil {
		return nil, fmt.Errorf("%w: %w", jwt.ErrInvalidKeyType, err)
	}
	// A nil io.Reader is documented as "use crypto/rand"; rand.Reader is passed
	// explicitly so the randomness source is visible at the call site.
	// &Options{} (empty Context) selects plain FIPS 204 ML-DSA.Sign — the
	// context string must match on verify, and RFC 9964 fixes it to empty.
	sig, err := signer.Sign(rand.Reader, []byte(signingString), &cryptomldsa.Options{})
	if err != nil {
		return nil, fmt.Errorf("mldsa: sign: %w", err)
	}
	return sig, nil
}

// Verify checks an ML-DSA signature over the JWS signing input.
//
// key is the public half: a *crypto/mldsa.PublicKey, an *AKPKey, or any
// crypto.Signer whose public half is one (so a verifier holding the private
// key still works). A signature of the wrong length for the parameter set is
// rejected before the verify so a malformed token cannot reach the primitive.
func (m *SigningMethodMLDSA) Verify(signingString string, sig []byte, key any) error {
	pub, err := m.publicKey(key)
	if err != nil {
		return fmt.Errorf("%w: %w", jwt.ErrInvalidKeyType, err)
	}
	if len(sig) != m.params.SignatureSize() {
		return fmt.Errorf("%w: signature is %d bytes, want %d for %s",
			jwt.ErrSignatureInvalid, len(sig), m.params.SignatureSize(), m.alg)
	}
	if err := cryptomldsa.Verify(pub, []byte(signingString), sig, &cryptomldsa.Options{}); err != nil {
		return jwt.ErrSignatureInvalid
	}
	return nil
}

// publicKey narrows the several shapes a verification key arrives in to the one
// crypto/mldsa type, rejecting anything of the wrong parameter set.
func (m *SigningMethodMLDSA) publicKey(key any) (*cryptomldsa.PublicKey, error) {
	switch k := key.(type) {
	case *cryptomldsa.PublicKey:
		return k, m.checkPublic(k)
	case *AKPKey:
		pub, err := k.PublicKey()
		if err != nil {
			return nil, err
		}
		return pub, m.checkPublic(pub)
	case crypto.Signer:
		pub, ok := k.Public().(*cryptomldsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("%w: got %T", ErrKeyType, k.Public())
		}
		return pub, m.checkPublic(pub)
	default:
		return nil, fmt.Errorf("%w: got %T", ErrKeyType, key)
	}
}

// checkPublic rejects an ML-DSA key of a different parameter set. Without it a
// token could be verified against an ML-DSA-44 or -87 key while its header
// claims ML-DSA-65 — the parameter set is part of the algorithm identity, not
// a detail of the key.
func (m *SigningMethodMLDSA) checkPublic(pub crypto.PublicKey) error {
	mlPub, ok := pub.(*cryptomldsa.PublicKey)
	if !ok {
		return fmt.Errorf("%w: got %T", ErrKeyType, pub)
	}
	if mlPub.Parameters() != m.params {
		return fmt.Errorf("%w: key is %s, want %s", ErrKeyType, mlPub.Parameters(), m.params)
	}
	return nil
}

// GenerateKey mints a fresh ML-DSA-65 key pair.
func GenerateKey() (*cryptomldsa.PrivateKey, error) {
	return cryptomldsa.GenerateKey(Params())
}
