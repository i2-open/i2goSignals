package mldsa

import (
	cryptomldsa "crypto/mldsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

// AKPKey is the RFC 9964 JWK form of an ML-DSA key pair (Slice Contract rev 1,
// Seam S3).
//
// RFC 9964 gives every post-quantum signature scheme one JWK key type, "AKP"
// (Algorithm Key Pair), with just two key members: "pub" holds the public key
// encoding and "priv" the private seed, both base64url without padding. Which
// algorithm those bytes belong to is carried in "alg", not in "kty" — so unlike
// an RSA or EC JWK, an AKP JWK is meaningless without its "alg".
//
// The Go field names are fixed by the seam contract; the wire names come from
// the struct tags. []byte fields cannot be tagged into base64url — encoding/json
// renders them as standard base64 with padding — so this type carries its own
// MarshalJSON/UnmarshalJSON rather than relying on tags alone.
//
// A zero Priv is a public-only key: that is the form published in a JWKS, and
// MarshalJSON omits "priv" entirely for it, so an AKPKey round-tripped through
// PublicJWK can never leak private material by accident.
type AKPKey struct {
	Kty  string `json:"kty"`
	Alg  string `json:"alg"`
	Kid  string `json:"kid,omitempty"`
	Pub  []byte `json:"pub"`
	Priv []byte `json:"priv,omitempty"`
}

// ErrNotAKP reports that a JWK is not an RFC 9964 AKP key of this package's
// parameter set. JWKS parsing uses it to skip a key rather than fail the set.
var ErrNotAKP = errors.New("mldsa: not an ML-DSA-65 AKP JWK")

// akpWire is the on-the-wire shape: the byte members as base64url strings.
// Keeping it separate from AKPKey is what lets the seam-mandated []byte fields
// survive while the JSON stays RFC 9964-conformant.
type akpWire struct {
	Kty  string `json:"kty"`
	Alg  string `json:"alg"`
	Kid  string `json:"kid,omitempty"`
	Pub  string `json:"pub"`
	Priv string `json:"priv,omitempty"`
}

// NewAKPKey builds the private JWK form of an ML-DSA private key.
//
// Priv is the 32-byte FIPS 204 seed (crypto/mldsa.PrivateKeySize), not the
// expanded key: that is what RFC 9964's "priv" member is defined to hold, and
// it is what crypto/mldsa.NewPrivateKey reconstructs from.
func NewAKPKey(kid string, sk *cryptomldsa.PrivateKey) (*AKPKey, error) {
	if sk == nil {
		return nil, errors.New("mldsa: nil private key")
	}
	pub := sk.PublicKey()
	if pub.Parameters() != Params() {
		return nil, fmt.Errorf("%w: key is %s, want %s", ErrKeyType, pub.Parameters(), Params())
	}
	return &AKPKey{
		Kty:  KeyType,
		Alg:  Alg,
		Kid:  kid,
		Pub:  pub.Bytes(),
		Priv: sk.Bytes(),
	}, nil
}

// NewAKPPublicKey builds the public-only JWK form of an ML-DSA public key —
// the shape published in a JWKS.
func NewAKPPublicKey(kid string, pk *cryptomldsa.PublicKey) (*AKPKey, error) {
	if pk == nil {
		return nil, errors.New("mldsa: nil public key")
	}
	if pk.Parameters() != Params() {
		return nil, fmt.Errorf("%w: key is %s, want %s", ErrKeyType, pk.Parameters(), Params())
	}
	return &AKPKey{Kty: KeyType, Alg: Alg, Kid: kid, Pub: pk.Bytes()}, nil
}

// PublicJWK returns a copy carrying no private material, for publication.
func (k *AKPKey) PublicJWK() *AKPKey {
	return &AKPKey{Kty: k.Kty, Alg: k.Alg, Kid: k.Kid, Pub: k.Pub}
}

// PublicKey reconstructs the crypto/mldsa public key.
func (k *AKPKey) PublicKey() (*cryptomldsa.PublicKey, error) {
	if err := k.validate(); err != nil {
		return nil, err
	}
	return cryptomldsa.NewPublicKey(Params(), k.Pub)
}

// PrivateKey reconstructs the crypto/mldsa private key from the stored seed.
// It fails on a public-only JWK rather than returning a zero key.
func (k *AKPKey) PrivateKey() (*cryptomldsa.PrivateKey, error) {
	if err := k.validate(); err != nil {
		return nil, err
	}
	if len(k.Priv) == 0 {
		return nil, errors.New("mldsa: AKP JWK carries no private key")
	}
	return cryptomldsa.NewPrivateKey(Params(), k.Priv)
}

// validate checks the members that identify the key as ML-DSA-65 AKP material.
// The public-key length is checked here so a truncated or wrong-parameter-set
// encoding is rejected with ErrNotAKP at the JWKS boundary instead of as an
// opaque primitive error later.
func (k *AKPKey) validate() error {
	if k.Kty != KeyType {
		return fmt.Errorf("%w: kty is %q, want %q", ErrNotAKP, k.Kty, KeyType)
	}
	if k.Alg != Alg {
		return fmt.Errorf("%w: alg is %q, want %q", ErrNotAKP, k.Alg, Alg)
	}
	if want := Params().PublicKeySize(); len(k.Pub) != want {
		return fmt.Errorf("%w: pub is %d bytes, want %d", ErrNotAKP, len(k.Pub), want)
	}
	return nil
}

// MarshalJSON writes the RFC 9964 form with pub/priv base64url-encoded without
// padding (RFC 7515 §2), which is how every other JOSE byte member is encoded.
func (k AKPKey) MarshalJSON() ([]byte, error) {
	w := akpWire{
		Kty: k.Kty,
		Alg: k.Alg,
		Kid: k.Kid,
		Pub: base64.RawURLEncoding.EncodeToString(k.Pub),
	}
	if len(k.Priv) > 0 {
		w.Priv = base64.RawURLEncoding.EncodeToString(k.Priv)
	}
	return json.Marshal(w)
}

// UnmarshalJSON reads the RFC 9964 form. Padded base64url is tolerated on the
// way in — some producers emit it even though RFC 7515 forbids it — while
// MarshalJSON always writes the unpadded form.
func (k *AKPKey) UnmarshalJSON(data []byte) error {
	var w akpWire
	if err := json.Unmarshal(data, &w); err != nil {
		return err
	}
	pub, err := decodeB64URL(w.Pub)
	if err != nil {
		return fmt.Errorf("mldsa: decoding AKP \"pub\": %w", err)
	}
	var priv []byte
	if w.Priv != "" {
		if priv, err = decodeB64URL(w.Priv); err != nil {
			return fmt.Errorf("mldsa: decoding AKP \"priv\": %w", err)
		}
	}
	k.Kty, k.Alg, k.Kid, k.Pub, k.Priv = w.Kty, w.Alg, w.Kid, pub, priv
	return nil
}

func decodeB64URL(s string) ([]byte, error) {
	if n := len(s) % 4; n != 0 {
		// Unpadded input: RawURLEncoding is the RFC 7515 form.
		return base64.RawURLEncoding.DecodeString(s)
	}
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.URLEncoding.DecodeString(s)
}

// ParseAKPJWK decodes one JWK and returns it only when it is an ML-DSA-65 AKP
// key. Anything else — an RSA JWK, an AKP JWK for another parameter set — comes
// back as ErrNotAKP, which callers walking a JWKS treat as "not mine, skip".
func ParseAKPJWK(raw json.RawMessage) (*AKPKey, error) {
	var probe struct {
		Kty string `json:"kty"`
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNotAKP, err)
	}
	if probe.Kty != KeyType {
		return nil, fmt.Errorf("%w: kty is %q", ErrNotAKP, probe.Kty)
	}
	if probe.Alg != Alg {
		return nil, fmt.Errorf("%w: alg is %q", ErrNotAKP, probe.Alg)
	}
	var key AKPKey
	if err := json.Unmarshal(raw, &key); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNotAKP, err)
	}
	if err := key.validate(); err != nil {
		return nil, err
	}
	return &key, nil
}
