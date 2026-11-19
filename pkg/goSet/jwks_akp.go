package goSet

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/i2-open/i2goSignals/pkg/goSet/mldsa"
	"github.com/i2-open/i2goSignals/pkg/logger"
)

var jwksLog = logger.Sub("JWKS")

// This file is the receiver half of RFC 9964 support: it resolves `kty:"AKP"`
// entries of a JWK Set, which jwkset (and so keyfunc) cannot parse. The AKP keys
// become pinned entries of a goSet.JWKS beside the RSA/EC keys jwkset parses
// (see jwks.go); both are rebuilt from the same bytes on every refresh.

// AKPKeys extracts the RFC 9964 ML-DSA-65 keys from a raw JWK Set, each pinned
// to alg ML-DSA-65.
//
// A JWK that is not ML-DSA-65 AKP material is skipped, not an error: a JWK Set
// legitimately mixes key types, and one unreadable key must not cost a receiver
// the rest of the set. A malformed *set* is an error, since that is the whole
// document.
func AKPKeys(rawJWKS json.RawMessage) (map[string]VerificationKey, error) {
	keys := map[string]VerificationKey{}
	if len(rawJWKS) == 0 {
		return keys, nil
	}
	var set struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(rawJWKS, &set); err != nil {
		return nil, fmt.Errorf("goSet: parsing JWKS for AKP keys: %w", err)
	}
	for _, raw := range set.Keys {
		akp, err := mldsa.ParseAKPJWK(raw)
		if err != nil {
			if errors.Is(err, mldsa.ErrNotAKP) {
				continue // an RSA/EC key, or an AKP key of another parameter set
			}
			jwksLog.Warn("Skipping malformed AKP JWK", "error", err)
			continue
		}
		pub, err := akp.PublicKey()
		if err != nil {
			jwksLog.Warn("Skipping unusable AKP JWK", "kid", akp.Kid, "error", err)
			continue
		}
		keys[akp.Kid] = VerificationKey{Key: pub, Alg: mldsa.Alg}
	}
	return keys, nil
}

// NewJwksWithAKP builds a static verification JWKS from raw JWK Set bytes,
// resolving RSA/EC keys through jwkset/keyfunc and ML-DSA keys through mldsa.
func NewJwksWithAKP(rawJWKS json.RawMessage) (*JWKS, error) {
	st, err := buildJwksState(rawJWKS)
	if err != nil {
		return nil, err
	}
	return &JWKS{state: st}, nil
}
