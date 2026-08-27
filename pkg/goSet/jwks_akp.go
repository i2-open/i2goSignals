package goSet

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/MicahParks/keyfunc/v2"

	"github.com/i2-open/i2goSignals/pkg/goSet/mldsa"
	"github.com/i2-open/i2goSignals/pkg/logger"
)

var jwksLog = logger.Sub("JWKS")

// This file is the receiver half of RFC 9964 support: it teaches this project's
// JWKS loading to resolve `kty:"AKP"` entries, which keyfunc cannot.
//
// keyfunc parses a JWK Set by switching on "kty" and *silently skipping* any
// type it does not know (keyfunc/v2 jwks.go, `default: continue`). So a JWKS
// publishing an RSA key and an ML-DSA key side by side loads today without
// error — the AKP key simply is not there, and a PQ-signed SET fails with
// ErrKIDNotFound. Rather than fork the library, the AKP entries are parsed here
// and handed back through keyfunc's own extension point, GivenKey: given keys
// are merged into the key map on every refresh, so an AKP key survives
// background JWKS refreshes alongside the RSA keys fetched from the wire.

// AKPGivenKeys extracts the RFC 9964 ML-DSA keys from a raw JWK Set as keyfunc
// given keys, ready to merge with the RSA/EC keys keyfunc parses itself.
//
// A JWK that is not ML-DSA-65 AKP material is skipped, not an error: a JWK Set
// legitimately mixes key types, and one unreadable key must not cost a receiver
// the rest of the set. A malformed *set* is an error, since that is the whole
// document.
//
// The given keys pin Algorithm to ML-DSA-65, so keyfunc refuses the key for a
// token whose header claims a different alg — the algorithm-confusion guard
// that AllowedAlgs applies at the header is applied again at the key.
func AKPGivenKeys(rawJWKS json.RawMessage) (map[string]keyfunc.GivenKey, error) {
	if len(rawJWKS) == 0 {
		return nil, nil
	}
	var set struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(rawJWKS, &set); err != nil {
		return nil, fmt.Errorf("goSet: parsing JWKS for AKP keys: %w", err)
	}

	var given map[string]keyfunc.GivenKey
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
		if given == nil {
			given = make(map[string]keyfunc.GivenKey, 1)
		}
		given[akp.Kid] = keyfunc.NewGivenCustom(pub, keyfunc.GivenKeyOptions{Algorithm: mldsa.Alg})
	}
	return given, nil
}

// NewJwksWithAKP builds a verification JWKS from raw JWK Set bytes, resolving
// RSA/EC keys through keyfunc and ML-DSA keys through mldsa. It is the
// AKP-aware replacement for keyfunc.NewJSON at every in-process JWKS load.
//
// When the set holds no AKP key the result is keyfunc.NewJSON's, unchanged.
func NewJwksWithAKP(rawJWKS json.RawMessage) (*keyfunc.JWKS, error) {
	akp, err := AKPGivenKeys(rawJWKS)
	if err != nil {
		return nil, err
	}
	if len(akp) == 0 {
		return keyfunc.NewJSON(rawJWKS)
	}
	// NewGivenKeysFromJSON runs the same parser as NewJSON and yields the RSA/EC
	// keys as given keys, so merging is a map union rather than a second parse
	// with different rules.
	classic, err := keyfunc.NewGivenKeysFromJSON(rawJWKS)
	if err != nil {
		return nil, err
	}
	if classic == nil {
		classic = make(map[string]keyfunc.GivenKey, len(akp))
	}
	for kid, key := range akp {
		classic[kid] = key
	}
	return keyfunc.NewGiven(classic), nil
}
