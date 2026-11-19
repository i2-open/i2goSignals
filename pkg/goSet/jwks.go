package goSet

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/MicahParks/jwkset"
	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
)

// VerificationKey is one public key in a JWKS together with the JWS alg it is
// pinned to. A token whose header names the key's kid but claims a different
// alg is refused at the key (ADR-0034 §5) — the algorithm-confusion guard that
// AllowedAlgs applies at the header is applied again here.
type VerificationKey struct {
	Key crypto.PublicKey
	Alg string
}

// ErrKIDNotFound is returned by JWKS.Keyfunc when no key in the set has the
// token's kid (after any permitted refresh).
var ErrKIDNotFound = errors.New("goSet: the given key ID was not found in the JWKS")

// JWKS is the family-owned verification key set (i2goSignals#399). It replaced
// keyfunc/v2's *keyfunc.JWKS in this module's exported API so that a future
// keyfunc major does not break the cross-repo API again.
//
// Keys come from two places:
//   - pinned: kid → VerificationKey, for RFC 9964 AKP (ML-DSA) keys, which
//     jwkset cannot parse, and for every key built in memory;
//   - classic: the RSA/EC keys of a JWK Set, held in a jwkset store behind a
//     keyfunc/v3 Keyfunc (which pins alg when the JWK carries one).
//
// Both parts are rebuilt together from the same bytes on every refresh of a
// remote set, so a rotated AKP key is picked up like a rotated RSA key.
type JWKS struct {
	mu    sync.RWMutex
	state jwksState

	remote *jwksRemote // nil for a static or in-memory set
}

type jwksState struct {
	pinned  map[string]VerificationKey
	classic keyfunc.Keyfunc // nil when the set holds no classic key
	keys    map[string]any  // kid → public key, every part
	raw     json.RawMessage // nil for an in-memory set
}

// NewJwksFromKeys builds a static JWKS from keys already held in memory. Every
// key is pinned to its Alg. RawJWKS of the result is nil.
func NewJwksFromKeys(keys map[string]VerificationKey) *JWKS {
	st := jwksState{
		pinned: make(map[string]VerificationKey, len(keys)),
		keys:   make(map[string]any, len(keys)),
	}
	for kid, k := range keys {
		st.pinned[kid] = k
		st.keys[kid] = k.Key
	}
	return &JWKS{state: st}
}

// Keyfunc is a jwt.Keyfunc: it returns the verification key for token, or an
// error if the set has no key for the token's kid and alg.
func (j *JWKS) Keyfunc(token *jwt.Token) (any, error) {
	key, err := j.lookup(token)
	// A token with no kid names no key a refresh could find, so only a named
	// kid triggers one.
	kid, _ := token.Header["kid"].(string)
	if kid != "" && errors.Is(err, ErrKIDNotFound) && j.remote != nil && j.remote.refreshForUnknownKID() {
		key, err = j.lookup(token)
	}
	return key, err
}

func (j *JWKS) lookup(token *jwt.Token) (any, error) {
	alg, _ := token.Header["alg"].(string)
	j.mu.RLock()
	st := j.state
	j.mu.RUnlock()

	if kid, ok := token.Header["kid"].(string); ok {
		if k, ok := st.pinned[kid]; ok {
			if k.Alg != "" && k.Alg != alg {
				return nil, fmt.Errorf("goSet: key %q is pinned to %s, token claims %s", kid, k.Alg, alg)
			}
			return k.Key, nil
		}
		if _, ok := st.keys[kid]; !ok {
			return nil, fmt.Errorf("%w: %q", ErrKIDNotFound, kid)
		}
	}
	if st.classic == nil {
		return nil, ErrKIDNotFound
	}
	return st.classic.Keyfunc(token)
}

// KIDs returns the key IDs in the set, sorted.
func (j *JWKS) KIDs() []string {
	j.mu.RLock()
	defer j.mu.RUnlock()
	kids := make([]string, 0, len(j.state.keys))
	for kid := range j.state.keys {
		kids = append(kids, kid)
	}
	sort.Strings(kids)
	return kids
}

// Len returns the number of keys in the set.
func (j *JWKS) Len() int {
	j.mu.RLock()
	defer j.mu.RUnlock()
	return len(j.state.keys)
}

// ReadOnlyKeys returns a copy of the kid → public key map.
func (j *JWKS) ReadOnlyKeys() map[string]any {
	j.mu.RLock()
	defer j.mu.RUnlock()
	out := make(map[string]any, len(j.state.keys))
	for kid, k := range j.state.keys {
		out[kid] = k
	}
	return out
}

// RawJWKS returns the JWK Set bytes the set was last built from, or nil for a
// set built in memory. It returns []byte, as keyfunc/v2 did, so a caller
// comparing it with a response body needs no conversion.
func (j *JWKS) RawJWKS() []byte {
	j.mu.RLock()
	defer j.mu.RUnlock()
	return j.state.raw
}

// Close stops a remote set's background refresh. It is safe to call more than
// once, on a nil set, and on a static set (where it does nothing).
func (j *JWKS) Close() {
	if j == nil || j.remote == nil {
		return
	}
	j.remote.close()
}

// buildJwksState parses a raw JWK Set: AKP keys via mldsa into the pinned map,
// every other key individually via jwkset into the classic store. One unusable
// key is skipped with a warning rather than costing the receiver the set
// (jwkset's own JWKSMarshal.ToStorage fails the whole set on one bad key). A
// malformed document is an error.
func buildJwksState(raw json.RawMessage) (jwksState, error) {
	var set struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(raw, &set); err != nil {
		return jwksState{}, fmt.Errorf("goSet: parsing JWKS: %w", err)
	}
	akp, err := AKPKeys(raw)
	if err != nil {
		return jwksState{}, err
	}
	st := jwksState{
		pinned: akp,
		keys:   make(map[string]any, len(set.Keys)),
		raw:    append(json.RawMessage(nil), raw...),
	}
	for kid, k := range akp {
		st.keys[kid] = k.Key
	}

	store := jwkset.NewMemoryStorage()
	classic := 0
	for _, rawKey := range set.Keys {
		var hdr struct {
			Kty string `json:"kty"`
		}
		if json.Unmarshal(rawKey, &hdr) == nil && hdr.Kty == "AKP" {
			continue // handled (or rejected) by AKPKeys
		}
		jwk, err := jwkset.NewJWKFromRawJSON(rawKey, jwkset.JWKMarshalOptions{}, jwkset.JWKValidateOptions{})
		if err != nil {
			jwksLog.Warn("Skipping unusable JWK", "error", err)
			continue
		}
		if err := store.KeyWrite(context.Background(), jwk); err != nil {
			return jwksState{}, fmt.Errorf("goSet: storing JWK: %w", err)
		}
		key := jwk.Key()
		if pk, ok := key.(interface{ Public() crypto.PublicKey }); ok {
			key = pk.Public()
		}
		st.keys[jwk.Marshal().KID] = key
		classic++
	}
	if classic > 0 {
		kf, err := keyfunc.New(keyfunc.Options{Storage: store})
		if err != nil {
			return jwksState{}, err
		}
		st.classic = kf
	}
	return st, nil
}
