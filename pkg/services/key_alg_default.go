package services

import (
	"crypto"
	"fmt"
	"os"
	"strings"

	"github.com/golang-jwt/jwt/v5"

	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/goSet/mldsa"
)

// KeyAlgEnvVar names the setting that chooses the type of a key created with
// no explicit algorithm (spec #114): POST /key/{name} without ?alg=,
// KeyService.CreateKeyPair, and the default issuer's key at startup. The
// auth-token key is not affected; it is always RSA because auth tokens are
// RS256.
const KeyAlgEnvVar = "I2SIG_KEY_ALG"

// DefaultKeyAlg is the key type used when KeyAlgEnvVar is unset or blank.
const DefaultKeyAlg = jwtES256

// DefaultKeyAlgFromEnv returns the key type KeyAlgEnvVar selects: ES256 when it
// is unset or blank, or one of RS256, ES256 and ML-DSA-65. Any other value is an
// error naming the variable; every binary calls this at startup and exits on
// the error.
func DefaultKeyAlgFromEnv() (string, error) {
	raw := strings.TrimSpace(os.Getenv(KeyAlgEnvVar))
	switch raw {
	case "":
		return DefaultKeyAlg, nil
	case jwtRS256, jwtES256, mldsa.Alg:
		return raw, nil
	default:
		return "", fmt.Errorf("%s=%q is not a supported key type; want %s, %s or %s",
			KeyAlgEnvVar, raw, jwtRS256, jwtES256, mldsa.Alg)
	}
}

// defaultKeyAlgOrES256 is DefaultKeyAlgFromEnv for NewKeyService, which has no
// error return: an invalid value falls back to ES256 there, because the binary
// has already refused to start on it.
func defaultKeyAlgOrES256() string {
	alg, err := DefaultKeyAlgFromEnv()
	if err != nil {
		ksLog.Warn("Invalid default key type; using ES256", "error", err)
		return DefaultKeyAlg
	}
	return alg
}

// DefaultKeyAlg is the JWS name of the key type this service creates when a
// request names no algorithm (KeyAlgEnvVar).
func (s *KeyService) DefaultKeyAlg() string {
	if s.defaultKeyAlg == "" {
		return DefaultKeyAlg
	}
	return s.defaultKeyAlg
}

// anyStoredAlg is the selection algorithm of a stream with an empty
// signing_alg: the issuer's newest active key of any type signs (spec #114).
// It is never stored; JwkKeyRec.Alg "" is RSA.
const anyStoredAlg = "\x00any"

// selectionAlgFor maps a stream's signing_alg to the stored algorithm signing
// selection filters on. Empty means any key type (anyStoredAlg); RS256, ES256
// and ML-DSA-65 pin that type, RS256 matching the stored "".
func selectionAlgFor(signingAlg string) (string, error) {
	if signingAlg == "" {
		return anyStoredAlg, nil
	}
	return storedAlgFor(signingAlg)
}

// SigningAlgLabel names a stream's signing_alg for an operator message: the JWS
// name when it is pinned, "any key type" when it is empty (the issuer's newest
// key signs).
func SigningAlgLabel(signingAlg string) string {
	if signingAlg == "" {
		return "any key type"
	}
	return signingAlg
}

// StreamSigningMethod is the JWS method a signing site signs a stream's SET
// with. A pinned signing_alg decides it; an empty one takes it from the key's
// type (SigningAlgOf), because that key is the issuer's newest of any type.
func StreamSigningMethod(signingAlg string, key crypto.Signer) jwt.SigningMethod {
	if signingAlg != "" || key == nil {
		return goSet.SigningMethodOrRS256(signingAlg)
	}
	alg, err := SigningAlgOf(key)
	if err != nil {
		ksLog.Error("Signing key of an unsupported type reached a signing site", "error", err)
		return goSet.SigningMethodOrRS256("")
	}
	return goSet.SigningMethodOrRS256(alg)
}
