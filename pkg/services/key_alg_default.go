package services

import (
	"crypto"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"

	"github.com/golang-jwt/jwt/v5"

	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/goSet/mldsa"
)

// KeyAlgEnvVar names the setting that chooses the type of a key created with
// no explicit algorithm (spec #114): POST /key/{name} without ?alg=,
// KeyService.CreateKeyPair, and the default issuer's key at startup. The
// auth-token key is not affected; it is always RSA because auth tokens are
// RS256.
const KeyAlgEnvVar = "I2SIG_KEY_ALG"

// FallbackKeyAlg is the key type used when KeyAlgEnvVar is unset or blank.
// KeyService.DefaultKeyAlg is the configured type a service actually mints.
const FallbackKeyAlg = jwtES256

// KeyIdHeader is the response header every minting POST /key/{name} carries
// the new key's kid in (spec #114). The server sets it; the CLI and the bench
// harness read it.
const KeyIdHeader = "Key-Id"

// DefaultKeyAlgFromEnv returns the key type KeyAlgEnvVar selects: ES256 when it
// is unset or blank, or one of RS256, ES256 and ML-DSA-65. Any other value is an
// error naming the variable; every binary calls this at startup and exits on
// the error.
func DefaultKeyAlgFromEnv() (string, error) {
	raw := strings.TrimSpace(os.Getenv(KeyAlgEnvVar))
	switch raw {
	case "":
		return FallbackKeyAlg, nil
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
		return FallbackKeyAlg
	}
	return alg
}

// LogDefaultKeyAlgOrExit is the startup check every server binary runs: it
// resolves KeyAlgEnvVar and logs the default key type, or logs the error and
// exits non-zero when the value names no supported type, rather than falling
// back silently (spec #114).
func LogDefaultKeyAlgOrExit(log *slog.Logger) string {
	alg, err := DefaultKeyAlgFromEnv()
	if err != nil {
		log.Error("Fatal: invalid default key type", "error", err)
		os.Exit(-1)
	}
	log.Info("Default key type", "alg", alg)
	return alg
}

// DefaultKeyAlg is the JWS name of the key type this service creates when a
// request names no algorithm (KeyAlgEnvVar).
func (s *KeyService) DefaultKeyAlg() string {
	if s.defaultKeyAlg == "" {
		return FallbackKeyAlg
	}
	return s.defaultKeyAlg
}

// keySelector is which signing keys selection considers: those of one stored
// algorithm (JwkKeyRec.Alg, "" for RSA), or, for a stream with an empty
// signing_alg, the issuer's keys of any type, so its newest active key of any
// type signs (spec #114).
type keySelector struct {
	storedAlg string // the JwkKeyRec.Alg to match; ignored when anyType
	anyType   bool
}

// anyKeyType selects a signing key of any type.
var anyKeyType = keySelector{anyType: true}

// pinnedAlg selects signing keys of the stored algorithm storedAlg only.
func pinnedAlg(storedAlg string) keySelector {
	return keySelector{storedAlg: storedAlg}
}

// matches reports whether rec's key type is one sel selects.
func (sel keySelector) matches(rec *interfaces.JwkKeyRec) bool {
	return sel.anyType || rec.Alg == sel.storedAlg
}

// label names sel for a log line: "any key type", or the JWS name of the
// pinned algorithm ("RS256" for the stored "").
func (sel keySelector) label() string {
	if sel.anyType {
		return SigningAlgLabel("")
	}
	return algLabel(sel.storedAlg)
}

// selectionFor maps a stream's signing_alg to the keys signing selection
// considers. Empty means any key type; RS256, ES256 and ML-DSA-65 pin that
// type, RS256 matching the stored "".
func selectionFor(signingAlg string) (keySelector, error) {
	if signingAlg == "" {
		return anyKeyType, nil
	}
	storedAlg, err := storedAlgFor(signingAlg)
	if err != nil {
		return keySelector{}, err
	}
	return pinnedAlg(storedAlg), nil
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
		// This runs on every SET, so the invariant violation is an ERROR once
		// per key type and DEBUG after that (CONTEXT.md log-level policy); the
		// RS256 fallback itself is unchanged.
		if _, seen := unsupportedSignerLogged.LoadOrStore(fmt.Sprintf("%T", key), true); seen {
			ksLog.Debug("Signing key of an unsupported type reached a signing site", "error", err)
		} else {
			ksLog.Error("Signing key of an unsupported type reached a signing site", "error", err)
		}
		return goSet.SigningMethodOrRS256("")
	}
	return goSet.SigningMethodOrRS256(alg)
}

// unsupportedSignerLogged records the key types StreamSigningMethod has already
// logged its ERROR for.
var unsupportedSignerLogged sync.Map

// SigningMethodOf is the JWS method a key of this type signs with, and its JWS
// name: the CLI and the bench harness sign with whatever key type the server
// minted (spec #114).
func SigningMethodOf(key crypto.Signer) (jwt.SigningMethod, string, error) {
	alg, err := SigningAlgOf(key)
	if err != nil {
		return nil, "", err
	}
	method, err := goSet.SigningMethodFor(alg)
	if err != nil {
		return nil, "", err
	}
	return method, alg, nil
}
