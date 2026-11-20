package tlsSupport

import (
	"crypto/tls"
	"log/slog"
	"os"
	"strings"
)

const (
	// EnvTlsPqKem selects the post-quantum key-exchange posture applied to
	// every *tls.Config this project builds. See Harden.
	EnvTlsPqKem = "I2SIG_TLS_PQ_KEM"

	// PqKemX25519MLKEM768 is the default value of EnvTlsPqKem. It leaves
	// CurvePreferences nil so the Go toolchain's own key-exchange set applies:
	// since Go 1.24 that set leads with the X25519MLKEM768 hybrid, and since
	// Go 1.26 it also offers SecP256r1MLKEM768 and SecP384r1MLKEM1024. Pinning
	// a literal list as the default would silently opt the project out of every
	// future addition, which is precisely the drift this default avoids.
	PqKemX25519MLKEM768 = "X25519MLKEM768"

	// PqKemMLKEM1024 adds standalone ML-KEM-1024 (NIST category 5) to the
	// offered key-exchange set for deployments whose policy demands it.
	//
	// The hybrid X25519MLKEM768 and the classical curves stay in the list on
	// purpose. crypto/tls treats CurvePreferences as an allow-list and picks
	// from it using its own internal preference order (see
	// (*Config).curvePreferences), so a narrower list cannot promote MLKEM1024
	// ahead of the hybrid — it can only make the connection fail against peers
	// that do not implement it. ML-KEM is also TLS 1.3-only, so dropping the
	// classical curves would break every TLS 1.2 peer outright.
	PqKemMLKEM1024 = "MLKEM1024"

	// MinTLSVersion is the floor Harden applies, and the value every
	// tls.Config literal in this repository states explicitly. TLS 1.2 rather
	// than 1.3 because SSF receivers in the field still terminate at 1.2.
	MinTLSVersion = tls.VersionTLS12
)

// mlkem1024CurvePreferences is the allow-list installed for
// EnvTlsPqKem=MLKEM1024. Kept as a package var so the guard test can assert
// against the same list the runtime uses rather than a copy that could drift.
var mlkem1024CurvePreferences = []tls.CurveID{
	tls.MLKEM1024,
	tls.X25519MLKEM768,
	tls.X25519,
	tls.CurveP256,
	tls.CurveP384,
	tls.CurveP521,
}

// Harden applies this project's TLS policy to cfg and returns it, so a caller
// can wrap a literal in place:
//
//	app.TLSConfig = tlsSupport.Harden(&tls.Config{MinVersion: tls.VersionTLS12, ...})
//
// It is the single place the key-exchange posture is decided. Every tls.Config
// built in pkg/tlsSupport and pkg/oauthClient routes through it, which is what
// lets one test of Harden stand for the invariant at all of those sites; the
// source-scan guard in this package fails the build if a new site skips it.
//
// Two things are guaranteed of the returned config:
//
//   - MinVersion is at least MinTLSVersion. A caller that asked for more (say
//     TLS 1.3) keeps it; only an unset (zero) MinVersion is filled in.
//   - CurvePreferences either stays nil — meaning the toolchain default, which
//     already leads with X25519MLKEM768 — or is an allow-list that contains
//     X25519MLKEM768. Post-quantum key exchange is therefore never silently
//     switched off by this project's own configuration.
//
// A nil cfg yields a fresh hardened config rather than a nil dereference.
func Harden(cfg *tls.Config) *tls.Config {
	if cfg == nil {
		// new() rather than a composite literal: the source-scan guard in
		// tls_config_guard_test.go requires every tls.Config literal to state
		// MinVersion and route through Harden, and Harden cannot route through
		// itself.
		cfg = new(tls.Config)
	}
	if cfg.MinVersion < MinTLSVersion {
		cfg.MinVersion = MinTLSVersion
	}
	if curves := pqKemCurvePreferences(); curves != nil {
		cfg.CurvePreferences = curves
	}
	return cfg
}

// pqKemCurvePreferences maps EnvTlsPqKem to a CurvePreferences allow-list, or
// nil to leave the toolchain default in place. An unrecognised value is a
// misconfiguration: it warns and falls back to the default rather than failing
// the handshake, because a typo in a deployment variable should not take TLS
// down.
func pqKemCurvePreferences() []tls.CurveID {
	switch v := strings.ToUpper(strings.TrimSpace(os.Getenv(EnvTlsPqKem))); v {
	case "", PqKemX25519MLKEM768:
		return nil
	case PqKemMLKEM1024:
		// Copy: the caller owns the returned config and could sort or append.
		return append([]tls.CurveID(nil), mlkem1024CurvePreferences...)
	default:
		slog.Warn("Unrecognized TLS PQ-KEM selection; using toolchain default",
			"env", EnvTlsPqKem, "value", v, "supported", []string{PqKemX25519MLKEM768, PqKemMLKEM1024})
		return nil
	}
}
