package tlsSupport

// PQ-KEM guard (i2goSignals#271).
//
// Hybrid post-quantum key exchange is negotiated today only because nothing in
// this project sets CurvePreferences — an invariant held by omission, which is
// the kind that a well-meaning "let's pin the curve list" change silently
// breaks. These tests turn it into a stated one:
//
//   - every *tls.Config this project builds runs through Harden, and
//   - Harden never produces a config that has switched X25519MLKEM768 off, nor
//     one below TLS 1.2, for either value of I2SIG_TLS_PQ_KEM.
//
// The companion source-scan guard in tls_config_guard_test.go proves the first
// half (no site skips Harden, every literal states MinVersion); the tests here
// prove the second. Together they cover the sites that cannot be reached from
// a unit test — the SPIFFE client configs need a live SPIRE agent — without
// pretending a mock stands in for the real constructor.

import (
	"crypto/tls"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// pqKemModes is every accepted value of I2SIG_TLS_PQ_KEM plus the two ways a
// deployment can fail to set it meaningfully. All four must satisfy the
// invariant; a bad value must degrade to the toolchain default, not to a
// classical-only handshake.
var pqKemModes = []struct {
	name string
	env  string
}{
	{"unset", ""},
	{"default X25519MLKEM768", PqKemX25519MLKEM768},
	{"opt-in MLKEM1024", PqKemMLKEM1024},
	{"unrecognised value", "supercalifragilistic-kem"},
}

// assertPqKemInvariant is the single assertion this whole guard exists to
// make. Every config produced anywhere in the project must satisfy it.
func assertPqKemInvariant(t *testing.T, where string, cfg *tls.Config) {
	t.Helper()
	require.NotNil(t, cfg, "%s: produced a nil *tls.Config", where)
	assert.GreaterOrEqual(t, cfg.MinVersion, uint16(tls.VersionTLS12),
		"%s: MinVersion must be stated and at least TLS 1.2", where)
	if cfg.CurvePreferences != nil {
		assert.True(t, slices.Contains(cfg.CurvePreferences, tls.X25519MLKEM768),
			"%s: an explicit CurvePreferences list must keep the X25519MLKEM768 hybrid; got %v",
			where, cfg.CurvePreferences)
	}
}

func TestHarden_PqKemInvariantHoldsForEveryMode(t *testing.T) {
	for _, mode := range pqKemModes {
		t.Run(mode.name, func(t *testing.T) {
			t.Setenv(EnvTlsPqKem, mode.env)
			assertPqKemInvariant(t, "Harden(&tls.Config{})", Harden(&tls.Config{}))
			assertPqKemInvariant(t, "Harden(nil)", Harden(nil))
		})
	}
}

func TestHarden_DefaultLeavesCurvePreferencesToTheToolchain(t *testing.T) {
	for _, env := range []string{"", PqKemX25519MLKEM768, "x25519mlkem768", "  X25519MLKEM768  "} {
		t.Setenv(EnvTlsPqKem, env)
		cfg := Harden(&tls.Config{})
		assert.Nil(t, cfg.CurvePreferences,
			"%q must leave CurvePreferences nil so future toolchain additions (SecP256r1MLKEM768, "+
				"SecP384r1MLKEM1024, ...) are picked up automatically", env)
	}
}

func TestHarden_MLKEM1024OffersBothMLKEMAndClassicalCurves(t *testing.T) {
	t.Setenv(EnvTlsPqKem, PqKemMLKEM1024)
	cfg := Harden(&tls.Config{})

	require.NotNil(t, cfg.CurvePreferences, "MLKEM1024 mode must install an explicit allow-list")
	assert.True(t, slices.Contains(cfg.CurvePreferences, tls.MLKEM1024),
		"the whole point of the opt-in is that MLKEM1024 becomes offerable")
	assert.True(t, slices.Contains(cfg.CurvePreferences, tls.X25519MLKEM768),
		"the hybrid must survive the opt-in: crypto/tls picks from the allow-list by its own "+
			"internal order, so dropping the hybrid cannot promote MLKEM1024, only break peers")
	assert.True(t, slices.Contains(cfg.CurvePreferences, tls.X25519),
		"ML-KEM is TLS 1.3-only; dropping the classical curves would break every TLS 1.2 peer")
}

func TestHarden_MLKEM1024ListIsNotSharedWithCallers(t *testing.T) {
	t.Setenv(EnvTlsPqKem, PqKemMLKEM1024)

	first := Harden(&tls.Config{})
	require.NotEmpty(t, first.CurvePreferences)
	first.CurvePreferences[0] = tls.CurveP256 // a caller sorting or trimming its own config

	second := Harden(&tls.Config{})
	assert.True(t, slices.Contains(second.CurvePreferences, tls.MLKEM1024),
		"one caller mutating its config must not degrade every later config")
}

func TestHarden_KeepsAStricterMinVersion(t *testing.T) {
	cfg := Harden(&tls.Config{MinVersion: tls.VersionTLS13})
	assert.Equal(t, uint16(tls.VersionTLS13), cfg.MinVersion,
		"Harden sets a floor, not a ceiling: a caller asking for TLS 1.3 must keep it")
}

func TestHarden_RaisesAnUnsetOrWeakMinVersion(t *testing.T) {
	assert.Equal(t, uint16(tls.VersionTLS12), Harden(&tls.Config{}).MinVersion)
	assert.Equal(t, uint16(tls.VersionTLS12), Harden(&tls.Config{MinVersion: tls.VersionTLS10}).MinVersion,
		"an explicit-but-obsolete floor must still be raised")
}

// TestSpiffeServerConfigs_SatisfyPqKemInvariant covers the two SPIFFE server
// constructors, which are reachable with a nil X509Source because they only
// close over it. The client-side SPIFFE constructors dereference the source
// immediately (see TestNewClusterMTLSClientConfig_NoSource) and so are covered
// by the source-scan guard plus Harden's own tests instead.
func TestSpiffeServerConfigs_SatisfyPqKemInvariant(t *testing.T) {
	for _, mode := range pqKemModes {
		t.Run(mode.name, func(t *testing.T) {
			t.Setenv(EnvTlsPqKem, mode.env)

			cfg, err := NewSpiffeServerConfig(nil)
			require.NoError(t, err)
			assertPqKemInvariant(t, "NewSpiffeServerConfig", cfg)

			cfg, err = NewClusterMTLSServerConfig(nil)
			require.NoError(t, err)
			assertPqKemInvariant(t, "NewClusterMTLSServerConfig", cfg)
		})
	}
}

// TestInitTransportLayerSecurity_FileBased_SatisfiesPqKemInvariant covers the
// file-based server config, which is the TLS config an operator without SPIRE
// actually runs with.
func TestInitTransportLayerSecurity_FileBased_SatisfiesPqKemInvariant(t *testing.T) {
	certPath, keyPath := writeTestServerKeyPair(t)

	for _, mode := range pqKemModes {
		t.Run(mode.name, func(t *testing.T) {
			t.Setenv(EnvTlsPqKem, mode.env)
			t.Setenv("I2SIG_TLS_ENABLED", "true")
			t.Setenv(EnvSpiffeSocket, "")
			t.Setenv(EnvServerCert, certPath)
			t.Setenv(EnvServerKey, keyPath)

			srv := &http.Server{} //nolint:gosec // no timeouts needed: never served, only inspected
			closer, enabled, err := InitTransportLayerSecurity(srv)
			require.NoError(t, err)
			require.True(t, enabled, "TLS should be enabled from the file-based key pair")
			require.Nil(t, closer, "no SPIFFE source to close on the file-based path")

			assertPqKemInvariant(t, "InitTransportLayerSecurity (file-based)", srv.TLSConfig)
		})
	}
}

// TestCheckCaInstalled_SatisfiesPqKemInvariant covers the two client-side
// configs CheckCaInstalled builds. The third branch mutates
// http.DefaultTransport process-wide, so it is deliberately left to the
// source-scan guard rather than given a test that would leak into every other
// package's HTTP behaviour.
func TestCheckCaInstalled_SatisfiesPqKemInvariant(t *testing.T) {
	caPath := writeTestCaCert(t)

	for _, mode := range pqKemModes {
		t.Run(mode.name, func(t *testing.T) {
			t.Setenv(EnvTlsPqKem, mode.env)
			t.Setenv(EnvCaCert, caPath)

			// Branch 1: client has no transport at all -> a fresh one is built.
			fresh := &http.Client{}
			CheckCaInstalled(fresh)
			transport, ok := fresh.Transport.(*http.Transport)
			require.True(t, ok, "CheckCaInstalled must install an *http.Transport")
			assertPqKemInvariant(t, "CheckCaInstalled (new transport)", transport.TLSClientConfig)

			// Branch 2: client already has a transport with no TLS config.
			existing := &http.Client{Transport: &http.Transport{}}
			CheckCaInstalled(existing)
			transport = existing.Transport.(*http.Transport)
			assertPqKemInvariant(t, "CheckCaInstalled (existing transport)", transport.TLSClientConfig)
		})
	}
}

// writeTestServerKeyPair writes a throwaway self-signed server cert/key pair to
// the test's temp dir and returns their paths.
func writeTestServerKeyPair(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	cert := createTestCert(t, priv, []string{"localhost"})

	dir := t.TempDir()
	certPath = filepath.Join(dir, "server-cert.pem")
	keyPath = filepath.Join(dir, "server-key.pem")

	require.NoError(t, os.WriteFile(certPath,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), 0o600))
	require.NoError(t, os.WriteFile(keyPath,
		pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}), 0o600))
	return certPath, keyPath
}

// writeTestCaCert writes a throwaway self-signed CA certificate and returns its
// path, so CheckCaInstalled has something real to load.
func writeTestCaCert(t *testing.T) string {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	cert := createTestCert(t, priv, []string{"test-ca.invalid"})

	path := filepath.Join(t.TempDir(), "ca-cert.pem")
	require.NoError(t, os.WriteFile(path,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), 0o600))
	return path
}
