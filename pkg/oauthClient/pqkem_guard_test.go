package oauthClient

// PQ-KEM guard for the oauthClient half of the TLS surface (i2goSignals#271).
//
// pkg/tlsSupport owns the policy (Harden) and the source-scan that proves every
// site routes through it. This file is the runtime half for the two configs
// this package builds: the per-server client config used for every admin/OAuth
// call, and the deliberately unverified dial that ExtractServerCertificate uses
// to show an operator a certificate before they trust it.

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/i2-open/i2goSignals/pkg/tlsSupport"
)

// pqKemModes mirrors the table in pkg/tlsSupport: both accepted values plus the
// two ways a deployment can fail to set one.
var pqKemModes = []struct {
	name string
	env  string
}{
	{"unset", ""},
	{"default X25519MLKEM768", tlsSupport.PqKemX25519MLKEM768},
	{"opt-in MLKEM1024", tlsSupport.PqKemMLKEM1024},
	{"unrecognised value", "supercalifragilistic-kem"},
}

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

// TestGetTlsConfigForServer_SatisfiesPqKemInvariant walks every branch of the
// per-server config: no server, the plain case, the self-signed-certificate
// case, and the operator override that turns verification off. Skipping
// verification must not also skip the key-exchange floor.
func TestGetTlsConfigForServer_SatisfiesPqKemInvariant(t *testing.T) {
	servers := map[string]*model.Server{
		"nil server":   nil,
		"plain server": {Alias: "plain"},
		"skip verify":  {Alias: "skip", TLSSkipVerify: true},
		"pinned cert (bad PEM falls back to the global pool)": {Alias: "pinned", TLSCertificate: "not a pem"},
	}

	for _, mode := range pqKemModes {
		t.Run(mode.name, func(t *testing.T) {
			t.Setenv(tlsSupport.EnvTlsPqKem, mode.env)
			for name, server := range servers {
				assertPqKemInvariant(t, "GetTlsConfigForServer/"+name, GetTlsConfigForServer(server))
			}

			t.Setenv("AUTH_DEBUG", "true")
			assertPqKemInvariant(t, "GetTlsConfigForServer/AUTH_DEBUG", GetTlsConfigForServer(nil))
		})
	}
}

// TestExtractServerCertificate_HandshakesUnderEveryPqKemMode is the check the
// invariant assertions cannot make on their own: that the allow-list installed
// for MLKEM1024 still negotiates against a stock Go TLS server. A curve list
// that excludes what the peer supports fails at handshake time, not at config
// time, so only a real dial catches it.
func TestExtractServerCertificate_HandshakesUnderEveryPqKemMode(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	for _, mode := range pqKemModes {
		t.Run(mode.name, func(t *testing.T) {
			t.Setenv(tlsSupport.EnvTlsPqKem, mode.env)

			cert, err := ExtractServerCertificate(srv.URL)
			require.NoError(t, err, "the hardened dial must still reach a stock Go TLS server")
			require.NotNil(t, cert)
		})
	}
}
