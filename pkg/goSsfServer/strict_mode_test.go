package goSsfServer

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/i2-open/i2goSignals/internal/providers/dbProviders"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/require"
)

// newStrictApp opens a fresh in-memory persistence and SsfApplication. Env vars
// that steer issuer resolution (I2SIG_ISSUER_DEFAULT) must be set by the caller
// BEFORE this runs, since both the provider's Open and NewApplication read them.
func newStrictApp(t *testing.T, dbName, baseUrl string) *SsfApplication {
	t.Helper()
	t.Setenv("MEM_DIRECTORY", t.TempDir())
	p, err := dbProviders.OpenPersistence("memorydb:", dbName)
	require.NoError(t, err)
	t.Cleanup(func() {
		if p.Storage != nil {
			_ = p.Storage.Close()
		}
	})
	return NewApplication(p, baseUrl)
}

// TestProvisionStrictMode_ServesIssuerDiscovery is the end-to-end strict-mode
// contract: an administrator-declared, path-bearing issuer is provisioned so its
// RFC 8615 path-inserted discovery endpoint resolves (ADR 0023) with issuer ==
// the full URL and a jwks_uri derived from the issuer path.
func TestProvisionStrictMode_ServesIssuerDiscovery(t *testing.T) {
	const baseUrl = "http://localhost:8889/"
	const issuer = "http://localhost:8889/issuer1"
	t.Setenv("I2SIG_ISSUER_DEFAULT", issuer)

	app := newStrictApp(t, "strict_discovery_test", baseUrl)
	require.Equal(t, issuer, app.GetDefIssuer(), "DefIssuer must reflect the declared issuer")

	require.NoError(t, app.ProvisionStrictMode(context.Background()))

	ts := httptest.NewServer(app.Handler)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/.well-known/ssf-configuration/issuer1")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "issuer-specific discovery must resolve once provisioned")

	var cfg model.TransmitterConfiguration
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&cfg))
	require.Equal(t, issuer, cfg.Issuer, "discovery must echo the declared issuer (SSF §7.2.4)")
	require.Equal(t, "http://localhost:8889/jwks/issuer1", cfg.JwksUri,
		"jwks_uri must be derived from the issuer path (ADR 0023)")
}

// TestProvisionStrictMode_RejectsMisconfiguration covers the fail-fast guard:
// strict mode refuses to start without an explicit, absolute http(s) issuer URL.
func TestProvisionStrictMode_RejectsMisconfiguration(t *testing.T) {
	cases := []struct {
		name   string
		issuer string
	}{
		{"empty", ""},
		{"default-sentinel", "DEFAULT"},
		{"not-a-url", "not-a-valid-url"},
		{"relative", "issuer1"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("I2SIG_ISSUER_DEFAULT", tc.issuer)
			t.Setenv("I2SIG_ISSUER", "") // envcompat also consults the legacy alias
			app := newStrictApp(t, "strict_reject_cfg_"+tc.name, "http://localhost:8889/")
			err := app.ProvisionStrictMode(context.Background())
			require.Error(t, err, "strict mode must refuse issuer %q", tc.issuer)
		})
	}
}
