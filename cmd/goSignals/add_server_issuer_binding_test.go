package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// issuerBindingStub answers the SSF discovery probe with a caller-controlled
// issuer (read through a pointer so a test can set it to the stub's own URL
// after construction) and a deliberately FREE-FORM jwks_uri on an unrelated
// host. Everything else 404s, so the later protected-resource probe is a
// harmless miss. Used to exercise the §7.2.4 issuer↔discovery-location check in
// `add server`.
func issuerBindingStub(t *testing.T, advertisedIssuer *string) *httptest.Server {
	t.Helper()
	const wk = "/.well-known/ssf-configuration"
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == wk || strings.HasPrefix(r.URL.Path, wk+"/") {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(model.TransmitterConfiguration{
				Issuer:  *advertisedIssuer,
				JwksUri: "https://keys.elsewhere.example/jwks.json",
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
}

// TestAddServer_StrictIssuerMismatch_Fails: a server added with --strict-ssf
// whose discovery doc advertises an issuer different from the location it was
// fetched from must FAIL the §7.2.4 binding and must NOT be recorded.
func TestAddServer_StrictIssuerMismatch_Fails(t *testing.T) {
	issuer := "https://impersonator.example.com"
	stub := issuerBindingStub(t, &issuer)
	defer stub.Close()

	cli := newTestCLI(t)
	cmd := &AddServerCmd{Alias: "strict-bad", Host: stub.URL, StrictSsf: true}
	err := cmd.Run(cli)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "issuer binding")
	_, exists := cli.Data.Servers["strict-bad"]
	assert.False(t, exists, "a strict server failing the issuer binding must not be recorded")
}

// TestAddServer_FlexibleIssuerMismatch_WarnsAndRecords: the default (non-strict)
// posture warns on a mismatch but still records the server and returns no error.
func TestAddServer_FlexibleIssuerMismatch_WarnsAndRecords(t *testing.T) {
	issuer := "https://different.example.com"
	stub := issuerBindingStub(t, &issuer)
	defer stub.Close()

	cli := newTestCLI(t)
	cmd := &AddServerCmd{Alias: "flex-mismatch", Host: stub.URL}
	out := captureStdout(t, func() {
		require.NoError(t, cmd.Run(cli))
	})
	_, exists := cli.Data.Servers["flex-mismatch"]
	assert.True(t, exists, "a flexible server with an issuer mismatch is still recorded")
	assert.Contains(t, out, "issuer binding", "a warning must be surfaced to the operator")
}

// TestAddServer_StrictIssuerMatch_Succeeds: a strict server whose advertised
// issuer equals the discovery location is recorded with no error — and the
// free-form jwks_uri (a different host) does not affect the outcome.
func TestAddServer_StrictIssuerMatch_Succeeds(t *testing.T) {
	var issuer string
	stub := issuerBindingStub(t, &issuer)
	defer stub.Close()
	issuer = stub.URL // issuer == discovery location

	cli := newTestCLI(t)
	cmd := &AddServerCmd{Alias: "strict-good", Host: stub.URL, StrictSsf: true}
	require.NoError(t, cmd.Run(cli))
	_, exists := cli.Data.Servers["strict-good"]
	assert.True(t, exists, "a strict server with a consistent issuer binding is recorded")
}
