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

// recordingDiscoveryStub answers the SSF discovery probe for ANY path that
// contains the well-known component and records the exact request path so a
// test can assert how `add server` built the discovery URL. It returns 404 for
// anything else so an append-style probe (the pre-#187 bug) fails the test.
func recordingDiscoveryStub(t *testing.T, gotPath *string) *httptest.Server {
	t.Helper()
	const wk = "/.well-known/ssf-configuration"
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only the ssf-configuration probe is of interest; `add server` also
		// fetches oauth-protected-resource later, which must not clobber the
		// recorded discovery path.
		if r.URL.Path == wk || strings.HasPrefix(r.URL.Path, wk+"/") {
			// RFC 8615 / SSF §7.2 insertion: /.well-known/ssf-configuration/<path>
			*gotPath = r.URL.Path
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(model.TransmitterConfiguration{
				Issuer: "https://transmitter.example.com",
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
}

// TestAddServer_InsertStyleDiscoveryWithPath proves that when the server URL
// carries a non-empty path (the OpenID conformance suite's emulated transmitter
// lives under /test/a/<alias>), `add server` probes discovery by INSERTING
// /.well-known/ssf-configuration between host and path per SSF §7.2 / Figure 17,
// never appending it after the path.
func TestAddServer_InsertStyleDiscoveryWithPath(t *testing.T) {
	var gotPath string
	stub := recordingDiscoveryStub(t, &gotPath)
	defer stub.Close()

	cli := newTestCLI(t)

	cmd := &AddServerCmd{
		Alias: "suite",
		Host:  stub.URL + "/test/a/abc",
	}
	err := cmd.Run(cli)
	require.NoError(t, err)

	assert.Equal(t, "/.well-known/ssf-configuration/test/a/abc", gotPath,
		"discovery URL must INSERT the well-known component between host and path")
}

// TestAddServer_InsertStyleDiscoveryHostOnly proves the host-only case (the
// SUT's default issuer) is unchanged: discovery is host + well-known path.
func TestAddServer_InsertStyleDiscoveryHostOnly(t *testing.T) {
	var gotPath string
	stub := recordingDiscoveryStub(t, &gotPath)
	defer stub.Close()

	cli := newTestCLI(t)

	cmd := &AddServerCmd{
		Alias: "host-only",
		Host:  stub.URL,
	}
	err := cmd.Run(cli)
	require.NoError(t, err)

	assert.Equal(t, "/.well-known/ssf-configuration", gotPath,
		"host-only issuer discovery URL must be host + well-known path")
}
