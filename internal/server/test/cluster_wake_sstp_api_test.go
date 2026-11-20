package test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/i2-open/i2goSignals/pkg/authSupport"
	"github.com/stretchr/testify/assert"
)

// TestClusterWakeSstpAPI verifies that both SSTP cluster wake-up routes are
// mounted on the running server and enforce the existing shared-HMAC auth (PRD
// #154 Q11.1, Q11.2, issue #167 AC: both routes mounted with auth; unauthenticated
// requests rejected). The body's sid carries the PairId (client) or tx-side SID
// (server); mode names the route.
func TestClusterWakeSstpAPI(t *testing.T) {
	t.Setenv("I2SIG_CLUSTER_INTERNAL_TOKEN", "test-secret")

	instance, err := createServer(t, "cluster_wake_sstp_api_test", true)
	if err != nil {
		t.Fatal(err)
	}
	defer instance.app.Shutdown()

	cases := []struct {
		name string
		path string
		sid  string
		mode string
	}{
		{"client", "/_cluster/wake-sstp-client", "pair-1", "sstp-client"},
		{"server", "/_cluster/wake-sstp-server", "sstp-tx-1", "sstp-server"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body, _ := json.Marshal(map[string]string{"sid": tc.sid, "mode": tc.mode})

			// 1. Valid wake-up is accepted (route is mounted, auth passes).
			token := authSupport.GenerateClusterToken("test-secret", tc.sid, tc.mode)
			req, _ := http.NewRequest(http.MethodPost, instance.ts.URL+tc.path, bytes.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+token)
			resp, err := instance.client.Do(req)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusAccepted, resp.StatusCode, "valid SSTP wake-up must be accepted")

			// 2. Invalid token is rejected.
			req, _ = http.NewRequest(http.MethodPost, instance.ts.URL+tc.path, bytes.NewReader(body))
			req.Header.Set("Authorization", "Bearer invalid-token")
			resp, err = instance.client.Do(req)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "invalid token must be rejected")

			// 3. Missing authorization is rejected.
			req, _ = http.NewRequest(http.MethodPost, instance.ts.URL+tc.path, bytes.NewReader(body))
			resp, err = instance.client.Do(req)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "missing auth must be rejected")
		})
	}
}
