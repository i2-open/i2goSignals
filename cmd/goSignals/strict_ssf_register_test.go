package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/i2-open/i2goSignals/pkg/ssfModels"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// strictRegisterCLI builds a minimal CLI + a single server whose Host and
// ConfigurationEndpoint point at handlerURL. strict controls the server's
// StrictSsf posture. ClientToken is set so executeCreateRequest emits a bearer
// and does not short-circuit on the no-credential branch.
func strictRegisterCLI(t *testing.T, handlerURL string, strict bool) (*CLI, *SsfServer) {
	t.Helper()
	dir := t.TempDir()
	g := Globals{ConfigFile: filepath.Join(dir, "config.json")}

	server := SsfServer{
		Alias:       "strict-tx",
		Host:        handlerURL,
		ClientToken: "admin-token",
		Streams:     map[string]Stream{},
		ServerConfiguration: &model.TransmitterConfiguration{
			ConfigurationEndpoint: handlerURL + "/stream",
		},
		StrictSsf: strict,
	}

	cli := &CLI{}
	cli.Globals = g
	cli.Data = ConfigData{
		Selected: "strict-tx",
		Servers:  map[string]SsfServer{"strict-tx": server},
	}
	stored := cli.Data.Servers["strict-tx"]
	return cli, &stored
}

// TestExecuteCreateRequest_StrictWarnAndDrop pins the CLI production caller: a
// publisher-leg create against a strict server must strip operator-asserted
// iss/aud/issuerJWKSUrl from the wire body (SSF §8.1.1.1) AND emit a
// user-visible warn-and-drop message. This drives the REAL executeCreateRequest
// path, not stripTransmitterSupplied in isolation.
func TestExecuteCreateRequest_StrictWarnAndDrop(t *testing.T) {
	var body model.StreamConfiguration
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
		body.Id = "remote-strict-1"
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	}))
	defer ts.Close()

	cli, server := strictRegisterCLI(t, ts.URL, true)

	reg := model.StreamConfiguration{
		Iss:           "https://operator-issuer.example.com",
		Aud:           []string{"https://operator-aud.example.com"},
		IssuerJWKSUrl: "https://operator-issuer.example.com/jwks.json",
		Delivery: &model.OneOfStreamConfigurationDelivery{
			PollTransmitMethod: &model.PollTransmitMethod{Method: model.DeliveryPoll},
		},
	}

	out := captureStdout(t, func() {
		_, err := cli.executeCreateRequest("strictstream", reg, server, "Poll Publisher", "")
		require.NoError(t, err)
	})

	// Wire body the strict server received must carry NO transmitter-owned fields.
	assert.Equal(t, "", body.Iss, "Iss must be stripped on strict publisher-leg POST")
	assert.Empty(t, body.Aud, "Aud must be stripped on strict publisher-leg POST")
	assert.Equal(t, "", body.IssuerJWKSUrl, "IssuerJWKSUrl must be stripped on strict publisher-leg POST")

	// And the operator must have been told.
	assert.Contains(t, out, "strict-ssf", "warn-and-drop message must mention strict-ssf")
	assert.Contains(t, out, "iss", "warn-and-drop must name the dropped iss value")
	assert.Contains(t, out, "aud", "warn-and-drop must name the dropped aud value")
}

// TestExecuteCreateRequest_FlexibleNoWarn confirms the non-strict counterpart:
// operator-asserted iss/aud reach the server unchanged and no warn-and-drop
// message is emitted.
func TestExecuteCreateRequest_FlexibleNoWarn(t *testing.T) {
	var body model.StreamConfiguration
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
		body.Id = "remote-flex-1"
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	}))
	defer ts.Close()

	cli, server := strictRegisterCLI(t, ts.URL, false)

	reg := model.StreamConfiguration{
		Iss: "https://operator-issuer.example.com",
		Aud: []string{"https://operator-aud.example.com"},
		Delivery: &model.OneOfStreamConfigurationDelivery{
			PollTransmitMethod: &model.PollTransmitMethod{Method: model.DeliveryPoll},
		},
	}

	out := captureStdout(t, func() {
		_, err := cli.executeCreateRequest("flexstream", reg, server, "Poll Publisher", "")
		require.NoError(t, err)
	})

	assert.Equal(t, "https://operator-issuer.example.com", body.Iss, "Iss preserved for flexible server")
	assert.Equal(t, []string{"https://operator-aud.example.com"}, body.Aud, "Aud preserved for flexible server")
	assert.False(t, strings.Contains(out, "strict-ssf"), "no warn-and-drop for flexible server")
}
