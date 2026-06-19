package test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/i2-open/i2goSignals/pkg/authSupport"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestReceiverUsesStreamTLSSettingsForDiscovery locks down the receiver-outbound
// TLS contract (commits 56887c2 + 68d9325): when a receiver stream is registered
// with tx_tls_skip_verify=true the SUT-initiated discovery (well-known) and
// issuer JWKS GETs must honor that setting on the outbound http.Client, so the
// receiver can attach to a transmitter presenting a self-signed certificate.
// Without the setting the same calls must fail at the TLS layer — the OpenID SSF
// conformance suite's transmitter is self-signed, so a regression here silently
// breaks every receiver-flow conformance plan against it.
func TestReceiverUsesStreamTLSSettingsForDiscovery(t *testing.T) {
	// Ensure the deployment-wide default does not mask the per-stream setting:
	// the negative case relies on TxTLSSkipVerify=false actually meaning verify.
	t.Setenv("I2SIG_TX_TLS_SKIP_VERIFY", "")

	var mu sync.Mutex
	wellKnownHits := 0
	jwksHits := 0

	// Self-signed TLS server acting as the foreign transmitter. The
	// httptest-generated cert is signed by an ephemeral CA the system roots do
	// not trust, so any client without InsecureSkipVerify (or an explicit cert
	// pin) fails at the TLS handshake before any HTTP request is made.
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/.well-known/ssf-configuration"):
			mu.Lock()
			wellKnownHits++
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(model.TransmitterConfiguration{
				Issuer:                "https://tx.example.test",
				JwksUri:               "https://tx.example.test/jwks",
				ConfigurationEndpoint: "https://tx.example.test/stream",
				StatusEndpoint:        "https://tx.example.test/status",
				VerificationEndpoint:  "https://tx.example.test/verify",
			})
		case r.URL.Path == "/jwks":
			mu.Lock()
			jwksHits++
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"keys":[]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	instance, err := createServer(t, "receiver_tls_settings_test", true)
	require.NoError(t, err)
	defer instance.app.Shutdown()

	wellKnownURL := ts.URL + "/.well-known/ssf-configuration"
	jwksURL := ts.URL + "/jwks"

	t.Run("skip-verify true allows discovery and JWKS against self-signed transmitter", func(t *testing.T) {
		mu.Lock()
		wellKnownHits = 0
		jwksHits = 0
		mu.Unlock()

		token := "tx-token"
		remote := "tx-stream-1"
		streamConfig := model.StreamConfiguration{
			Iss:             "https://tx.example.test",
			Aud:             []string{"https://receiver.example.test"},
			EventsRequested: []string{"*"},
			IssuerJWKSUrl:   jwksURL,
			TxWellKnownUrl:  &wellKnownURL,
			TxToken:         &token,
			RemoteStreamId:  &remote, // suppress auto-registration POST
			TxTLSSkipVerify: true,    // the contract under test
			Delivery: &model.OneOfStreamConfigurationDelivery{
				PollReceiveMethod: &model.PollReceiveMethod{
					Method:      model.ReceivePoll,
					EndpointUrl: ts.URL + "/poll",
					PollConfig:  &model.PollParameters{ReturnImmediately: true},
				},
			},
		}

		created, err := instance.CreateStream(streamConfig, authSupport.ConvertProject(instance.projectId))
		require.NoError(t, err, "discovery + JWKS GET against a self-signed transmitter must succeed when tx_tls_skip_verify=true")
		assert.True(t, created.TxTLSSkipVerify, "per-stream tx_tls_skip_verify must persist onto the stream")

		// Sanity: stream should be enabled (no permanent JWKS error). A TLS
		// failure during loadJwksForReceiver would have flipped this to
		// disabled.
		state, err := instance.GetStreamState(created.Id)
		require.NoError(t, err)
		assert.NotEqual(t, model.StreamStateDisable, state.Status,
			"stream must not be disabled by a JWKS load error when tx_tls_skip_verify=true")

		mu.Lock()
		defer mu.Unlock()
		assert.GreaterOrEqual(t, wellKnownHits, 1,
			"CreateStream must fetch /.well-known/ssf-configuration through the stream's TLS settings")
		assert.GreaterOrEqual(t, jwksHits, 1,
			"CreateStream must fetch the issuer JWKS through the stream's TLS settings")

		_ = instance.DeleteStream(created.Id)
	})

	t.Run("skip-verify false fails TLS against a self-signed transmitter", func(t *testing.T) {
		mu.Lock()
		wellKnownHits = 0
		jwksHits = 0
		mu.Unlock()

		token := "tx-token"
		remote := "tx-stream-2"
		streamConfig := model.StreamConfiguration{
			Iss:             "https://tx.example.test",
			Aud:             []string{"https://receiver.example.test"},
			EventsRequested: []string{"*"},
			IssuerJWKSUrl:   jwksURL,
			TxWellKnownUrl:  &wellKnownURL,
			TxToken:         &token,
			RemoteStreamId:  &remote,
			TxTLSSkipVerify: false, // explicit: verify against system roots
			Delivery: &model.OneOfStreamConfigurationDelivery{
				PollReceiveMethod: &model.PollReceiveMethod{
					Method:      model.ReceivePoll,
					EndpointUrl: ts.URL + "/poll",
					PollConfig:  &model.PollParameters{ReturnImmediately: true},
				},
			},
		}

		_, err := instance.CreateStream(streamConfig, authSupport.ConvertProject(instance.projectId))
		require.Error(t, err,
			"CreateStream must fail the well-known fetch when tx_tls_skip_verify=false against a self-signed transmitter")

		mu.Lock()
		defer mu.Unlock()
		assert.Equal(t, 0, wellKnownHits,
			"the well-known fetch must not reach the transmitter at all — TLS verify rejects the handshake first")
	})
}
