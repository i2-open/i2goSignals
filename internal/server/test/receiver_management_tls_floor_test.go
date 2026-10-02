package test

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestReceiverManagementHonoursTLSFloor pins the business-stream TLS floor
// (#322) on the receiver-management dial sites in api_receiver.go (#324): the
// cascade DELETE and the management exercise (read/update/replace/status) must
// refuse an http:// transmitter management URL unless the stream carries the
// tx_allow_plaintext grant, and an https:// URL is unaffected by the grant.
//
// "Dialed" is observed as a new TCP connection to the management server, so the
// https case holds whether or not the client trusts the test certificate.
func TestReceiverManagementHonoursTLSFloor(t *testing.T) {
	t.Setenv("I2SIG_RCV_MANAGEMENT_EXERCISE", "true")

	instance, err := createServer(t, "receiver_mgmt_tls_floor_test", true)
	require.NoError(t, err)
	defer instance.app.Shutdown()

	sites := []struct {
		name  string
		drive func(ctx context.Context, state *model.StreamStateRecord)
	}{
		{"cascade-delete", instance.app.CascadeReceiverStreamDelete},
		{"management-exercise", instance.app.ExerciseReceiverManagement},
	}
	cases := []struct {
		name       string
		useTLS     bool
		allowPlain bool
		wantDialed bool
	}{
		{"http-refused-without-grant", false, false, false},
		{"http-dialed-with-grant", false, true, true},
		{"https-dialed-without-grant", true, false, true},
	}

	for _, site := range sites {
		for _, tc := range cases {
			t.Run(site.name+"/"+tc.name, func(t *testing.T) {
				var conns int32
				mgmt := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusNoContent)
				}))
				mgmt.Config.ConnState = func(_ net.Conn, s http.ConnState) {
					if s == http.StateNew {
						atomic.AddInt32(&conns, 1)
					}
				}
				if tc.useTLS {
					mgmt.StartTLS()
				} else {
					mgmt.Start()
				}
				defer mgmt.Close()

				// The well-known document (discovery is outside this guard)
				// advertises the management endpoints on the mgmt server.
				wk := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(model.TransmitterConfiguration{
						Issuer:                "https://tx.example.test",
						ConfigurationEndpoint: mgmt.URL + "/streams",
						StatusEndpoint:        mgmt.URL + "/status",
					})
				}))
				defer wk.Close()

				wkURL := wk.URL
				remoteId := "TX-REMOTE-324"
				token := "tx-static-token"
				state := &model.StreamStateRecord{
					StreamConfiguration: model.StreamConfiguration{
						Id:               "local-324",
						TxAllowPlaintext: tc.allowPlain,
						Iss:              "https://tx.example.test",
						TxWellKnownUrl:   &wkURL,
						TxToken:          &token,
						RemoteStreamId:   &remoteId,
						Delivery: &model.OneOfStreamConfigurationDelivery{
							PollReceiveMethod: &model.PollReceiveMethod{
								Method:      model.ReceivePoll,
								EndpointUrl: "https://tx.example.test/poll",
							},
						},
					},
				}

				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				site.drive(ctx, state)

				dialed := atomic.LoadInt32(&conns) > 0
				assert.Equal(t, tc.wantDialed, dialed,
					"management URL %s (tx_allow_plaintext=%v) dialed=%v", mgmt.URL, tc.allowPlain, dialed)
			})
		}
	}
}
