package server

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/i2-open/i2goSignals/pkg/dao/memory"
	"github.com/i2-open/i2goSignals/pkg/services"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/i2-open/i2goSignals/pkg/tlsSupport"
)

// TestReceiverVerifyAndStatusHonourTLSFloor extends the #324 TLS-floor
// coverage (internal/server/test/receiver_management_tls_floor_test.go) to the
// verification and status-check dials of the push and poll receivers: an
// http:// transmitter URL is refused unless the stream carries the
// tx_allow_plaintext grant, and an https:// URL is unaffected by the grant.
// "Dialed" is observed as a new TCP connection to the management server.
func TestReceiverVerifyAndStatusHonourTLSFloor(t *testing.T) {
	t.Setenv("I2SIG_RCV_VERIFY_ON_ESTABLISH", "true")
	sa := &SignalsApplication{ServerService: services.NewServerService(memory.NewServerDAO())}

	sites := []struct {
		name  string
		drive func(ctx context.Context, state *model.StreamStateRecord, mgmtURL string) error
	}{
		{"poll-status", func(ctx context.Context, state *model.StreamStateRecord, mgmtURL string) error {
			ps := &ClientPollStream{sa: sa, stream: state, ctx: ctx, statusUrl: mgmtURL + "/status"}
			_, err := ps.checkTransmitterStatus(ctx)
			return err
		}},
		{"push-status", func(ctx context.Context, state *model.StreamStateRecord, mgmtURL string) error {
			rps := &ReceiverPushStream{sa: sa, stream: state, ctx: ctx, statusUrl: mgmtURL + "/status"}
			_, err := rps.checkTransmitterStatus(ctx)
			return err
		}},
		{"poll-verify", func(ctx context.Context, state *model.StreamStateRecord, mgmtURL string) error {
			ps := &ClientPollStream{sa: sa, stream: state, ctx: ctx, verifyUrl: mgmtURL + "/verify"}
			ps.initiateVerification()
			return nil
		}},
		{"push-verify", func(ctx context.Context, state *model.StreamStateRecord, mgmtURL string) error {
			// The status URL stays unresolvable so a failed verification's
			// status-check fallback cannot dial the server itself.
			rps := &ReceiverPushStream{sa: sa, stream: state, ctx: ctx, verifyUrl: mgmtURL + "/verify"}
			rps.initiateVerification()
			return nil
		}},
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

				remoteId := "TX-REMOTE-324"
				token := "tx-static-token"
				state := &model.StreamStateRecord{
					StreamConfiguration: model.StreamConfiguration{
						Id:               "local-324",
						TxAllowPlaintext: tc.allowPlain,
						TxToken:          &token,
						RemoteStreamId:   &remoteId,
					},
				}

				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				err := site.drive(ctx, state, mgmt.URL)

				dialed := atomic.LoadInt32(&conns) > 0
				assert.Equal(t, tc.wantDialed, dialed,
					"management URL %s (tx_allow_plaintext=%v) dialed=%v", mgmt.URL, tc.allowPlain, dialed)
				if !tc.wantDialed && err != nil {
					assert.True(t, errors.Is(err, tlsSupport.ErrPlaintextNotAllowed), "refusal must surface ErrPlaintextNotAllowed, got %v", err)
				}
			})
		}
	}
}

// TestTransmitterStatusRegisteredServerHonoursTLSFloor covers the status check
// through a registered (TxAlias) server, whose status endpoint comes from its
// cached SSF metadata rather than the stream.
func TestTransmitterStatusRegisteredServerHonoursTLSFloor(t *testing.T) {
	var conns int32
	mgmt := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	mgmt.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			atomic.AddInt32(&conns, 1)
		}
	}
	mgmt.Start()
	defer mgmt.Close()

	server := &model.Server{Alias: "tx", Host: mgmt.URL,
		ServerConfiguration: &model.TransmitterConfiguration{StatusEndpoint: mgmt.URL + "/status"}}
	conf := &model.StreamConfiguration{Id: "local-324"}

	_, err := transmitterStatus(context.Background(), http.DefaultClient, server, conf, func() string { return "" })
	require.ErrorIs(t, err, tlsSupport.ErrPlaintextNotAllowed)
	assert.Zero(t, atomic.LoadInt32(&conns), "a plaintext status endpoint must not be dialed without the grant")
}
