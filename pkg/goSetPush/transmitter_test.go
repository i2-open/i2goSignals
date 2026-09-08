package goSetPush

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// TestPushSET_ReusesConnectionsAcrossCalls guards the shared default client:
// consecutive pushes to the same receiver must ride one pooled keep-alive
// connection rather than dial (and TLS-handshake) per event.
func TestPushSET_ReusesConnectionsAcrossCalls(t *testing.T) {
	var newConns atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	srv.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			newConns.Add(1)
		}
	}
	srv.StartTLS()
	defer srv.Close()

	const pushes = 5
	for i := 0; i < pushes; i++ {
		res := PushSET(context.Background(), "token", TransmitterConfig{
			EndpointURL:        srv.URL,
			InsecureSkipVerify: true,
		})
		if !res.Accepted {
			t.Fatalf("push %d: expected accepted, got status=%d err=%v", i, res.StatusCode, res.Err)
		}
	}
	if got := newConns.Load(); got != 1 {
		t.Fatalf("expected %d pushes to share 1 connection, server saw %d new connections", pushes, got)
	}
}
