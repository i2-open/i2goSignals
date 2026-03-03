package server

import (
	"bytes"
	"crypto/tls"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

type safeBuffer struct {
	buf bytes.Buffer
	mu  sync.Mutex
}

func (s *safeBuffer) Write(p []byte) (n int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *safeBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

func TestTLSHandshakeErrorLogging(t *testing.T) {
	var buf safeBuffer
	// Create a handler that writes to our buffer
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelError})

	// Create a listener
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func(ln net.Listener) {
		_ = ln.Close()
	}(ln)

	server := &http.Server{
		Addr:     ln.Addr().String(),
		ErrorLog: slog.NewLogLogger(handler, slog.LevelError),
	}

	go func() {
		// Using relative paths to the certs from pkg/goSignals/server
		_ = server.ServeTLS(ln, "../../../config/certs/server-cert.pem", "../../../config/certs/server-key.pem")
	}()
	defer func(server *http.Server) {
		_ = server.Close()
	}(server)

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	// Attempt a connection that will fail the TLS handshake
	// For example, a client that doesn't trust the self-signed CA or just sends junk
	conf := &tls.Config{
		InsecureSkipVerify: false, // This will fail because we don't provide the CA
	}

	conn, err := tls.Dial("tcp", ln.Addr().String(), conf)
	if err == nil {
		_ = conn.Close()
		t.Log("Expected TLS handshake error, but it succeeded")
	}

	// Wait a bit for the error to be logged by the server
	time.Sleep(200 * time.Millisecond)

	output := buf.String()
	if output == "" {
		// If nothing logged yet, try sending junk
		rawConn, _ := net.Dial("tcp", ln.Addr().String())
		if rawConn != nil {
			_, _ = rawConn.Write([]byte("NOT A TLS HANDSHAKE"))
			_ = rawConn.Close()
		}
		time.Sleep(200 * time.Millisecond)
		output = buf.String()
	}

	t.Logf("Captured log output:\n%s", output)

	// We expect to see something like "http: TLS handshake error" in the log
	if !strings.Contains(output, "http: TLS handshake error") {
		t.Errorf("Expected log to contain 'http: TLS handshake error', got: %s", output)
	}

	// Also check if it has the level=ERROR from our slog handler
	if !strings.Contains(output, "level=ERROR") {
		t.Errorf("Expected log to contain 'level=ERROR', got: %s", output)
	}
}
