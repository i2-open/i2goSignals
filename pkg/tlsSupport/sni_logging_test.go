package tlsSupport

import (
	"bytes"
	"crypto/tls"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestSNILogging(t *testing.T) {
	// Setup a buffer to capture logs
	var buf bytes.Buffer
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	slog.SetDefault(slog.New(handler))

	// Mock environment variables for TLS
	t.Setenv("TLS_ENABLED", "true")
	t.Setenv("SERVER_CERT_PATH", "../../config/certs/server-cert.pem")
	t.Setenv("SERVER_KEY_PATH", "../../config/certs/server-key.pem")

	server := &http.Server{
		Addr: "127.0.0.1:0",
	}

	enabled, err := InitTransportLayerSecurity(server)
	if err != nil {
		t.Fatalf("Failed to init TLS: %v", err)
	}
	if !enabled {
		t.Fatal("TLS should be enabled")
	}

	// Create a listener
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func(ln net.Listener) {
		_ = ln.Close()
	}(ln)
	server.Addr = ln.Addr().String()

	go func() {
		_ = server.ServeTLS(ln, "", "")
	}()
	defer func(server *http.Server) {
		_ = server.Close()
	}(server)

	time.Sleep(100 * time.Millisecond)

	// Attempt a connection with SNI
	conf := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "test.example.com",
	}

	conn, err := tls.Dial("tcp", ln.Addr().String(), conf)
	if err != nil {
		// Handshake might fail due to cert issues, but we want to see if it started and logged SNI
		t.Logf("Dial failed as expected or not: %v", err)
	} else {
		_ = conn.Close()
	}

	time.Sleep(100 * time.Millisecond)

	output := buf.String()
	t.Logf("Captured log output:\n%s", output)

	if !strings.Contains(output, "TLS handshake started") {
		t.Error("Expected log to contain 'TLS handshake started'")
	}
	if !strings.Contains(output, "sni=test.example.com") {
		t.Error("Expected log to contain 'sni=test.example.com'")
	}
}
