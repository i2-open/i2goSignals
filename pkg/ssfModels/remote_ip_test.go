package model

import (
	"crypto/tls"
	"net/http"
	"testing"
)

func TestBuildRemoteIPFromRequest_NoTLS_NoForwarded(t *testing.T) {
	r, _ := http.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.1:1234"

	got := BuildRemoteIPFromRequest(r)

	if got.Protocol != "http" {
		t.Errorf("expected protocol http, got %s", got.Protocol)
	}
	if got.IP != "10.0.0.1:1234" {
		t.Errorf("expected IP 10.0.0.1:1234, got %s", got.IP)
	}
	if got.Forwarded != "" {
		t.Errorf("expected empty Forwarded, got %s", got.Forwarded)
	}
}

func TestBuildRemoteIPFromRequest_WithTLS(t *testing.T) {
	r, _ := http.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.2:443"
	r.TLS = &tls.ConnectionState{}

	got := BuildRemoteIPFromRequest(r)

	if got.Protocol != "https" {
		t.Errorf("expected protocol https, got %s", got.Protocol)
	}
	if got.IP != "10.0.0.2:443" {
		t.Errorf("expected IP 10.0.0.2:443, got %s", got.IP)
	}
}

func TestBuildRemoteIPFromRequest_XForwardedFor(t *testing.T) {
	r, _ := http.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.3:80"
	r.Header.Set("X-Forwarded-For", "203.0.113.5, 198.51.100.1")

	got := BuildRemoteIPFromRequest(r)

	if got.Forwarded != "203.0.113.5, 198.51.100.1" {
		t.Errorf("expected X-Forwarded-For value, got %s", got.Forwarded)
	}
}

func TestBuildRemoteIPFromRequest_XRealIPFallback(t *testing.T) {
	r, _ := http.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.4:80"
	r.Header.Set("X-Real-IP", "203.0.113.9")

	got := BuildRemoteIPFromRequest(r)

	if got.Forwarded != "203.0.113.9" {
		t.Errorf("expected X-Real-IP as fallback, got %s", got.Forwarded)
	}
}

func TestBuildRemoteIPFromRequest_XForwardedForTakesPrecedence(t *testing.T) {
	r, _ := http.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.5:80"
	r.Header.Set("X-Forwarded-For", "203.0.113.10")
	r.Header.Set("X-Real-IP", "203.0.113.99")

	got := BuildRemoteIPFromRequest(r)

	if got.Forwarded != "203.0.113.10" {
		t.Errorf("expected X-Forwarded-For to take precedence, got %s", got.Forwarded)
	}
}

func TestBuildOutboundRemoteIP(t *testing.T) {
	got := BuildOutboundRemoteIP("https", "192.168.1.1:8080")

	if got.Protocol != "https" {
		t.Errorf("expected protocol https, got %s", got.Protocol)
	}
	if got.IP != "192.168.1.1:8080" {
		t.Errorf("expected IP 192.168.1.1:8080, got %s", got.IP)
	}
	if got.Forwarded != "" {
		t.Errorf("expected empty Forwarded for outbound, got %s", got.Forwarded)
	}
}
