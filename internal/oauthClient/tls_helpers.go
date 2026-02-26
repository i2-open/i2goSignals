package oauthClient

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/i2-open/i2goSignals/internal/model"
)

// CertificateInfo holds displayable information about a TLS certificate
type CertificateInfo struct {
	Subject      string    `json:"subject"`
	Issuer       string    `json:"issuer"`
	ValidFrom    time.Time `json:"validFrom"`
	ValidTo      time.Time `json:"validTo"`
	Fingerprint  string    `json:"fingerprint"` // SHA-256 hex
	PEM          string    `json:"pem"`
	SerialNumber string    `json:"serialNumber"`
	DNSNames     []string  `json:"dnsNames"`
	IPAddresses  []string  `json:"ipAddresses"`
}

// ExtractServerCertificate connects to the given URL and retrieves the server's
// certificate without validating it. Returns the first certificate in the chain.
func ExtractServerCertificate(hostURL string) (*x509.Certificate, error) {
	// Parse the URL to get host:port
	host, port, err := parseHostPort(hostURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	// Connect with InsecureSkipVerify to retrieve the certificate
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 10 * time.Second},
		"tcp",
		net.JoinHostPort(host, port),
		&tls.Config{InsecureSkipVerify: true},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to connect: %w", err)
	}
	defer conn.Close()

	// Get the peer certificates
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates received from server")
	}

	return certs[0], nil
}

// ParseCertificateInfo extracts displayable information from a certificate
func ParseCertificateInfo(cert *x509.Certificate) *CertificateInfo {
	// Calculate SHA-256 fingerprint
	fingerprint := sha256.Sum256(cert.Raw)
	fingerprintHex := hex.EncodeToString(fingerprint[:])

	// Format fingerprint with colons for readability
	formatted := ""
	for i := 0; i < len(fingerprintHex); i += 2 {
		if i > 0 {
			formatted += ":"
		}
		formatted += fingerprintHex[i : i+2]
	}

	// Encode to PEM
	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}
	pemData := pem.EncodeToMemory(pemBlock)

	// Extract IP addresses as strings
	ipAddresses := make([]string, len(cert.IPAddresses))
	for i, ip := range cert.IPAddresses {
		ipAddresses[i] = ip.String()
	}

	return &CertificateInfo{
		Subject:      cert.Subject.String(),
		Issuer:       cert.Issuer.String(),
		ValidFrom:    cert.NotBefore,
		ValidTo:      cert.NotAfter,
		Fingerprint:  formatted,
		PEM:          string(pemData),
		SerialNumber: cert.SerialNumber.String(),
		DNSNames:     cert.DNSNames,
		IPAddresses:  ipAddresses,
	}
}

// ParsePEMCertificate parses a PEM-encoded certificate string
func ParsePEMCertificate(pemData string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block")
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("PEM block is not a certificate (type: %s)", block.Type)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, nil
}

// CreateCertPool creates a certificate pool with the given PEM-encoded certificate
func CreateCertPool(pemCert string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(pemCert)) {
		return nil, fmt.Errorf("failed to add certificate to pool")
	}
	return pool, nil
}

// parseHostPort extracts host and port from a URL string
// Returns host, port, error
func parseHostPort(urlStr string) (string, string, error) {
	// Simple parsing - expects format like "https://host:port" or "host:port"
	// Remove protocol if present
	if len(urlStr) > 8 && urlStr[0:8] == "https://" {
		urlStr = urlStr[8:]
	} else if len(urlStr) > 7 && urlStr[0:7] == "http://" {
		urlStr = urlStr[7:]
	}

	// Remove path if present
	if idx := len(urlStr); idx > 0 {
		for i, c := range urlStr {
			if c == '/' {
				idx = i
				break
			}
		}
		urlStr = urlStr[0:idx]
	}

	// Split host and port
	host, port, err := net.SplitHostPort(urlStr)
	if err != nil {
		// No port specified, use default based on protocol
		host = urlStr
		port = "443" // default to HTTPS port
	}

	return host, port, nil
}

// GetTlsConfigForServer returns a TLS configuration for the given server and allows support of a self-signed key or
// administrative override to skip verification
func GetTlsConfigForServer(server *model.Server) *tls.Config {
	if server == nil {
		return &tls.Config{}
	}

	// If no custom TLS config needed, return default client
	if server.TLSCertificate == "" && !server.TLSSkipVerify {
		return &tls.Config{}
	}

	// Build custom TLS config
	tlsConfig := &tls.Config{}

	if server.TLSSkipVerify {
		tlsConfig.InsecureSkipVerify = true
		clientLog.Warn("Using InsecureSkipVerify for server", "alias", server.Alias)
	} else if server.TLSCertificate != "" {
		// Create a cert pool with the stored certificate
		certPool, err := CreateCertPool(server.TLSCertificate)
		if err != nil {
			clientLog.Error("Failed to create cert pool, falling back to default",
				"alias", server.Alias, "error", err)
			return tlsConfig
		}
		tlsConfig.RootCAs = certPool
		clientLog.Debug("Using custom certificate for server", "alias", server.Alias)
	}

	return tlsConfig
}

// GetBaseHTTPClientForServer returns an http.Client configured with the appropriate TLS settings
// for the given server. This should be used as the base client for all HTTP requests to a server.
func GetBaseHTTPClientForServer(server *model.Server) *http.Client {
	tlsConfig := GetTlsConfigForServer(server)

	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
		Timeout: 30 * time.Second,
	}
}
