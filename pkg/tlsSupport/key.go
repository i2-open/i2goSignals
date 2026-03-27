package tlsSupport

import (
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"net/http"
	"os"
	"strings"
)

func InitTransportLayerSecurity(app *http.Server) (bool, error) {
	if found := stripQuotes(os.Getenv("TLS_ENABLED")); strings.ToLower(found) == "true" {
		certFile, keyFile := GetCertKeyPaths()
		cert, certErr := os.ReadFile(certFile)
		if certErr != nil {
			return false, certErr
		}
		key, keyErr := os.ReadFile(keyFile)
		if keyErr != nil {
			return false, keyErr
		}
		pair, pairErr := tls.X509KeyPair(cert, key)
		if pairErr != nil {
			return false, pairErr
		}
		app.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{pair},
			GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
				slog.Debug("TLS handshake started", "sni", hello.ServerName, "remote", hello.Conn.RemoteAddr())
				return nil, nil
			},
		}
		return true, nil
	}
	return false, nil
}

func GetCertKeyPaths() (certFile string, keyFile string) {
	serverKeyPath := os.Getenv(EnvServerKey)
	if serverKeyPath == "" {
		serverKeyPath = "config/certs/server-key.pem"
	}

	serverCertPath := os.Getenv(EnvServerCert)
	if serverCertPath == "" {
		serverCertPath = "config/certs/server-cert.pem"
	}
	return serverCertPath, serverKeyPath
}

const (
	EnvServerKey    = "SERVER_KEY_PATH"
	EnvServerCert   = "SERVER_CERT_PATH"
	EnvCertCaPubKey = "CERT_CA_PUB_KEY"
	EnvCaCert       = "CA_CERT"
)

// stripQuotes removes surrounding double or single quotes from a string
func stripQuotes(s string) string {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

// CheckCaInstalled will check if a CA certificate has been installed in the http.Client or if nil, the system cert pool
func CheckCaInstalled(client *http.Client) {
	// Note; this is not tested because we don't want to install temporary test certs.
	caCertPath := os.Getenv(EnvCertCaPubKey)
	if caCertPath == "" {
		caCertPath = os.Getenv(EnvCaCert)
	}
	if caCertPath == "" {
		caCertPath = "config/certs/ca-cert.pem"
	}

	if caCertPath != "" {
		caCertPem, err := os.ReadFile(caCertPath)
		if err != nil {
			if !os.IsNotExist(err) {
				slog.Warn("Error reading CA certificate: " + err.Error())
			}
			return
		}
		var caPool *x509.CertPool
		if client != nil {
			slog.Debug("Installing CA certificate into HTTP client", "file", caCertPath)
			caPool = x509.NewCertPool()
			t := &http.Transport{
				TLSClientConfig: &tls.Config{RootCAs: caPool},
			}
			client.Transport = t
		} else {
			slog.Debug("Installing CA certificate into default transport", "file", caCertPath)
			caPool, _ = x509.SystemCertPool()
			if caPool == nil {
				caPool = x509.NewCertPool()
			}
			if t, ok := http.DefaultTransport.(*http.Transport); ok {
				if t.TLSClientConfig == nil {
					t.TLSClientConfig = &tls.Config{}
				}
				t.TLSClientConfig.RootCAs = caPool
			}
		}
		ok := caPool.AppendCertsFromPEM(caCertPem)
		if !ok {
			slog.Error("Error loading CA PEM")
		}

	}
}
