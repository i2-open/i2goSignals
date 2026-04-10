package tlsSupport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
)

func InitTransportLayerSecurity(app *http.Server) (io.Closer, bool, error) {
	tlsEnabled := stripQuotes(os.Getenv("TLS_ENABLED")) == "true"
	spiffeEnabled := SpiffeEnabled()

	if !tlsEnabled && !spiffeEnabled {
		return nil, false, nil
	}

	var closer io.Closer
	var fileCert *tls.Certificate

	if tlsEnabled {
		certFile, keyFile := GetCertKeyPaths()
		cert, certErr := os.ReadFile(certFile)
		if certErr != nil {
			return nil, false, certErr
		}
		key, keyErr := os.ReadFile(keyFile)
		if keyErr != nil {
			return nil, false, keyErr
		}
		pair, pairErr := tls.X509KeyPair(cert, key)
		if pairErr != nil {
			return nil, false, pairErr
		}
		fileCert = &pair
	}

	if spiffeEnabled {
		spiffeCtx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		x509Source, err := NewX509Source(spiffeCtx)
		if err != nil {
			slog.Warn("SPIFFE enabled but X509Source failed; falling back to file-based TLS", "error", err)
		} else {
			closer = x509Source
			spiffeGetCert := tlsconfig.GetCertificate(x509Source)

			app.TLSConfig = &tls.Config{
				MinVersion: tls.VersionTLS12,
				ClientAuth: tls.RequestClientCert,
				GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
					slog.Debug("TLS handshake started", "sni", hello.ServerName, "remote", hello.Conn.RemoteAddr())

					// If we have a file-based cert and the SNI matches a local/host name, prefer it.
					// This allows browsers on the host (hitting localhost) to use the trusted-ish file cert.
					if fileCert != nil {
						switch hello.ServerName {
						case "localhost", "127.0.0.1", "::1":
							return fileCert, nil
						}
					}

					// Otherwise, prefer the SPIFFE SVID. Internal workloads (like scim_cluster1)
					// will expect this and trust it via the SPIRE CA.
					return spiffeGetCert(hello)
				},
				VerifyPeerCertificate: func(_ [][]byte, _ [][]*x509.Certificate) error {
					// Allow all certs through the handshake; handlers must authorize.
					return nil
				},
			}
			return closer, true, nil
		}
	}

	// SPIFFE not available or failed; use file-based TLS if enabled.
	if fileCert != nil {
		app.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{*fileCert},
			GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
				slog.Debug("TLS handshake started (file-based)", "sni", hello.ServerName, "remote", hello.Conn.RemoteAddr())
				return nil, nil
			},
		}
		return nil, true, nil
	}

	return nil, false, nil
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

// GetGlobalCertPool returns a cert pool containing the CA certificate found via standard env vars
// (CERT_CA_PUB_KEY, CA_CERT, then any extraEnvVars), falling back to "config/certs/ca-cert.pem".
// Returns the system cert pool (augmented with the CA cert) if found.
func GetGlobalCertPool(extraEnvVars ...string) *x509.CertPool {
	envVars := []string{EnvCertCaPubKey, EnvCaCert}
	envVars = append(envVars, extraEnvVars...)

	caCertPath := ""
	for _, env := range envVars {
		if v := os.Getenv(env); v != "" {
			caCertPath = v
			break
		}
	}
	if caCertPath == "" {
		caCertPath = "config/certs/ca-cert.pem"
	}

	caPool, _ := x509.SystemCertPool()
	if caPool == nil {
		caPool = x509.NewCertPool()
	}

	caCertPem, err := os.ReadFile(caCertPath)
	if err != nil {
		if !os.IsNotExist(err) {
			slog.Warn("Error reading CA certificate: " + err.Error())
		}
		return caPool
	}
	if ok := caPool.AppendCertsFromPEM(caCertPem); !ok {
		slog.Error("Error loading CA PEM from " + caCertPath)
	} else {
		slog.Debug("Loaded global CA certificate", "file", caCertPath)
	}
	return caPool
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

		if client != nil {
			if t, ok := client.Transport.(*http.Transport); ok {
				if t.TLSClientConfig == nil {
					t.TLSClientConfig = &tls.Config{}
				}
				if t.TLSClientConfig.RootCAs == nil {
					t.TLSClientConfig.RootCAs = x509.NewCertPool()
				}
				slog.Debug("Installing CA certificate into HTTP client's existing transport", "file", caCertPath)
				t.TLSClientConfig.RootCAs.AppendCertsFromPEM(caCertPem)
			} else if client.Transport == nil {
				slog.Debug("Installing CA certificate into HTTP client's new transport", "file", caCertPath)
				caPool := x509.NewCertPool()
				caPool.AppendCertsFromPEM(caCertPem)
				client.Transport = &http.Transport{
					TLSClientConfig: &tls.Config{RootCAs: caPool},
				}
			} else {
				slog.Warn("HTTP client has non-standard transport, skipping CA installation")
			}
		} else {
			slog.Debug("Installing CA certificate into default transport", "file", caCertPath)
			caPool, _ := x509.SystemCertPool()
			if caPool == nil {
				caPool = x509.NewCertPool()
			}
			if t, ok := http.DefaultTransport.(*http.Transport); ok {
				if t.TLSClientConfig == nil {
					t.TLSClientConfig = &tls.Config{}
				}
				if t.TLSClientConfig.RootCAs == nil {
					t.TLSClientConfig.RootCAs = caPool
				}
				t.TLSClientConfig.RootCAs.AppendCertsFromPEM(caCertPem)
			}
		}
	}
}
