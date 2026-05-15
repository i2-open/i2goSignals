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

	"github.com/i2-open/i2goSignals/internal/envcompat"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
)

func InitTransportLayerSecurity(app *http.Server) (io.Closer, bool, error) {
	tlsEnabled := tlsEnabledFromEnv()
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
		if len(pair.Certificate) > 0 {
			leaf, err := x509.ParseCertificate(pair.Certificate[0])
			if err == nil {
				pair.Leaf = leaf
			}
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

					spiffeCert, spiffeErr := spiffeGetCert(hello)

					// 1. Try to find a certificate that matches the requested SNI.
					if hello.ServerName != "" {
						// Check if SPIFFE SVID matches the requested SNI.
						if spiffeErr == nil && spiffeCert != nil {
							leaf := spiffeCert.Leaf
							if leaf == nil && len(spiffeCert.Certificate) > 0 {
								leaf, _ = x509.ParseCertificate(spiffeCert.Certificate[0])
							}
							if leaf != nil && leaf.VerifyHostname(hello.ServerName) == nil {
								return spiffeCert, nil
							}
						}

						// Fallback to file-based cert if it matches the SNI.
						// This handles cases where the SVID might be missing DNS SANs (e.g. for scim_cluster1).
						if fileCert != nil && fileCert.Leaf != nil {
							if err := fileCert.Leaf.VerifyHostname(hello.ServerName); err == nil {
								return fileCert, nil
							}
						}
					}

					// 2. Default: prefer the file-based cert if no match or no SNI.
					// This provides maximum compatibility with legacy/external clients (like Java).
					if fileCert != nil {
						return fileCert, nil
					}

					// 3. Last resort: use the SPIFFE SVID.
					if spiffeErr == nil && spiffeCert != nil {
						return spiffeCert, nil
					}

					return spiffeCert, spiffeErr
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
	serverKeyPath := envcompat.Lookup(EnvServerKey, "SERVER_KEY_PATH")
	if serverKeyPath == "" {
		serverKeyPath = "config/certs/server-key.pem"
	}

	serverCertPath := envcompat.Lookup(EnvServerCert, "SERVER_CERT_PATH")
	if serverCertPath == "" {
		serverCertPath = "config/certs/server-cert.pem"
	}
	return serverCertPath, serverKeyPath
}

const (
	EnvServerKey  = "I2SIG_TLS_KEY_PATH"
	EnvServerCert = "I2SIG_TLS_CERT_PATH"
	EnvCaCert     = "I2SIG_TLS_CA_CERT"
)

// caCertPathFromEnv returns the CA-certificate path configured via
// I2SIG_TLS_CA_CERT (preferred) or the deprecated CA_CERT (with a
// one-time WARN through envcompat). The historical CERT_CA_PUB_KEY
// alias is intentionally not consulted: it has been removed in v0.11.0
// because it duplicated CA_CERT.
func caCertPathFromEnv() string {
	return envcompat.Lookup(EnvCaCert, "CA_CERT")
}

// tlsEnabledFromEnv reads the TLS enablement flag through envcompat,
// preferring I2SIG_TLS_ENABLED and falling back to the deprecated
// TLS_ENABLED. Surrounding quotes are stripped so values written as
// I2SIG_TLS_ENABLED='"true"' (the form some compose files use) are
// honored.
func tlsEnabledFromEnv() bool {
	return stripQuotes(envcompat.Lookup("I2SIG_TLS_ENABLED", "TLS_ENABLED")) == "true"
}

// stripQuotes removes surrounding double or single quotes from a string
func stripQuotes(s string) string {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

// GetGlobalCertPool returns a cert pool containing the CA certificate
// found via I2SIG_TLS_CA_CERT (preferred), the deprecated CA_CERT, or
// any caller-supplied extraEnvVars (consulted last), falling back to
// "config/certs/ca-cert.pem". Returns the system cert pool augmented
// with the CA cert if found.
func GetGlobalCertPool(extraEnvVars ...string) *x509.CertPool {
	caCertPath := caCertPathFromEnv()
	if caCertPath == "" {
		for _, env := range extraEnvVars {
			if v := os.Getenv(env); v != "" {
				caCertPath = v
				break
			}
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
	caCertPath := caCertPathFromEnv()
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
