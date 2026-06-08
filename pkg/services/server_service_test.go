package services

import (
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/i2-open/i2goSignals/pkg/dao/memory"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/suite"
)

type ServerServiceTestSuite struct {
	suite.Suite
	service   *ServerService
	ssfServer *httptest.Server
}

func (s *ServerServiceTestSuite) SetupTest() {
	dao := memory.NewServerDAO()
	s.service = NewServerService(dao)
	// s.ssfServer represents a reachable goSignals peer: its SSF discovery
	// document parses AND advertises gosignals_version. A 200 with an empty
	// body is a parse failure under Fetch*, so the body must be valid JSON.
	s.ssfServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/ssf-configuration" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer":            r.Host,
				"gosignals_version": "1.0.0",
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
}

func (s *ServerServiceTestSuite) TearDownTest() {
	s.ssfServer.Close()
}

func (s *ServerServiceTestSuite) TestCreateServer() {
	token := "valid-token"
	server := &model.Server{
		Alias:       "test-server",
		Type:        model.ServerTypeGosignals,
		Host:        s.ssfServer.URL,
		ClientToken: &token,
	}

	err := s.service.CreateServer(s.T().Context(), server)
	s.NoError(err)

	// Try to create another with same alias
	server2 := &model.Server{
		Alias:       "test-server",
		Type:        model.ServerTypeSsf,
		Host:        s.ssfServer.URL,
		ClientToken: &token,
	}
	err = s.service.CreateServer(s.T().Context(), server2)
	s.Error(err)
	s.ErrorIs(err, ErrServerAlreadyExists)
}

func (s *ServerServiceTestSuite) TestCreateServer_NoCredentials() {
	server := &model.Server{
		Alias: "test-server",
		Type:  model.ServerTypeGosignals,
	}
	err := s.service.CreateServer(s.T().Context(), server)
	s.Error(err)
	s.Contains(err.Error(), "must be provided")
}

func (s *ServerServiceTestSuite) TestCRUD() {
	token := "valid-token"
	server := &model.Server{
		Alias:       "test-server",
		Type:        model.ServerTypeGosignals,
		Host:        s.ssfServer.URL,
		ClientToken: &token,
	}

	err := s.service.CreateServer(s.T().Context(), server)
	s.NoError(err)
	s.NotEmpty(server.Id)

	// Get
	retrieved, err := s.service.GetServer(s.T().Context(), server.Id.Hex())
	s.NoError(err)
	s.Equal(server.Alias, retrieved.Alias)

	// Update
	server.Alias = "updated-alias"
	err = s.service.UpdateServer(s.T().Context(), server)
	s.NoError(err)

	retrieved, _ = s.service.GetServer(s.T().Context(), server.Id.Hex())
	s.Equal("updated-alias", retrieved.Alias)

	// List
	servers, err := s.service.ListServers(s.T().Context())
	s.NoError(err)
	s.Len(servers, 1)

	// Delete
	err = s.service.DeleteServer(s.T().Context(), server.Id.Hex())
	s.NoError(err)

	_, err = s.service.GetServer(s.T().Context(), server.Id.Hex())
	s.Error(err)
}

func (s *ServerServiceTestSuite) TestCreateServer_OAuthValidation() {
	asServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "test-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer asServer.Close()

	server := &model.Server{
		Alias: "oauth-server",
		Type:  model.ServerTypeSsf,
		Host:  s.ssfServer.URL,
		OAuthClientConfig: &model.OAuthClientConfig{
			TokenURL:     asServer.URL,
			ClientID:     "client",
			ClientSecret: "secret",
		},
	}

	err := s.service.CreateServer(s.T().Context(), server)
	s.NoError(err)
}

func (s *ServerServiceTestSuite) TestCreateServer_OAuthDiscovery() {
	// Mock AS
	asServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/oauth-authorization-server" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"token_endpoint": "http://as.example.com/token",
			})
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer asServer.Close()

	// Mock Resource
	resServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/oauth-protected-resource" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"authorization_servers": []string{asServer.URL},
			})
		} else if r.URL.Path == "/.well-known/ssf-configuration" {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer resServer.Close()

	// Another server to mock the discovered token endpoint
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "test-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer tokenServer.Close()

	// Re-mock AS to return the real token server URL
	asServerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/oauth-authorization-server" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"token_endpoint": tokenServer.URL,
			})
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	})
	// Update asServer's handler
	asServer.Config.Handler = asServerHandler

	server := &model.Server{
		Alias: "discovery-server",
		Type:  model.ServerTypeSsf,
		Host:  resServer.URL,
		OAuthClientConfig: &model.OAuthClientConfig{
			ClientID:     "client",
			ClientSecret: "secret",
		},
	}

	err := s.service.CreateServer(s.T().Context(), server)
	s.NoError(err)
	s.Equal(tokenServer.URL, server.OAuthClientConfig.TokenURL)
}

func (s *ServerServiceTestSuite) TestCreateServer_SelfSignedCertDiscovery() {
	// Mock Server (both AS and Resource)
	mockServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/oauth-protected-resource":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"authorization_servers": []string{"https://" + r.Host},
			})
		case "/.well-known/oauth-authorization-server":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"token_endpoint": "https://" + r.Host + "/token",
			})
		case "/token":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "test-token",
				"token_type":   "Bearer",
				"expires_in":   3600,
			})
		case "/.well-known/ssf-configuration":
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer mockServer.Close()

	// Get the certificate from mockServer
	certBytes := mockServer.Certificate().Raw
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})

	server := &model.Server{
		Alias: "discovery-server",
		Type:  model.ServerTypeSsf,
		Host:  mockServer.URL,
		OAuthClientConfig: &model.OAuthClientConfig{
			ClientID:     "client",
			ClientSecret: "secret",
		},
		TLSCertificate: string(certPEM),
	}

	err := s.service.CreateServer(s.T().Context(), server)
	s.NoError(err)
	s.Equal("https://"+mockServer.Listener.Addr().String()+"/token", server.OAuthClientConfig.TokenURL)
}

// TestCreateServer_InfersSsfTypeFromOAuth proves that when the caller leaves
// Type empty but supplies an OAuthClientConfig, CreateServer infers and
// persists Type == ssf (the foreign SSF transmitter case for PRD #83 / #85).
func (s *ServerServiceTestSuite) TestCreateServer_InfersSsfTypeFromOAuth() {
	// Foreign SSF transmitter: SSF discovery parses but advertises NO
	// gosignals_version -> step 2 of the ladder yields ssf.
	ssfPeer := newSsfOnlyServer()
	defer ssfPeer.Close()

	asServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "test-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer asServer.Close()

	server := &model.Server{
		Alias: "ssf-tx",
		Host:  ssfPeer.URL,
		OAuthClientConfig: &model.OAuthClientConfig{
			TokenURL:     asServer.URL,
			ClientID:     "client",
			ClientSecret: "secret",
		},
	}

	err := s.service.CreateServer(s.T().Context(), server)
	s.NoError(err)

	retrieved, err := s.service.GetServerByAlias(s.T().Context(), "ssf-tx")
	s.NoError(err)
	s.Equal(model.ServerTypeSsf, retrieved.Type)
}

// TestCreateServer_InfersGosignalsTypeFromToken proves that when the caller
// leaves Type empty and supplies only a ClientToken (no OAuthClientConfig),
// CreateServer infers and persists Type == gosignals.
func (s *ServerServiceTestSuite) TestCreateServer_InfersGosignalsTypeFromToken() {
	token := "valid-token"
	server := &model.Server{
		Alias:       "gs-server",
		Host:        s.ssfServer.URL,
		ClientToken: &token,
	}

	err := s.service.CreateServer(s.T().Context(), server)
	s.NoError(err)

	retrieved, err := s.service.GetServerByAlias(s.T().Context(), "gs-server")
	s.NoError(err)
	s.Equal(model.ServerTypeGosignals, retrieved.Type)
}

// newSsfOnlyServer returns a mock that advertises SSF discovery WITHOUT a
// gosignals_version (a genuine foreign SSF transmitter) plus a token endpoint.
func newSsfOnlyServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/ssf-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer": r.Host,
			})
		case "/token":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "test-token",
				"token_type":   "Bearer",
				"expires_in":   3600,
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

// TestCreateServer_OAuthClientGosignalsPeer_NotMislabeled is the issue #141
// regression: an OAuth-client peer whose SSF discovery advertises
// gosignals_version must be persisted as gosignals, not ssf.
func (s *ServerServiceTestSuite) TestCreateServer_OAuthClientGosignalsPeer_NotMislabeled() {
	asServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "test-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer asServer.Close()

	server := &model.Server{
		Alias: "gosignals-oauth-peer",
		Host:  s.ssfServer.URL, // advertises gosignals_version
		OAuthClientConfig: &model.OAuthClientConfig{
			TokenURL:     asServer.URL,
			ClientID:     "client",
			ClientSecret: "secret",
		},
	}

	err := s.service.CreateServer(s.T().Context(), server)
	s.NoError(err)

	retrieved, err := s.service.GetServerByAlias(s.T().Context(), "gosignals-oauth-peer")
	s.NoError(err)
	s.Equal(model.ServerTypeGosignals, retrieved.Type)
}

// TestCreateServer_ExternalRfc8935NoSsfDiscovery_PrmFallback is step 3: a peer
// with no SSF discovery but a resolvable PRM is classified ssf, and its
// authorization_servers are harvested onto ServerConfiguration.
func (s *ServerServiceTestSuite) TestCreateServer_ExternalRfc8935NoSsfDiscovery_PrmFallback() {
	var asURL string
	prmServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/oauth-protected-resource":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"authorization_servers": []string{asURL},
				"scopes_supported":      []string{"ssf.manage"},
			})
		case "/token":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "test-token",
				"token_type":   "Bearer",
				"expires_in":   3600,
			})
		case "/.well-known/ssf-configuration":
			// Reachable (status-only validation passes) but a 200 with an
			// empty body is a parse failure under Fetch*, dropping the ladder
			// to the PRM branch (step 3) -- the empty-body gotcha.
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer prmServer.Close()
	asURL = prmServer.URL

	server := &model.Server{
		Alias: "external-rfc8935",
		Host:  prmServer.URL,
		OAuthClientConfig: &model.OAuthClientConfig{
			TokenURL:     prmServer.URL + "/token",
			ClientID:     "client",
			ClientSecret: "secret",
		},
	}

	err := s.service.CreateServer(s.T().Context(), server)
	s.NoError(err)

	retrieved, err := s.service.GetServerByAlias(s.T().Context(), "external-rfc8935")
	s.NoError(err)
	s.Equal(model.ServerTypeSsf, retrieved.Type)
	s.Require().NotNil(retrieved.ServerConfiguration)
	s.Equal([]string{asURL}, retrieved.ServerConfiguration.AuthorizationServers)
}

// TestCreateServer_UnreachablePeerTokenMode_FallsBackGosignals is step 4: a
// token-mode peer whose host cannot be probed keeps gosignals by provenance.
func (s *ServerServiceTestSuite) TestCreateServer_UnreachablePeerTokenMode_FallsBackGosignals() {
	token := "valid-token"
	// Reachable-but-empty server: validation passes (status-only), but neither
	// SSF nor PRM parses, so the ladder reaches step 4.
	bareServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/ssf-configuration" {
			// 200 with empty body == parse failure under Fetch*.
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer bareServer.Close()

	server := &model.Server{
		Alias:       "unreachable-token-peer",
		Host:        bareServer.URL,
		ClientToken: &token,
	}

	err := s.service.CreateServer(s.T().Context(), server)
	s.NoError(err)

	retrieved, err := s.service.GetServerByAlias(s.T().Context(), "unreachable-token-peer")
	s.NoError(err)
	s.Equal(model.ServerTypeGosignals, retrieved.Type)
}

// TestCreateServer_ExplicitTypeWins proves an explicit caller Type is preserved
// and the discovery ladder is skipped (even when discovery would say otherwise).
func (s *ServerServiceTestSuite) TestCreateServer_ExplicitTypeWins() {
	token := "valid-token"
	// s.ssfServer advertises gosignals_version (would resolve to gosignals),
	// but the caller explicitly asks for ssf.
	server := &model.Server{
		Alias:       "explicit-type",
		Type:        model.ServerTypeSsf,
		Host:        s.ssfServer.URL,
		ClientToken: &token,
	}

	err := s.service.CreateServer(s.T().Context(), server)
	s.NoError(err)

	retrieved, err := s.service.GetServerByAlias(s.T().Context(), "explicit-type")
	s.NoError(err)
	s.Equal(model.ServerTypeSsf, retrieved.Type)
}

// TestCreateServer_PersistsDiscoveredConfiguration proves a step-1 success
// records the decoded SSF configuration (including gosignals_version).
func (s *ServerServiceTestSuite) TestCreateServer_PersistsDiscoveredConfiguration() {
	token := "valid-token"
	server := &model.Server{
		Alias:       "persist-config",
		Host:        s.ssfServer.URL,
		ClientToken: &token,
	}

	err := s.service.CreateServer(s.T().Context(), server)
	s.NoError(err)

	retrieved, err := s.service.GetServerByAlias(s.T().Context(), "persist-config")
	s.NoError(err)
	s.Require().NotNil(retrieved.ServerConfiguration)
	s.Equal("1.0.0", retrieved.ServerConfiguration.GoSignalsVersion)
}

func TestServerServiceSuite(t *testing.T) {
	suite.Run(t, new(ServerServiceTestSuite))
}
