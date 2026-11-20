package test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/i2-open/i2goSignals/internal/providers/dbProviders"
	"github.com/i2-open/i2goSignals/internal/providers/dbProviders/memory_provider"
	ssef "github.com/i2-open/i2goSignals/internal/server"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/suite"
)

type ApiServerTestSuite struct {
	suite.Suite
	sa        *ssef.SignalsApplication
	ts        *httptest.Server
	ssfServer *httptest.Server
}

func (s *ApiServerTestSuite) SetupSuite() {
	s.T().Setenv("I2SIG_STORE_MEM_DIRECTORY", s.T().TempDir())
	provider, err := memory_provider.Open("memorydb:", "api_server_test")
	s.NoError(err)
	persistence := &dbProviders.Persistence{
		StreamService: provider.GetStreamService(),
		KeyService:    provider.GetKeyService(),
		EventService:  provider.GetEventService(),
		ClientService: provider.GetClientService(),
		ServerService: provider.GetServerService(),
		TokenService:  provider.GetTokenService(),
		Coordinator:   provider.Coordinator(),
		Storage:       memory_provider.NewMemoryStorage(provider),
	}
	s.sa = ssef.NewApplication(persistence, "")
	s.ts = httptest.NewServer(s.sa.Handler)
	s.ssfServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/ssf-configuration" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
}

func (s *ApiServerTestSuite) TearDownSuite() {
	s.ts.Close()
	s.ssfServer.Close()
	s.sa.Shutdown()
}

func (s *ApiServerTestSuite) TestServerCreate() {
	// 1. Mint an admin token: /server provisioning is admin-only (issue #139).
	client := model.SsfClient{Id: model.NewRecordId(), ProjectIds: []string{"proj-A"}}
	iat, err := s.sa.Auth.IssueStreamClientToken(client, "proj-A", true, "")
	s.NoError(err)

	token := "valid-token"
	server := model.Server{
		Alias:       "test-server",
		Type:        model.ServerTypeGosignals,
		Host:        s.ssfServer.URL,
		ClientToken: &token,
	}
	body, _ := json.Marshal(server)

	// 2. Try to create server without token
	req, _ := http.NewRequest(http.MethodPost, s.ts.URL+"/server", bytes.NewBuffer(body))
	resp, err := http.DefaultClient.Do(req)
	s.NoError(err)
	s.Equal(http.StatusUnauthorized, resp.StatusCode)

	// 3. Create server with IAT token
	req, _ = http.NewRequest(http.MethodPost, s.ts.URL+"/server", bytes.NewBuffer(body))
	req.Header.Set("Authorization", "Bearer "+iat)
	resp, err = http.DefaultClient.Do(req)
	s.NoError(err)
	s.Equal(http.StatusCreated, resp.StatusCode)

	var created model.Server
	err = json.NewDecoder(resp.Body).Decode(&created)
	s.NoError(err)
	s.Equal(server.Alias, created.Alias)
	s.NotEmpty(created.Id)

	// 4. Try to create again with same alias (should return 409)
	req, _ = http.NewRequest(http.MethodPost, s.ts.URL+"/server", bytes.NewBuffer(body))
	req.Header.Set("Authorization", "Bearer "+iat)
	resp, err = http.DefaultClient.Do(req)
	s.NoError(err)
	s.Equal(http.StatusConflict, resp.StatusCode)
}

// TestServerCreateStrictSsf drives the real POST /server handler to confirm the
// operator-declared StrictSsf posture round-trips on create: set true reads back
// true, and a server added without the flag defaults to false (flexible). See
// PRD #196 done-means 16/17 and ADR 0024 (operator-declared, never auto-detected).
func (s *ApiServerTestSuite) TestServerCreateStrictSsf() {
	client := model.SsfClient{Id: model.NewRecordId(), ProjectIds: []string{"proj-A"}}
	iat, err := s.sa.Auth.IssueStreamClientToken(client, "proj-A", true, "")
	s.NoError(err)

	// Strict explicitly set true round-trips back true.
	token := "valid-token"
	strict := model.Server{
		Alias:       "strict-server",
		Type:        model.ServerTypeGosignals,
		Host:        s.ssfServer.URL,
		ClientToken: &token,
		StrictSsf:   true,
	}
	body, _ := json.Marshal(strict)
	req, _ := http.NewRequest(http.MethodPost, s.ts.URL+"/server", bytes.NewBuffer(body))
	req.Header.Set("Authorization", "Bearer "+iat)
	resp, err := http.DefaultClient.Do(req)
	s.NoError(err)
	s.Equal(http.StatusCreated, resp.StatusCode)

	var created model.Server
	err = json.NewDecoder(resp.Body).Decode(&created)
	s.NoError(err)
	s.True(created.StrictSsf, "StrictSsf should round-trip true on create")

	// Read back via GET to confirm persistence carried the flag.
	req, _ = http.NewRequest(http.MethodGet, s.ts.URL+"/server/strict-server", nil)
	req.Header.Set("Authorization", "Bearer "+iat)
	resp, err = http.DefaultClient.Do(req)
	s.NoError(err)
	s.Equal(http.StatusOK, resp.StatusCode)
	var fetched model.Server
	err = json.NewDecoder(resp.Body).Decode(&fetched)
	s.NoError(err)
	s.True(fetched.StrictSsf, "StrictSsf should persist as true")

	// Default-off: a server added without the flag reads back false (flexible).
	token2 := "valid-token-2"
	flexible := model.Server{
		Alias:       "flexible-server",
		Type:        model.ServerTypeGosignals,
		Host:        s.ssfServer.URL,
		ClientToken: &token2,
	}
	body2, _ := json.Marshal(flexible)
	req, _ = http.NewRequest(http.MethodPost, s.ts.URL+"/server", bytes.NewBuffer(body2))
	req.Header.Set("Authorization", "Bearer "+iat)
	resp, err = http.DefaultClient.Do(req)
	s.NoError(err)
	s.Equal(http.StatusCreated, resp.StatusCode)
	var createdFlex model.Server
	err = json.NewDecoder(resp.Body).Decode(&createdFlex)
	s.NoError(err)
	s.False(createdFlex.StrictSsf, "StrictSsf should default to false (flexible)")
}

func TestApiServerSuite(t *testing.T) {
	suite.Run(t, new(ApiServerTestSuite))
}
