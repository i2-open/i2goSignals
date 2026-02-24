package test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/i2-open/i2goSignals/internal/model"
	"github.com/i2-open/i2goSignals/internal/providers/dbProviders/memory_provider"
	ssef "github.com/i2-open/i2goSignals/pkg/goSignals/server"
	"github.com/stretchr/testify/suite"
)

type ApiServerTestSuite struct {
	suite.Suite
	sa *ssef.SignalsApplication
	ts *httptest.Server
}

func (s *ApiServerTestSuite) SetupSuite() {
	provider, err := memory_provider.Open("memorydb:", "api_server_test")
	s.NoError(err)
	s.sa = ssef.NewApplication(provider, "")
	s.ts = httptest.NewServer(s.sa.Handler)
}

func (s *ApiServerTestSuite) TearDownSuite() {
	s.ts.Close()
	s.sa.Shutdown()
}

func (s *ApiServerTestSuite) TestServerCreate() {
	// 1. Generate an IAT token (has ScopeRegister)
	iat, err := s.sa.Auth.IssueProjectIat(nil)
	s.NoError(err)

	server := model.Server{
		Alias: "test-server",
		Type:  model.ServerTypeGosignals,
		Host:  "https://test.example.com",
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

func TestApiServerSuite(t *testing.T) {
	suite.Run(t, new(ApiServerTestSuite))
}
