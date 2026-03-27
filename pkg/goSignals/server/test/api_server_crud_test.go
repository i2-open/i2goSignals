package test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/i2-open/i2goSignals/internal/providers/dbProviders/memory_provider"
	ssef "github.com/i2-open/i2goSignals/pkg/goSignals/server"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/suite"
)

type ApiServerCrudTestSuite struct {
	suite.Suite
	sa        *ssef.SignalsApplication
	ts        *httptest.Server
	ssfServer *httptest.Server
	iat       string
}

func (s *ApiServerCrudTestSuite) SetupSuite() {
	provider, err := memory_provider.Open("memorydb:", "api_server_crud_test")
	s.NoError(err)
	s.sa = ssef.NewApplication(provider, "")
	s.ts = httptest.NewServer(s.sa.Handler)
	s.ssfServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/ssf-configuration" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))

	iat, err := s.sa.Auth.IssueProjectIat(nil)
	s.NoError(err)
	s.iat = iat
}

func (s *ApiServerCrudTestSuite) TearDownSuite() {
	s.ts.Close()
	s.ssfServer.Close()
	s.sa.Shutdown()
}

func (s *ApiServerCrudTestSuite) TestServerCRUD() {
	// 1. Create a server
	token := "valid-token"
	server := model.Server{
		Alias:       "crud-server",
		Type:        model.ServerTypeGosignals,
		Host:        s.ssfServer.URL,
		ClientToken: &token,
	}
	body, _ := json.Marshal(server)
	req, _ := http.NewRequest(http.MethodPost, s.ts.URL+"/server", bytes.NewBuffer(body))
	req.Header.Set("Authorization", "Bearer "+s.iat)
	resp, err := http.DefaultClient.Do(req)
	s.NoError(err)
	s.Equal(http.StatusCreated, resp.StatusCode)

	// 2. Get server by alias
	req, _ = http.NewRequest(http.MethodGet, s.ts.URL+"/server/crud-server", nil)
	req.Header.Set("Authorization", "Bearer "+s.iat)
	resp, err = http.DefaultClient.Do(req)
	s.NoError(err)
	s.Equal(http.StatusOK, resp.StatusCode)

	var retrieved model.Server
	err = json.NewDecoder(resp.Body).Decode(&retrieved)
	s.NoError(err)
	s.Equal(server.Alias, retrieved.Alias)
	s.Equal(server.Host, retrieved.Host)

	// 3. Update server
	retrieved.Host = s.ssfServer.URL
	updateBody, _ := json.Marshal(retrieved)
	req, _ = http.NewRequest(http.MethodPut, s.ts.URL+"/server/crud-server", bytes.NewBuffer(updateBody))
	req.Header.Set("Authorization", "Bearer "+s.iat)
	resp, err = http.DefaultClient.Do(req)
	s.NoError(err)
	s.Equal(http.StatusOK, resp.StatusCode)

	var updated model.Server
	err = json.NewDecoder(resp.Body).Decode(&updated)
	s.NoError(err)
	s.Equal(s.ssfServer.URL, updated.Host)

	// 4. Update alias (and check conflict)
	// Create another server first
	token2 := "valid-token-2"
	server2 := model.Server{
		Alias:       "other-server",
		Type:        model.ServerTypeGosignals,
		Host:        s.ssfServer.URL,
		ClientToken: &token2,
	}
	body2, _ := json.Marshal(server2)
	req, _ = http.NewRequest(http.MethodPost, s.ts.URL+"/server", bytes.NewBuffer(body2))
	req.Header.Set("Authorization", "Bearer "+s.iat)
	resp, err = http.DefaultClient.Do(req)
	s.NoError(err)
	s.Equal(http.StatusCreated, resp.StatusCode)

	// Try to update crud-server alias to other-server
	updated.Alias = "other-server"
	conflictBody, _ := json.Marshal(updated)
	req, _ = http.NewRequest(http.MethodPut, s.ts.URL+"/server/crud-server", bytes.NewBuffer(conflictBody))
	req.Header.Set("Authorization", "Bearer "+s.iat)
	resp, err = http.DefaultClient.Do(req)
	s.NoError(err)
	s.Equal(http.StatusConflict, resp.StatusCode)

	// 5. List servers
	req, _ = http.NewRequest(http.MethodGet, s.ts.URL+"/server", nil)
	req.Header.Set("Authorization", "Bearer "+s.iat)
	resp, err = http.DefaultClient.Do(req)
	s.NoError(err)
	s.Equal(http.StatusOK, resp.StatusCode)

	var list []model.Server
	err = json.NewDecoder(resp.Body).Decode(&list)
	s.NoError(err)
	s.GreaterOrEqual(len(list), 2)

	// 6. Delete server
	req, _ = http.NewRequest(http.MethodDelete, s.ts.URL+"/server/crud-server", nil)
	req.Header.Set("Authorization", "Bearer "+s.iat)
	resp, err = http.DefaultClient.Do(req)
	s.NoError(err)
	s.Equal(http.StatusNoContent, resp.StatusCode)

	// Verify it's gone
	req, _ = http.NewRequest(http.MethodGet, s.ts.URL+"/server/crud-server", nil)
	req.Header.Set("Authorization", "Bearer "+s.iat)
	resp, err = http.DefaultClient.Do(req)
	s.NoError(err)
	s.Equal(http.StatusNotFound, resp.StatusCode)
}

func TestApiServerCrudSuite(t *testing.T) {
	suite.Run(t, new(ApiServerCrudTestSuite))
}
