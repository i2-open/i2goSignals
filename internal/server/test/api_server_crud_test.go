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
	"go.mongodb.org/mongo-driver/v2/bson"
)

type ApiServerCrudTestSuite struct {
	suite.Suite
	sa        *ssef.SignalsApplication
	ts        *httptest.Server
	ssfServer *httptest.Server
	iat       string
}

func (s *ApiServerCrudTestSuite) SetupSuite() {
	s.T().Setenv("I2SIG_STORE_MEM_DIRECTORY", s.T().TempDir())
	provider, err := memory_provider.Open("memorydb:", "api_server_crud_test")
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

	// /server provisioning is admin-only (issue #139); mint an admin token.
	client := model.SsfClient{Id: bson.NewObjectID(), ProjectIds: []string{"proj-A"}}
	iat, err := s.sa.Auth.IssueStreamClientToken(client, "proj-A", true, "")
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

// TestServerUpdateStrictSsf drives the real PUT /server/{alias} handler to
// confirm an operator can flip the strict posture after creation: a server
// created flexible (default false) flips to true via update and reads back true.
// See PRD #196 done-means 18 and ADR 0024 (operator-declared correction path).
func (s *ApiServerCrudTestSuite) TestServerUpdateStrictSsf() {
	// 1. Create a server with strict defaulting off.
	token := "valid-token"
	server := model.Server{
		Alias:       "strict-crud-server",
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
	var created model.Server
	err = json.NewDecoder(resp.Body).Decode(&created)
	s.NoError(err)
	s.False(created.StrictSsf, "newly added server defaults to flexible")

	// 2. Flip the strict flag on via update.
	created.StrictSsf = true
	updateBody, _ := json.Marshal(created)
	req, _ = http.NewRequest(http.MethodPut, s.ts.URL+"/server/strict-crud-server", bytes.NewBuffer(updateBody))
	req.Header.Set("Authorization", "Bearer "+s.iat)
	resp, err = http.DefaultClient.Do(req)
	s.NoError(err)
	s.Equal(http.StatusOK, resp.StatusCode)
	var updated model.Server
	err = json.NewDecoder(resp.Body).Decode(&updated)
	s.NoError(err)
	s.True(updated.StrictSsf, "StrictSsf should read back true after update")

	// 3. Confirm persistence via GET.
	req, _ = http.NewRequest(http.MethodGet, s.ts.URL+"/server/strict-crud-server", nil)
	req.Header.Set("Authorization", "Bearer "+s.iat)
	resp, err = http.DefaultClient.Do(req)
	s.NoError(err)
	s.Equal(http.StatusOK, resp.StatusCode)
	var fetched model.Server
	err = json.NewDecoder(resp.Body).Decode(&fetched)
	s.NoError(err)
	s.True(fetched.StrictSsf, "flipped StrictSsf should persist")
}

func TestApiServerCrudSuite(t *testing.T) {
	suite.Run(t, new(ApiServerCrudTestSuite))
}
