package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/i2-open/i2goSignals/internal/providers/dbProviders"
	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/suite"
)

// KeyStatusHandlerSuite exercises POST /key/{keyName}/status: the takeover-class
// authorization (ADR 0006) and the transition semantics (ADR 0028).
type KeyStatusHandlerSuite struct {
	suite.Suite
	app *SignalsApplication
}

func TestKeyStatusHandlerSuite(t *testing.T) {
	suite.Run(t, new(KeyStatusHandlerSuite))
}

func (s *KeyStatusHandlerSuite) SetupTest() {
	persistence, err := dbProviders.OpenPersistence("memorydb:", "keystatus-test")
	s.Require().NoError(err)
	s.Require().NoError(persistence.KeyService.InitializeTokenKey(context.Background(), "DEFAULT"))
	s.app = newTestApplication(persistence)
	s.app.DefIssuer = "DEFAULT"
	_, err = persistence.KeyService.CreateKeyPair(context.Background(), "iss", "sig", "proj-A")
	s.Require().NoError(err)
}

func (s *KeyStatusHandlerSuite) adminToken() string {
	client := model.SsfClient{Id: model.NewRecordId(), ProjectIds: []string{"proj-A"}}
	tok, err := s.app.GetAuth().IssueStreamClientToken(client, "proj-A", true, "")
	s.Require().NoError(err)
	return tok
}

func (s *KeyStatusHandlerSuite) streamToken() string {
	client := model.SsfClient{Id: model.NewRecordId(), ProjectIds: []string{"proj-A"}}
	tok, err := s.app.GetAuth().IssueStreamClientToken(client, "proj-A", false, "")
	s.Require().NoError(err)
	return tok
}

func (s *KeyStatusHandlerSuite) post(keyName, bearer string, req model.SetKeyStatusRequest) *httptest.ResponseRecorder {
	body, _ := json.Marshal(req)
	r := httptest.NewRequest(http.MethodPost, "/key/"+keyName+"/status", bytes.NewReader(body))
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	r = mux.SetURLVars(r, map[string]string{"keyName": keyName})
	rr := httptest.NewRecorder()
	s.app.SetKeyStatus(rr, r)
	return rr
}

// TestBareKeyScopeDenied: a bootstrap (bare "key" scope) bearer is rejected —
// status mutation is takeover-class (ADR 0006).
func (s *KeyStatusHandlerSuite) TestBareKeyScopeDenied() {
	s.T().Setenv("I2SIG_BOOTSTRAP_TOKEN", "s3cret-bootstrap")
	rr := s.post("iss", "s3cret-bootstrap", model.SetKeyStatusRequest{Status: "suspended"})
	s.Equal(http.StatusForbidden, rr.Code, "bare key-scope must be denied")
}

// TestStreamAdminSuspendSucceeds: a stream-admin bearer may suspend, and the
// response carries the updated per-kid status plus the last-active warning.
func (s *KeyStatusHandlerSuite) TestStreamAdminSuspendSucceeds() {
	rr := s.post("iss", s.adminToken(), model.SetKeyStatusRequest{Status: "suspended"})
	s.Require().Equal(http.StatusOK, rr.Code, rr.Body.String())
	var resp KeyStatusResponse
	s.Require().NoError(json.Unmarshal(rr.Body.Bytes(), &resp))
	s.Require().Len(resp.Summary.KeyStates, 1)
	s.Equal(interfaces.KeyStatusSuspended, resp.Summary.KeyStates[0].Status)
	s.NotEmpty(resp.Warning, "suspending the last active key warns")
}

// TestNonAdminDenied: a plain stream-mgmt bearer (no admin/root) is rejected.
func (s *KeyStatusHandlerSuite) TestNonAdminDenied() {
	rr := s.post("iss", s.streamToken(), model.SetKeyStatusRequest{Status: "revoked"})
	s.Equal(http.StatusForbidden, rr.Code)
}

// TestInvalidStatus400: an unknown status is a 400.
func (s *KeyStatusHandlerSuite) TestInvalidStatus400() {
	rr := s.post("iss", s.adminToken(), model.SetKeyStatusRequest{Status: "frozen"})
	s.Equal(http.StatusBadRequest, rr.Code)
}

// TestKidFromDifferentKeyName404: a kid that does not belong to keyName is 404.
func (s *KeyStatusHandlerSuite) TestKidFromDifferentKeyName404() {
	_, err := s.app.KeyService.CreateKeyPair(context.Background(), "other", "sig", "proj-A")
	s.Require().NoError(err)
	rr := s.post("iss", s.adminToken(), model.SetKeyStatusRequest{Status: "suspended", Kid: "other"})
	s.Equal(http.StatusNotFound, rr.Code)
}

// TestReactivateRevoked400: revoked is terminal.
func (s *KeyStatusHandlerSuite) TestReactivateRevoked400() {
	rr := s.post("iss", s.adminToken(), model.SetKeyStatusRequest{Status: "revoked"})
	s.Require().Equal(http.StatusOK, rr.Code)
	rr = s.post("iss", s.adminToken(), model.SetKeyStatusRequest{Status: "active"})
	s.Equal(http.StatusBadRequest, rr.Code, "cannot leave the terminal revoked state")
}

// TestHardDeleteRouteGone: the DELETE /key and DELETE /jwks hard-delete surfaces
// are removed from the gateway route table (admin ADR 0013 / ADR 0028). The
// KeyService delete Go methods remain (enterprise imports them) — only the HTTP
// surface goes.
func TestHardDeleteRouteGone(t *testing.T) {
	h := &HttpRouter{sa: &SignalsApplication{}}
	for _, rt := range h.getRoutes() {
		if rt.Method == http.MethodDelete && (rt.Pattern == "/key/{keyName}" || rt.Pattern == "/jwks/{keyName}") {
			t.Fatalf("hard-delete route still present: %s %s", rt.Method, rt.Pattern)
		}
	}
	// The status route must be present.
	found := false
	for _, rt := range h.getRoutes() {
		if rt.Method == http.MethodPost && rt.Pattern == "/key/{keyName}/status" {
			found = true
		}
	}
	if !found {
		t.Fatal("POST /key/{keyName}/status route not registered")
	}
}
