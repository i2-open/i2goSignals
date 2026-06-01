package server

import (
    "bytes"
    "context"
    "encoding/json"
    "net/http"
    "net/http/httptest"
    "testing"

    "github.com/gorilla/mux"
    "github.com/i2-open/i2goSignals/internal/authUtil"
    "github.com/i2-open/i2goSignals/internal/eventRouter"
    "github.com/i2-open/i2goSignals/internal/providers/dbProviders"
    "github.com/i2-open/i2goSignals/pkg/ssfModels"
    "github.com/stretchr/testify/suite"
    "go.mongodb.org/mongo-driver/v2/bson"
)

// ServerProvisioningAuthzSuite verifies the issue #139 authorization model:
//   - POST /stream with tx_alias requires admin (root rides free); a plain
//     create at stream scope is unchanged.
//   - All five /server endpoints are admin-only (reg/stream are rejected).
type ServerProvisioningAuthzSuite struct {
    suite.Suite
    app *SignalsApplication
}

func (s *ServerProvisioningAuthzSuite) SetupTest() {
    persistence, err := dbProviders.OpenPersistence("memorydb:", "serverauthz-test")
    s.Require().NoError(err)
    err = persistence.KeyService.InitializeTokenKey(context.Background(), "DEFAULT")
    s.Require().NoError(err)

    s.app = newTestApplication(persistence)
    s.app.DefIssuer = "DEFAULT"
    // A plain (non-tx_alias) create reaches the post-create EventRouter wiring;
    // give the app a real router so that regression path returns a clean 201
    // instead of dereferencing a nil router. Poll-transmitter streams are served
    // by every node and take no lease, so no background goroutine races here.
    s.app.EventRouter = eventRouter.NewRouter(eventRouter.RouterDeps{
        StreamService: persistence.StreamService,
        KeyService:    persistence.KeyService,
        EventService:  persistence.EventService,
        Coordinator:   persistence.Coordinator,
    }, "test-node")
    s.app.pushReceivers = map[string]model.StreamStateRecord{}
    s.app.pollClients = map[string]*ClientPollStream{}
}

// adminToken mints a stream-admin token bound to the project.
func (s *ServerProvisioningAuthzSuite) adminToken(projectId string) string {
    client := model.SsfClient{Id: bson.NewObjectID(), ProjectIds: []string{projectId}}
    tok, err := s.app.GetAuth().IssueStreamClientToken(client, projectId, true, "")
    s.Require().NoError(err)
    return tok
}

// streamToken mints a stream-mgmt (non-admin) client token bound to the project.
func (s *ServerProvisioningAuthzSuite) streamToken(projectId string) string {
    client := model.SsfClient{Id: bson.NewObjectID(), ProjectIds: []string{projectId}}
    tok, err := s.app.GetAuth().IssueStreamClientToken(client, projectId, false, "")
    s.Require().NoError(err)
    return tok
}

// regToken mints a register (IAT) token bound to the project.
func (s *ServerProvisioningAuthzSuite) regToken(projectId string) string {
    tok, err := s.app.GetAuth().IssueProjectIat(&authUtil.AuthContext{ProjectId: projectId})
    s.Require().NoError(err)
    return tok
}

func (s *ServerProvisioningAuthzSuite) do(handler http.HandlerFunc, method, path, bearer string, body []byte, vars map[string]string) *httptest.ResponseRecorder {
    var rdr *bytes.Reader
    if body != nil {
        rdr = bytes.NewReader(body)
    } else {
        rdr = bytes.NewReader([]byte{})
    }
    req := httptest.NewRequest(method, path, rdr)
    if bearer != "" {
        req.Header.Set("Authorization", "Bearer "+bearer)
    }
    if vars != nil {
        req = mux.SetURLVars(req, vars)
    }
    rr := httptest.NewRecorder()
    handler(rr, req)
    return rr
}

// --- StreamCreateHandler tx_alias discriminator ---

func (s *ServerProvisioningAuthzSuite) TestStreamCreate_TxAliasWithStreamScope403() {
    tok := s.streamToken("proj-A")
    alias := "ssfTx"
    cfg := model.StreamStateRecord{}
    cfg.TxAlias = &alias
    body, _ := json.Marshal(cfg)

    rr := s.do(s.app.StreamCreate, http.MethodPost, "/stream", tok, body, nil)
    s.Equal(http.StatusForbidden, rr.Code, "tx_alias create at stream scope must be denied")
    s.Contains(rr.Body.String(), "admin", "denial message must be actionable")
}

func (s *ServerProvisioningAuthzSuite) TestStreamCreate_TxAliasWithAdminScopeSucceeds() {
    tok := s.adminToken("proj-A")
    alias := "ssfTx"
    cfg := model.StreamStateRecord{}
    cfg.TxAlias = &alias
    body, _ := json.Marshal(cfg)

    rr := s.do(s.app.StreamCreate, http.MethodPost, "/stream", tok, body, nil)
    s.NotEqual(http.StatusForbidden, rr.Code, "tx_alias create at admin scope must pass the authz gate")
}

func (s *ServerProvisioningAuthzSuite) TestStreamCreate_PlainAtStreamScopeSucceeds() {
    tok := s.streamToken("proj-A")
    // No tx_alias -> the unchanged local-only path. A poll-transmitter stream is
    // served by every node and takes no lease.
    cfg := model.StreamStateRecord{}
    cfg.Iss = "http://transmitter.example.com"
    cfg.Aud = []string{"http://receiver.example.com"}
    cfg.Delivery = &model.OneOfStreamConfigurationDelivery{
        PollTransmitMethod: &model.PollTransmitMethod{Method: model.DeliveryPoll},
    }
    body, _ := json.Marshal(cfg)

    rr := s.do(s.app.StreamCreate, http.MethodPost, "/stream", tok, body, nil)
    s.Equal(http.StatusCreated, rr.Code, "a plain stream-create at stream scope must remain allowed (regression guard)")
}

// --- /server endpoints are admin-only ---

func (s *ServerProvisioningAuthzSuite) TestCreateServer_RejectsRegAndStream() {
    body, _ := json.Marshal(model.Server{Alias: "tx1"})
    for name, tok := range map[string]string{"reg": s.regToken("proj-A"), "stream": s.streamToken("proj-A")} {
        rr := s.do(s.app.CreateServer, http.MethodPost, "/server", tok, body, nil)
        s.Equalf(http.StatusForbidden, rr.Code, "%s token must be rejected by POST /server", name)
    }
}

func (s *ServerProvisioningAuthzSuite) TestCreateServer_AdminSucceeds() {
    iat := "iat-placeholder"
    body, _ := json.Marshal(model.Server{Alias: "tx1", Host: "https://transmitter.example.com", IatToken: &iat})
    rr := s.do(s.app.CreateServer, http.MethodPost, "/server", s.adminToken("proj-A"), body, nil)
    s.Equal(http.StatusCreated, rr.Code, "admin token must be accepted by POST /server")
}

func (s *ServerProvisioningAuthzSuite) TestGetServer_RejectsRegAndStream() {
    vars := map[string]string{"alias": "tx1"}
    for name, tok := range map[string]string{"reg": s.regToken("proj-A"), "stream": s.streamToken("proj-A")} {
        rr := s.do(s.app.ServerGet, http.MethodGet, "/server/tx1", tok, nil, vars)
        s.Equalf(http.StatusForbidden, rr.Code, "%s token must be rejected by GET /server", name)
    }
}

func (s *ServerProvisioningAuthzSuite) TestUpdateServer_RejectsRegAndStream() {
    vars := map[string]string{"alias": "tx1"}
    body, _ := json.Marshal(model.Server{Alias: "tx1"})
    for name, tok := range map[string]string{"reg": s.regToken("proj-A"), "stream": s.streamToken("proj-A")} {
        rr := s.do(s.app.ServerUpdate, http.MethodPut, "/server/tx1", tok, body, vars)
        s.Equalf(http.StatusForbidden, rr.Code, "%s token must be rejected by PUT /server", name)
    }
}

func (s *ServerProvisioningAuthzSuite) TestDeleteServer_RejectsRegAndStream() {
    vars := map[string]string{"alias": "tx1"}
    for name, tok := range map[string]string{"reg": s.regToken("proj-A"), "stream": s.streamToken("proj-A")} {
        rr := s.do(s.app.ServerDelete, http.MethodDelete, "/server/tx1", tok, nil, vars)
        s.Equalf(http.StatusForbidden, rr.Code, "%s token must be rejected by DELETE /server", name)
    }
}

func (s *ServerProvisioningAuthzSuite) TestListServer_RejectsRegAndStream() {
    for name, tok := range map[string]string{"reg": s.regToken("proj-A"), "stream": s.streamToken("proj-A")} {
        rr := s.do(s.app.ServerList, http.MethodGet, "/server", tok, nil, nil)
        s.Equalf(http.StatusForbidden, rr.Code, "%s token must be rejected by GET /server (list)", name)
    }
}

func (s *ServerProvisioningAuthzSuite) TestListServer_AdminSucceeds() {
    rr := s.do(s.app.ServerList, http.MethodGet, "/server", s.adminToken("proj-A"), nil, nil)
    s.Equal(http.StatusOK, rr.Code, "admin token must be accepted by GET /server (list)")
}

func TestServerProvisioningAuthzSuite(t *testing.T) {
    suite.Run(t, new(ServerProvisioningAuthzSuite))
}
