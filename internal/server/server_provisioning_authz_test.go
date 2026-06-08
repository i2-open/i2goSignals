package server

import (
    "bytes"
    "context"
    "crypto/rand"
    "crypto/rsa"
    "encoding/base64"
    "encoding/json"
    "net/http"
    "net/http/httptest"
    "testing"
    "time"

    "github.com/golang-jwt/jwt/v5"
    "github.com/gorilla/mux"
    "github.com/i2-open/i2goSignals/internal/eventRouter"
    "github.com/i2-open/i2goSignals/internal/providers/dbProviders"
    "github.com/i2-open/i2goSignals/pkg/authSupport"
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
    tok, err := s.app.GetAuth().IssueProjectIat(&authSupport.AuthContext{ProjectId: projectId})
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

// TestCanProvisionTxAlias locks the tx_alias authorization policy directly,
// across both caller shapes, without minting tokens: foreign-server provisioning
// needs admin (root rides free) OR the full reg+stream+event operate-the-stream
// set. Any subset short of that — including register alone — is denied.
func TestCanProvisionTxAlias(t *testing.T) {
    oauth := func(scopes ...string) *authSupport.AuthContext {
        return &authSupport.AuthContext{IsOAuthClient: true, GrantedScopes: scopes}
    }
    local := func(roles ...string) *authSupport.AuthContext {
        return &authSupport.AuthContext{Eat: &authSupport.EventAuthToken{Roles: roles}}
    }
    const (
        reg    = authSupport.ScopeRegister
        stream = authSupport.ScopeStreamMgmt
        event  = authSupport.ScopeEventDelivery
        admin  = authSupport.ScopeStreamAdmin
        root   = authSupport.ScopeRoot
    )
    tests := []struct {
        name string
        ctx  *authSupport.AuthContext
        want bool
    }{
        {"oauth admin", oauth(admin), true},
        {"oauth full set", oauth(reg, stream, event), true},
        {"oauth full set unordered", oauth(event, reg, stream), true},
        {"oauth reg only", oauth(reg), false},
        {"oauth reg+stream missing event", oauth(reg, stream), false},
        {"oauth reg+event missing stream", oauth(reg, event), false},
        {"oauth stream+event missing reg", oauth(stream, event), false},
        {"oauth foreign root not honored", oauth(root), false},
        {"local admin", local(admin), true},
        {"local root rides free", local(root), true},
        {"local full set", local(reg, stream, event), true},
        {"local reg only", local(reg), false},
        {"local stream only", local(stream), false},
    }
    for _, tc := range tests {
        t.Run(tc.name, func(t *testing.T) {
            if got := canProvisionTxAlias(tc.ctx); got != tc.want {
                t.Errorf("canProvisionTxAlias(%s) = %v, want %v", tc.name, got, tc.want)
            }
        })
    }
}

// startOIDC stands up a throwaway OIDC discovery + JWKS endpoint and returns the
// discovery URL plus the signing key/kid that mintOAuth uses to forge tokens the
// server's OAuth validator will accept. It mirrors the fixture in
// internal/authUtil's tests; duplicated here because test helpers don't cross
// package boundaries.
func (s *ServerProvisioningAuthzSuite) startOIDC() (discoveryURL, kid string, priv *rsa.PrivateKey) {
    var err error
    priv, err = rsa.GenerateKey(rand.Reader, 2048)
    s.Require().NoError(err)
    pub := &priv.PublicKey
    n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
    e := base64.RawURLEncoding.EncodeToString([]byte{0x01, 0x00, 0x01}) // 65537
    kid = "oauth-kid-authz"

    var jwksURL string
    srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        switch r.URL.Path {
        case "/.well-known/openid-configuration":
            w.Header().Set("Content-Type", "application/json")
            _ = json.NewEncoder(w).Encode(map[string]string{"jwks_uri": jwksURL})
        case "/jwks":
            w.Header().Set("Content-Type", "application/json")
            _ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{
                {"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256", "n": n, "e": e},
            }})
        default:
            http.NotFound(w, r)
        }
    }))
    jwksURL = srv.URL + "/jwks"
    s.T().Cleanup(srv.Close)
    return srv.URL + "/.well-known/openid-configuration", kid, priv
}

// mintOAuth forges an OIDC-shaped RS256 token whose realm roles carry the given
// scopes — the shape of an STS/OAuth-exchanged caller (no local EAT).
func (s *ServerProvisioningAuthzSuite) mintOAuth(priv *rsa.PrivateKey, kid string, roles []string) string {
    claims := authSupport.OidcClaims{
        RegisteredClaims: jwt.RegisteredClaims{
            IssuedAt:  jwt.NewNumericDate(time.Now().Add(-time.Minute)),
            ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
            Issuer:    "http://oidc-issuer.example",
            Audience:  []string{"gosignals"},
            ID:        "oauth-test-jti",
        },
    }
    claims.RealmAccess.Roles = roles
    tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
    tok.Header["kid"] = kid
    signed, err := tok.SignedString(priv)
    s.Require().NoError(err)
    return signed
}

// Regression for the OAuth/STS admin caller: an admin token obtained by exchange
// has Eat==nil and carries its authority in GrantedScopes. The tx_alias gate must
// honor that admin grant, not deny it for lacking a local EAT (the #139 gate read
// authCtx.Eat directly; #128 had already fixed the same bug class for the
// token-admin endpoints but did not touch this stream-create gate).
func (s *ServerProvisioningAuthzSuite) TestStreamCreate_TxAliasWithOAuthAdminScopeSucceeds() {
    discoveryURL, kid, priv := s.startOIDC()
    s.T().Setenv("I2SIG_AUTH_OAUTH_SERVERS", discoveryURL)
    tok := s.mintOAuth(priv, kid, []string{authSupport.ScopeStreamAdmin})

    alias := "ssfTx"
    cfg := model.StreamStateRecord{}
    cfg.TxAlias = &alias
    body, _ := json.Marshal(cfg)

    rr := s.do(s.app.StreamCreate, http.MethodPost, "/stream", tok, body, nil)
    s.NotEqual(http.StatusForbidden, rr.Code,
        "tx_alias create by an OAuth/STS admin caller (Eat==nil, GrantedScopes=[admin]) must pass the authz gate")
}

// A non-admin OAuth caller (e.g. only the stream scope) must still be denied at
// the tx_alias gate — the fix admits admins, not every OAuth caller.
func (s *ServerProvisioningAuthzSuite) TestStreamCreate_TxAliasWithOAuthStreamScopeDenied() {
    discoveryURL, kid, priv := s.startOIDC()
    s.T().Setenv("I2SIG_AUTH_OAUTH_SERVERS", discoveryURL)
    tok := s.mintOAuth(priv, kid, []string{authSupport.ScopeStreamMgmt})

    alias := "ssfTx"
    cfg := model.StreamStateRecord{}
    cfg.TxAlias = &alias
    body, _ := json.Marshal(cfg)

    rr := s.do(s.app.StreamCreate, http.MethodPost, "/stream", tok, body, nil)
    s.Equal(http.StatusForbidden, rr.Code,
        "tx_alias create by a non-admin OAuth caller must remain denied")
}

// A non-admin caller holding the full reg+stream+event operational set can
// provision a foreign (tx_alias) stream — it can drive the whole remote lifecycle.
func (s *ServerProvisioningAuthzSuite) TestStreamCreate_TxAliasWithOAuthFullScopeSetSucceeds() {
    discoveryURL, kid, priv := s.startOIDC()
    s.T().Setenv("I2SIG_AUTH_OAUTH_SERVERS", discoveryURL)
    tok := s.mintOAuth(priv, kid, []string{
        authSupport.ScopeRegister, authSupport.ScopeStreamMgmt, authSupport.ScopeEventDelivery,
    })

    alias := "ssfTx"
    cfg := model.StreamStateRecord{}
    cfg.TxAlias = &alias
    body, _ := json.Marshal(cfg)

    rr := s.do(s.app.StreamCreate, http.MethodPost, "/stream", tok, body, nil)
    s.NotEqual(http.StatusForbidden, rr.Code,
        "tx_alias create with the full reg+stream+event set must pass the authz gate")
}

// The full set is required: reg+stream without event is still denied (register
// alone, or any partial set, is not enough to provision a foreign stream).
func (s *ServerProvisioningAuthzSuite) TestStreamCreate_TxAliasWithOAuthPartialScopeSetDenied() {
    discoveryURL, kid, priv := s.startOIDC()
    s.T().Setenv("I2SIG_AUTH_OAUTH_SERVERS", discoveryURL)
    tok := s.mintOAuth(priv, kid, []string{authSupport.ScopeRegister, authSupport.ScopeStreamMgmt})

    alias := "ssfTx"
    cfg := model.StreamStateRecord{}
    cfg.TxAlias = &alias
    body, _ := json.Marshal(cfg)

    rr := s.do(s.app.StreamCreate, http.MethodPost, "/stream", tok, body, nil)
    s.Equal(http.StatusForbidden, rr.Code,
        "tx_alias create with reg+stream but missing event must remain denied")
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

// reg is a first-class alternate for plain stream creation (alongside stream and
// admin): a register-scoped credential must be able to create a stream. Only the
// tx_alias (foreign-server provisioning) variant escalates to admin.
func (s *ServerProvisioningAuthzSuite) TestStreamCreate_PlainAtRegScopeSucceeds() {
    tok := s.regToken("proj-A")
    cfg := model.StreamStateRecord{}
    cfg.Iss = "http://transmitter.example.com"
    cfg.Aud = []string{"http://receiver.example.com"}
    cfg.Delivery = &model.OneOfStreamConfigurationDelivery{
        PollTransmitMethod: &model.PollTransmitMethod{Method: model.DeliveryPoll},
    }
    body, _ := json.Marshal(cfg)

    rr := s.do(s.app.StreamCreate, http.MethodPost, "/stream", tok, body, nil)
    s.Equal(http.StatusCreated, rr.Code, "a plain stream-create with the reg scope must be allowed")
}

// --- StreamCreateHandler SSTP pair-create discriminator (finding #4) ---

// sstpCascadeBootstrap builds a discriminated SstpPairBootstrap body that both
// passes IsSstpBootstrapBody (role + a per-direction object) and triggers the
// foreign-cascade path (peer_server_alias set). This is the request shape that
// drives a remote write using stored peer credentials and must be gated like a
// tx_alias foreign provision.
func sstpCascadeBootstrap() []byte {
    boot := model.SstpPairBootstrap{
        Role:            model.SstpRoleInitiator,
        PeerServerAlias: "peerTx",
        Primary: model.SstpDirection{
            Iss: "https://a.example", Aud: []string{"https://b.example"},
        },
    }
    body, _ := json.Marshal(boot)
    return body
}

// A caller with only stream_mgmt must NOT be able to drive an SSTP pair-create
// that cascades to a peer (peer_server_alias set) — that is the privilege-
// escalation finding. It must be rejected at the same gate tx_alias uses.
func (s *ServerProvisioningAuthzSuite) TestStreamCreate_SstpCascadeWithStreamScope403() {
    tok := s.streamToken("proj-A")
    rr := s.do(s.app.StreamCreate, http.MethodPost, "/stream", tok, sstpCascadeBootstrap(), nil)
    s.Equal(http.StatusForbidden, rr.Code, "SSTP cascade create at stream scope must be denied")
    s.Contains(rr.Body.String(), "admin", "denial message must be actionable")
}

// A register-only caller is likewise denied the cascade path (register alone is
// not enough to provision against a foreign peer, mirroring tx_alias).
func (s *ServerProvisioningAuthzSuite) TestStreamCreate_SstpCascadeWithRegScope403() {
    tok := s.regToken("proj-A")
    rr := s.do(s.app.StreamCreate, http.MethodPost, "/stream", tok, sstpCascadeBootstrap(), nil)
    s.Equal(http.StatusForbidden, rr.Code, "SSTP cascade create at register scope must be denied")
}

// A responder-role bootstrap mints a long-lived pair bearer even without a peer
// cascade, so it too must clear the elevated gate.
func (s *ServerProvisioningAuthzSuite) TestStreamCreate_SstpResponderWithStreamScope403() {
    tok := s.streamToken("proj-A")
    boot := model.SstpPairBootstrap{
        Role: model.SstpRoleResponder,
        Inbound: model.SstpDirection{
            Iss: "https://a.example", Aud: []string{"https://b.example"},
        },
    }
    body, _ := json.Marshal(boot)
    rr := s.do(s.app.StreamCreate, http.MethodPost, "/stream", tok, body, nil)
    s.Equal(http.StatusForbidden, rr.Code, "SSTP responder create (mints a pair bearer) at stream scope must be denied")
}

// An admin caller must clear the SSTP cascade gate — the gate admits the same
// authorized callers tx_alias does. We assert only that the request is NOT
// rejected at the authz gate (it may later fail in CreateSstpPair because the
// peer alias does not resolve to a real server in this unit fixture).
func (s *ServerProvisioningAuthzSuite) TestStreamCreate_SstpCascadeWithAdminScopePassesGate() {
    tok := s.adminToken("proj-A")
    rr := s.do(s.app.StreamCreate, http.MethodPost, "/stream", tok, sstpCascadeBootstrap(), nil)
    s.NotEqual(http.StatusForbidden, rr.Code, "SSTP cascade create at admin scope must pass the authz gate")
}

// A non-admin caller holding the full reg+stream+event operational set can also
// clear the SSTP cascade gate (parity with the tx_alias policy).
func (s *ServerProvisioningAuthzSuite) TestStreamCreate_SstpCascadeWithOAuthFullScopeSetPassesGate() {
    discoveryURL, kid, priv := s.startOIDC()
    s.T().Setenv("I2SIG_AUTH_OAUTH_SERVERS", discoveryURL)
    tok := s.mintOAuth(priv, kid, []string{
        authSupport.ScopeRegister, authSupport.ScopeStreamMgmt, authSupport.ScopeEventDelivery,
    })
    rr := s.do(s.app.StreamCreate, http.MethodPost, "/stream", tok, sstpCascadeBootstrap(), nil)
    s.NotEqual(http.StatusForbidden, rr.Code,
        "SSTP cascade create with the full reg+stream+event set must pass the authz gate")
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
