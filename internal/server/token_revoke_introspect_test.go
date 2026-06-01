package server

import (
    "context"
    "encoding/json"
    "net/http"
    "net/http/httptest"
    "net/url"
    "strings"
    "testing"

    "github.com/gorilla/mux"
    "github.com/i2-open/i2goSignals/internal/providers/dbProviders"
    "github.com/i2-open/i2goSignals/pkg/ssfModels"
    "github.com/stretchr/testify/suite"
    "go.mongodb.org/mongo-driver/v2/bson"
)

// TokenAdminSuite drives the single-token management endpoints (/revoke,
// /introspect, DELETE /token/{jti}) end-to-end against a memory-backed
// persistence with a real AuthIssuer, exercising RFC 7009 / RFC 7662
// conformance and the shared project guard.
type TokenAdminSuite struct {
    suite.Suite
    app *SignalsApplication
}

func (s *TokenAdminSuite) SetupTest() {
    persistence, err := dbProviders.OpenPersistence("memorydb:", "tokenadmin-test")
    s.Require().NoError(err)
    // Wire the token signing key so the AuthIssuer can mint + validate tokens.
    err = persistence.KeyService.InitializeTokenKey(context.Background(), "DEFAULT")
    s.Require().NoError(err)

    s.app = newTestApplication(persistence)
    s.app.DefIssuer = "DEFAULT"
}

// issueStreamTokenForProject mints an event-delivery (non-admin) token bound to
// the given project, returning the token string and its JTI.
func (s *TokenAdminSuite) issueDeliveryToken(projectId string) (string, string) {
    tok, err := s.app.GetAuth().IssueStreamToken("stream-"+projectId, projectId, nil)
    s.Require().NoError(err)
    jti := s.jtiOf(tok)
    return tok, jti
}

// issueAdminToken mints a stream-admin token bound to the given project.
func (s *TokenAdminSuite) issueAdminToken(projectId string) string {
    client := model.SsfClient{Id: bson.NewObjectID(), ProjectIds: []string{projectId}}
    tok, err := s.app.GetAuth().IssueStreamClientToken(client, projectId, true, "")
    s.Require().NoError(err)
    return tok
}

func (s *TokenAdminSuite) jtiOf(token string) string {
    claims, err := s.app.GetAuth().ParseAuthTokenVerbose(token, false)
    s.Require().NoError(err)
    s.Require().NotNil(claims)
    return claims.ID
}

func (s *TokenAdminSuite) postForm(handler http.HandlerFunc, path string, bearer string, form url.Values) *httptest.ResponseRecorder {
    req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
    req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
    if bearer != "" {
        req.Header.Set("Authorization", "Bearer "+bearer)
    }
    rr := httptest.NewRecorder()
    handler(rr, req)
    return rr
}

// --- Tracer bullet: RFC 7662 field names ---

func (s *TokenAdminSuite) TestIntrospectUsesRFC7662FieldNames() {
    adminTok := s.issueAdminToken("proj-A")
    _, jti := s.issueDeliveryToken("proj-A")

    rr := s.postForm(s.app.IntrospectHandler, "/introspect", adminTok, url.Values{"token": {jti}})
    s.Equal(http.StatusOK, rr.Code)

    var raw map[string]any
    s.Require().NoError(json.Unmarshal(rr.Body.Bytes(), &raw))

    // RFC 7662 field names.
    s.Contains(raw, "active")
    s.Contains(raw, "token_type", "RFC 7662 uses token_type, not the non-standard 'type'")
    s.NotContains(raw, "type", "non-standard 'type' must be renamed to token_type")
    s.Equal(model.TokenTypeStream, raw["token_type"])
}

// --- RFC 7009 /revoke always-200 semantics ---

func (s *TokenAdminSuite) TestRevokeUnknownTokenReturns200() {
    adminTok := s.issueAdminToken("proj-A")
    // An opaque/unknown JTI that was never issued.
    rr := s.postForm(s.app.RevokeHandler, "/revoke", adminTok, url.Values{"token": {"never-issued-jti"}})
    s.Equal(http.StatusOK, rr.Code, "RFC 7009 §2.2: unknown token still returns 200")
}

func (s *TokenAdminSuite) TestRevokeUnparseableTokenReturns200() {
    adminTok := s.issueAdminToken("proj-A")
    rr := s.postForm(s.app.RevokeHandler, "/revoke", adminTok, url.Values{"token": {"not-a-jwt.garbage"}})
    s.Equal(http.StatusOK, rr.Code, "an unparseable token still returns 200 without erroring")
}

func (s *TokenAdminSuite) TestRevokeToleratesTokenTypeHint() {
    adminTok := s.issueAdminToken("proj-A")
    deliveryTok, _ := s.issueDeliveryToken("proj-A")
    rr := s.postForm(s.app.RevokeHandler, "/revoke", adminTok, url.Values{
        "token":           {deliveryTok},
        "token_type_hint": {"access_token"},
    })
    s.Equal(http.StatusOK, rr.Code, "token_type_hint is accepted but ignored")
}

func (s *TokenAdminSuite) TestRevokeSetsRevokedAtAndIntrospectReportsInactive() {
    adminTok := s.issueAdminToken("proj-A")
    deliveryTok, jti := s.issueDeliveryToken("proj-A")

    // Before revoke: active.
    pre, err := s.app.GetTokenService().IntrospectToken(context.Background(), jti)
    s.Require().NoError(err)
    s.True(pre.Active)

    // Revoke by presenting the full JWT (RFC 7009).
    rr := s.postForm(s.app.RevokeHandler, "/revoke", adminTok, url.Values{"token": {deliveryTok}})
    s.Equal(http.StatusOK, rr.Code)

    // revoked_at is set on the record (IsRevoked reads revoked_at).
    revoked, err := s.app.GetTokenService().IsRevoked(context.Background(), jti)
    s.Require().NoError(err)
    s.True(revoked, "revoke must set revoked_at")

    // A later introspect reports active:false (record retained).
    post, err := s.app.GetTokenService().IntrospectToken(context.Background(), jti)
    s.Require().NoError(err)
    s.False(post.Active, "introspect reports active:false after revoke")
}

func (s *TokenAdminSuite) TestRevokeAlreadyRevokedReturns200() {
    adminTok := s.issueAdminToken("proj-A")
    deliveryTok, _ := s.issueDeliveryToken("proj-A")

    rr := s.postForm(s.app.RevokeHandler, "/revoke", adminTok, url.Values{"token": {deliveryTok}})
    s.Equal(http.StatusOK, rr.Code)
    // Second revoke of the same token.
    rr = s.postForm(s.app.RevokeHandler, "/revoke", adminTok, url.Values{"token": {deliveryTok}})
    s.Equal(http.StatusOK, rr.Code, "already-revoked token still returns 200")
}

func (s *TokenAdminSuite) TestRevokeMissingTokenReturns400() {
    adminTok := s.issueAdminToken("proj-A")
    rr := s.postForm(s.app.RevokeHandler, "/revoke", adminTok, url.Values{})
    s.Equal(http.StatusBadRequest, rr.Code, "absent token param is a malformed request")
}

// --- Project guard across /revoke, /introspect, DELETE /token/{jti} ---

func (s *TokenAdminSuite) deleteToken(bearer, jti string) *httptest.ResponseRecorder {
    req := httptest.NewRequest(http.MethodDelete, "/token/"+jti, nil)
    if bearer != "" {
        req.Header.Set("Authorization", "Bearer "+bearer)
    }
    req = muxSetVar(req, "jti", jti)
    rr := httptest.NewRecorder()
    s.app.TokenRevokeHandler(rr, req)
    return rr
}

func (s *TokenAdminSuite) TestIntrospectCrossProjectDeniedForNonAdmin() {
    // Target token lives in proj-A.
    _, targetJti := s.issueDeliveryToken("proj-A")
    // Caller is a non-admin (delivery) token in proj-B.
    callerTok, _ := s.issueDeliveryToken("proj-B")

    rr := s.postForm(s.app.IntrospectHandler, "/introspect", callerTok, url.Values{"token": {targetJti}})
    s.Equal(http.StatusOK, rr.Code)
    var raw map[string]any
    s.Require().NoError(json.Unmarshal(rr.Body.Bytes(), &raw))
    s.Equal(false, raw["active"], "cross-project introspect reports active:false (no leak)")
    s.NotContains(raw, "project_id", "cross-project introspect must not leak the target's project")
}

func (s *TokenAdminSuite) TestIntrospectSameProjectAllowedForNonAdmin() {
    _, targetJti := s.issueDeliveryToken("proj-A")
    callerTok, _ := s.issueDeliveryToken("proj-A")

    rr := s.postForm(s.app.IntrospectHandler, "/introspect", callerTok, url.Values{"token": {targetJti}})
    s.Equal(http.StatusOK, rr.Code)
    var raw map[string]any
    s.Require().NoError(json.Unmarshal(rr.Body.Bytes(), &raw))
    s.Equal(true, raw["active"], "same-project non-admin introspect is allowed and reports the live token")
}

func (s *TokenAdminSuite) TestIntrospectAdminUnrestricted() {
    _, targetJti := s.issueDeliveryToken("proj-A")
    adminTok := s.issueAdminToken("proj-B") // admin in a DIFFERENT project

    rr := s.postForm(s.app.IntrospectHandler, "/introspect", adminTok, url.Values{"token": {targetJti}})
    s.Equal(http.StatusOK, rr.Code)
    var raw map[string]any
    s.Require().NoError(json.Unmarshal(rr.Body.Bytes(), &raw))
    s.Equal(true, raw["active"], "admin/root is unrestricted across projects")
    s.Equal("proj-A", raw["project_id"])
}

func (s *TokenAdminSuite) TestRevokeCrossProjectStill200ButDoesNotRevoke() {
    targetTok, targetJti := s.issueDeliveryToken("proj-A")
    callerTok, _ := s.issueDeliveryToken("proj-B") // non-admin in another project

    rr := s.postForm(s.app.RevokeHandler, "/revoke", callerTok, url.Values{"token": {targetTok}})
    s.Equal(http.StatusOK, rr.Code, "RFC 7009 always-200, even when the project guard denies")

    // The target was NOT revoked.
    revoked, err := s.app.GetTokenService().IsRevoked(context.Background(), targetJti)
    s.Require().NoError(err)
    s.False(revoked, "cross-project /revoke must be a no-op")
}

func (s *TokenAdminSuite) TestRevokeSameProjectByNonAdminRevokes() {
    targetTok, targetJti := s.issueDeliveryToken("proj-A")
    callerTok, _ := s.issueDeliveryToken("proj-A")

    rr := s.postForm(s.app.RevokeHandler, "/revoke", callerTok, url.Values{"token": {targetTok}})
    s.Equal(http.StatusOK, rr.Code)
    revoked, err := s.app.GetTokenService().IsRevoked(context.Background(), targetJti)
    s.Require().NoError(err)
    s.True(revoked, "same-project non-admin revoke takes effect")
}

func (s *TokenAdminSuite) TestDeleteTokenCrossProjectDeniedForNonAdmin() {
    _, targetJti := s.issueDeliveryToken("proj-A")
    callerTok, _ := s.issueDeliveryToken("proj-B")

    rr := s.deleteToken(callerTok, targetJti)
    s.Equal(http.StatusForbidden, rr.Code, "admin-by-identifier path returns 403 on cross-project")
    revoked, err := s.app.GetTokenService().IsRevoked(context.Background(), targetJti)
    s.Require().NoError(err)
    s.False(revoked)
}

func (s *TokenAdminSuite) TestDeleteTokenAdminUnrestricted() {
    _, targetJti := s.issueDeliveryToken("proj-A")
    adminTok := s.issueAdminToken("proj-B")

    rr := s.deleteToken(adminTok, targetJti)
    s.Equal(http.StatusNoContent, rr.Code, "admin/root may revoke any project by identifier")
    revoked, err := s.app.GetTokenService().IsRevoked(context.Background(), targetJti)
    s.Require().NoError(err)
    s.True(revoked)
}

func TestTokenAdminSuite(t *testing.T) {
    suite.Run(t, new(TokenAdminSuite))
}

// muxSetVar attaches a mux route variable to a request, so handlers that read
// mux.Vars(r) (e.g. DELETE /token/{jti}) can be driven directly in tests.
func muxSetVar(r *http.Request, key, value string) *http.Request {
    return mux.SetURLVars(r, map[string]string{key: value})
}
