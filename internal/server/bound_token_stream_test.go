package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Issue #303 review ruling: a stream-bound token (a local EAT with non-empty
// StreamIds) operates ONLY on its bound streams, however the stream is named.
// The stream_id parameter and path var are confined in ValidateAuthorizationAny
// (pinned in pkg/authSupport); these tests pin the body stream_id at the four
// handlers that accept one, and that an unbound token keeps each handler's
// pre-#303 rule.

const boundOtherSid = "bound-other-stream"

// GenerateVerifyEvent lets VerificationRequestHandler complete against the
// status spy router; the verify SET itself is not under test here.
func (r *routerStateSpy) GenerateVerifyEvent(string, string) (*model.EventRecord, error) {
	return &model.EventRecord{}, nil
}

// bodySite drives one handler that takes a body stream_id.
type bodySite struct {
	name    string
	method  string
	path    string
	handler func(SsfApplicationInterface, http.ResponseWriter, *http.Request)
	body    func(sid string) map[string]any
}

func bodyStreamSites() []bodySite {
	subject := map[string]any{"format": "email", "email": "alice@example.com"}
	return []bodySite{
		{"verify", http.MethodPost, "/verify", VerificationRequestHandler,
			func(sid string) map[string]any { return map[string]any{"stream_id": sid} }},
		{"add-subject", http.MethodPost, "/add-subject", AddSubjectHandler,
			func(sid string) map[string]any { return map[string]any{"stream_id": sid, "subject": subject} }},
		{"remove-subject", http.MethodPost, "/remove-subject", RemoveSubjectHandler,
			func(sid string) map[string]any { return map[string]any{"stream_id": sid, "subject": subject} }},
		{"subject-filter review", http.MethodPost, "/subject-filter/review", ReviewSubjectFilterHandler,
			func(sid string) map[string]any { return map[string]any{"stream_id": sid, "subject": subject} }},
		{"stream update", http.MethodPut, "/stream", StreamUpdateHandler,
			func(sid string) map[string]any { return map[string]any{"stream_id": sid, "description": "updated"} }},
	}
}

func (a *statusRefreshApp) callBodySite(t *testing.T, site bodySite, bearer, querySid, bodySid string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(site.body(bodySid))
	require.NoError(t, err)
	target := site.path
	if querySid != "" {
		target += "?stream_id=" + querySid
	}
	req := httptest.NewRequest(site.method, target, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+bearer)
	rr := httptest.NewRecorder()
	site.handler(a, rr, req)
	return rr
}

// newBoundTokenApp stores a plain stream, a second plain stream and an SSTP
// pair, with subject filtering on so the subject handlers reach their checks.
func newBoundTokenApp(t *testing.T) *statusRefreshApp {
	t.Helper()
	t.Setenv("I2SIG_SUBJECT_FILTERING", "ENABLED")
	app := newStatusRefreshApp(t)
	persistStatusPlain(t, app, model.StreamStateEnabled, "")
	require.NoError(t, app.StreamService.PersistStreamStateRecord(context.Background(), &model.StreamStateRecord{
		ProjectId: statusTestProject,
		StreamConfiguration: model.StreamConfiguration{
			Id:       boundOtherSid,
			Delivery: &model.OneOfStreamConfigurationDelivery{PollTransmitMethod: &model.PollTransmitMethod{Method: model.DeliveryPoll}},
		},
		Status: model.StreamStateEnabled,
	}))
	persistStatusPair(t, app, model.StreamStateEnabled, "", model.StreamStateEnabled, "")
	return app
}

func storedDescription(t *testing.T, app *statusRefreshApp, sid string) string {
	t.Helper()
	rec, err := app.StreamService.GetStreamState(context.Background(), sid)
	require.NoError(t, err)
	return rec.Description
}

// TestBodyStreamId_BoundTokenConfinedToItsStreams: at every body-stream_id
// site a bound token is refused when the body names a stream outside its
// binding, or a stream other than the one the request resolved to, and no
// stream is modified.
func TestBodyStreamId_BoundTokenConfinedToItsStreams(t *testing.T) {
	for _, site := range bodyStreamSites() {
		t.Run(site.name, func(t *testing.T) {
			cases := []struct {
				name     string
				bearer   func(*statusRefreshApp) string
				querySid string
				bodySid  string
			}{
				{"single-stream token, no parameter, body names another stream",
					func(a *statusRefreshApp) string { return a.boundMgmtBearer(t, statusPlainSid) }, "", boundOtherSid},
				{"single-stream token, own parameter, body names another stream",
					func(a *statusRefreshApp) string { return a.boundMgmtBearer(t, statusPlainSid) }, statusPlainSid, boundOtherSid},
				{"pair bearer, no parameter, body names a stream outside the pair",
					func(a *statusRefreshApp) string { return a.pairBearer(t) }, "", boundOtherSid},
				{"pair bearer, tx parameter, body names its rx SID",
					func(a *statusRefreshApp) string { return a.pairBearer(t) }, statusPairTxSid, statusPairRxSid},
			}
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					app := newBoundTokenApp(t)
					rr := app.callBodySite(t, site, tc.bearer(app), tc.querySid, tc.bodySid)
					assert.Equal(t, http.StatusForbidden, rr.Code, rr.Body.String())
					assert.Equal(t, 0, app.refreshes(), "a refused request must not refresh the router or receiver")
					for _, sid := range []string{statusPlainSid, boundOtherSid, statusPairTxSid} {
						assert.Empty(t, storedDescription(t, app, sid), "stream %s must not be modified", sid)
					}
				})
			}
		})
	}
}

// TestBodyStreamId_PairBearerWorksOnItsOwnSIDs: the binding check admits a pair
// bearer naming either of its own SIDs with no parameter. What each handler
// does next (a verify SET, a 404 from the absent subject-filter service, the
// rx-side subject guidance) is its own business; it is not a 403. Stream update
// is driven through the tx SID only: its post-update re-read is a document _id
// lookup that an rx SID does not satisfy, which is outside this rule.
func TestBodyStreamId_PairBearerWorksOnItsOwnSIDs(t *testing.T) {
	for _, site := range bodyStreamSites() {
		sids := []string{statusPairTxSid, statusPairRxSid}
		if site.name == "stream update" {
			sids = sids[:1]
		}
		for _, sid := range sids {
			t.Run(site.name+" "+sid, func(t *testing.T) {
				app := newBoundTokenApp(t)
				rr := app.callBodySite(t, site, app.pairBearer(t), "", sid)
				assert.NotEqual(t, http.StatusForbidden, rr.Code, rr.Body.String())
				assert.Less(t, rr.Code, http.StatusInternalServerError, rr.Body.String())
			})
		}
	}
}

// TestBodyStreamId_UnboundTokenKeepsPreFixRule: an unbound (broad-scope) token
// is not confined by the binding rule, so each handler keeps what it did before
// #303. Verify, subject add/remove and review refuse a parameter that differs
// from the body; stream update acts on the parameter's stream. With no
// parameter, every site accepts the body's stream.
func TestBodyStreamId_UnboundTokenKeepsPreFixRule(t *testing.T) {
	for _, site := range bodyStreamSites() {
		t.Run(site.name, func(t *testing.T) {
			t.Run("parameter differs from body", func(t *testing.T) {
				app := newBoundTokenApp(t)
				rr := app.callBodySite(t, site, app.adminBearer(t), statusPlainSid, boundOtherSid)
				if site.name == "stream update" {
					require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
					assert.Equal(t, "updated", storedDescription(t, app, statusPlainSid), "the parameter's stream is updated")
					assert.Empty(t, storedDescription(t, app, boundOtherSid), "the body's stream is not")
					return
				}
				assert.Equal(t, http.StatusForbidden, rr.Code, rr.Body.String())
			})
			t.Run("no parameter", func(t *testing.T) {
				app := newBoundTokenApp(t)
				rr := app.callBodySite(t, site, app.adminBearer(t), "", boundOtherSid)
				assert.NotEqual(t, http.StatusForbidden, rr.Code, rr.Body.String())
				assert.Less(t, rr.Code, http.StatusInternalServerError, rr.Body.String())
			})
		})
	}
}
