package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/i2-open/i2goSignals/internal/eventRouter"
	"github.com/i2-open/i2goSignals/internal/providers/dbProviders"
	"github.com/i2-open/i2goSignals/pkg/authSupport"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Issue #303: POST /status must resolve the SID the way GET /status does, so an
// SSTP pair can be set through its inbound SID as well as read, and a status
// write moves both halves of the pair, so "no change" is judged against both.

const (
	statusPairTxSid   = "status-pair-tx"
	statusPairRxSid   = "status-pair-rx"
	statusPairId      = "status-pair-wire"
	statusPlainSid    = "status-plain"
	statusTestProject = "status-proj"
)

// routerStateSpy records the router refresh UpdateStatusHandler runs when it
// judges a request modified. Every other EventRouter method is left nil: the
// handler reaches only UpdateStreamState.
type routerStateSpy struct {
	eventRouter.EventRouter
	updated []string
}

func (r *routerStateSpy) UpdateStreamState(stream *model.StreamStateRecord) {
	if stream == nil { // the real router ignores a nil record
		return
	}
	r.updated = append(r.updated, stream.StreamConfiguration.Id)
}

// statusRefreshApp is the real test application with the two refresh seams
// (router, receiver) observed instead of run, so a test can tell a modified
// request from a no-op.
type statusRefreshApp struct {
	*SignalsApplication
	router  *routerStateSpy
	handled []string
}

func (a *statusRefreshApp) GetEventRouter() eventRouter.EventRouter { return a.router }

func (a *statusRefreshApp) HandleReceiver(stream *model.StreamStateRecord) *ClientPollStream {
	a.handled = append(a.handled, stream.StreamConfiguration.Id)
	return nil
}

func (a *statusRefreshApp) refreshes() int { return len(a.router.updated) + len(a.handled) }

func (a *statusRefreshApp) resetRefreshes() {
	a.router.updated = nil
	a.handled = nil
}

func newStatusRefreshApp(t *testing.T) *statusRefreshApp {
	t.Helper()
	persistence, err := dbProviders.OpenPersistence("memorydb:", "update-status-sid-"+t.Name())
	require.NoError(t, err)
	require.NoError(t, persistence.KeyService.InitializeTokenKey(context.Background(), "DEFAULT"))
	app := newTestApplication(persistence)
	app.DefIssuer = "DEFAULT"
	return &statusRefreshApp{SignalsApplication: app, router: &routerStateSpy{}}
}

// persistStatusPair stores an SSTP pair whose two halves carry the given
// statuses and reasons.
func persistStatusPair(t *testing.T, app *statusRefreshApp, outStatus, outReason, inStatus, inReason string) {
	t.Helper()
	rec := &model.StreamStateRecord{
		ProjectId: statusTestProject,
		PairId:    statusPairId,
		StreamConfiguration: model.StreamConfiguration{
			Id:       statusPairTxSid,
			Delivery: &model.OneOfStreamConfigurationDelivery{SstpTransmitMarker: &model.SstpTransmitMarker{Method: model.DeliverySstp}},
		},
		SstpInbound: &model.StreamConfiguration{
			Id:       statusPairRxSid,
			Delivery: &model.OneOfStreamConfigurationDelivery{SstpReceiveMarker: &model.SstpReceiveMarker{Method: model.ReceiveSstp}},
		},
		SstpMethod: &model.SstpMethod{
			Role:        model.SstpRoleInitiator,
			EndpointUrl: "https://peer.example/sstp/peer-pair",
			PeerPairId:  "peer-pair",
		},
		Status:          outStatus,
		ErrorMsg:        outReason,
		InboundStatus:   inStatus,
		InboundErrorMsg: inReason,
	}
	require.NoError(t, app.StreamService.PersistStreamStateRecord(context.Background(), rec))
}

func persistStatusPlain(t *testing.T, app *statusRefreshApp, status, reason string) {
	t.Helper()
	rec := &model.StreamStateRecord{
		ProjectId: statusTestProject,
		StreamConfiguration: model.StreamConfiguration{
			Id:       statusPlainSid,
			Delivery: &model.OneOfStreamConfigurationDelivery{PollTransmitMethod: &model.PollTransmitMethod{Method: model.DeliveryPoll}},
		},
		Status:   status,
		ErrorMsg: reason,
	}
	require.NoError(t, app.StreamService.PersistStreamStateRecord(context.Background(), rec))
}

func (a *statusRefreshApp) pairBearer(t *testing.T) string {
	t.Helper()
	tok, err := a.GetAuth().IssueSstpPairToken(statusPairTxSid, statusPairRxSid, statusTestProject, false, nil)
	require.NoError(t, err)
	return tok
}

// adminBearer is a broad-scope token: no stream binding, authorizes any stream
// in the project when the request names one.
func (a *statusRefreshApp) adminBearer(t *testing.T) string {
	t.Helper()
	client := model.SsfClient{Id: model.NewRecordId(), ProjectIds: []string{statusTestProject}}
	tok, err := a.GetAuth().IssueStreamClientToken(client, statusTestProject, true, "")
	require.NoError(t, err)
	return tok
}

// boundMgmtBearer is a stream client's limited-scope token: stream-management
// scope bound to exactly one stream. No issuer mints this shape for status
// writes today, so it is signed here with the issuer's own key.
func (a *statusRefreshApp) boundMgmtBearer(t *testing.T, sid string) string {
	t.Helper()
	auth := a.GetAuth()
	require.NotNil(t, auth)
	kid := auth.TokenKid
	if kid == "" {
		kid = auth.TokenIssuer
	}
	eat := authSupport.EventAuthToken{
		StreamIds: []string{sid},
		ProjectId: statusTestProject,
		Roles:     []string{authSupport.ScopeStreamMgmt},
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			Audience:  []string{auth.TokenIssuer},
			Issuer:    auth.TokenIssuer,
			ID:        goSet.GenerateJti(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, eat)
	token.Header["typ"] = "jwt"
	token.Header["kid"] = kid
	signed, err := token.SignedString(auth.PrivateKey)
	require.NoError(t, err)
	return signed
}

func (a *statusRefreshApp) postStatus(t *testing.T, bearer, sid, status, reason string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(model.UpdateStreamStatus{Status: status, Reason: reason})
	require.NoError(t, err)
	target := "/status"
	if sid != "" {
		target += "?stream_id=" + sid
	}
	req := httptest.NewRequest(http.MethodPost, target, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+bearer)
	rr := httptest.NewRecorder()
	UpdateStatusHandler(a, rr, req)
	return rr
}

func (a *statusRefreshApp) getStatus(t *testing.T, bearer, sid string) model.StreamStatus {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/status?stream_id="+sid, nil)
	req.Header.Set("Authorization", "Bearer "+bearer)
	rr := httptest.NewRecorder()
	GetStatusHandler(a, rr, req)
	require.Equal(t, http.StatusOK, rr.Code, "GET /status on %s", sid)
	var got model.StreamStatus
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &got))
	return got
}

func decodeStatus(t *testing.T, rr *httptest.ResponseRecorder) model.StreamStatus {
	t.Helper()
	var got model.StreamStatus
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &got), "body: %s", rr.Body.String())
	return got
}

// TestUpdateStatus_SstpPairBySID is the SID × status table over an SSTP pair:
// either SID resolves (no 404), and every status — enabled, paused, disabled —
// moves both halves whichever SID names it, the same single status a push/poll
// stream carries (#303). A status POSTed on either SID reads back identically
// through GET /status on BOTH SIDs, and the response reports it.
func TestUpdateStatus_SstpPairBySID(t *testing.T) {
	const reason = "operator action"
	transitions := []struct{ from, to string }{
		{model.StreamStateEnabled, model.StreamStatePause},
		{model.StreamStateEnabled, model.StreamStateDisable},
		{model.StreamStatePause, model.StreamStateEnabled},
		{model.StreamStatePause, model.StreamStateDisable},
		{model.StreamStateDisable, model.StreamStateEnabled},
		{model.StreamStateDisable, model.StreamStatePause},
	}
	for _, tr := range transitions {
		for _, sid := range []string{statusPairTxSid, statusPairRxSid} {
			t.Run(tr.from+" to "+tr.to+" via "+sid, func(t *testing.T) {
				app := newStatusRefreshApp(t)
				persistStatusPair(t, app, tr.from, "start", tr.from, "start")
				bearer := app.pairBearer(t)

				rr := app.postStatus(t, bearer, sid, tr.to, reason)
				require.Equal(t, http.StatusOK, rr.Code, "POST /status on %s: %s", sid, rr.Body.String())
				want := model.StreamStatus{Status: tr.to, Reason: reason}
				assert.Equal(t, want, decodeStatus(t, rr), "the response reports the pair's status")
				assert.Len(t, app.router.updated, 1, "a status change refreshes the router")
				assert.Len(t, app.handled, 1, "a status change refreshes the receiver")

				assert.Equal(t, want, app.getStatus(t, bearer, statusPairTxSid), "outbound half via GET /status")
				assert.Equal(t, want, app.getStatus(t, bearer, statusPairRxSid), "inbound half via GET /status")
			})
		}
	}
}

// TestUpdateStatus_SstpPauseByRxSidPausesPair: a pause named by the rx SID
// pauses the whole pair — both halves — and refreshes the pair in the router
// exactly once (#303).
func TestUpdateStatus_SstpPauseByRxSidPausesPair(t *testing.T) {
	const reason = "peer maintenance"
	app := newStatusRefreshApp(t)
	persistStatusPair(t, app, model.StreamStateEnabled, "", model.StreamStateEnabled, "")
	bearer := app.pairBearer(t)

	rr := app.postStatus(t, bearer, statusPairRxSid, model.StreamStatePause, reason)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())

	assert.Equal(t, []string{statusPairTxSid}, app.router.updated, "the pair record is refreshed in the router once")
	assert.Len(t, app.handled, 1, "the pair record is refreshed in the receiver once")
	paused := model.StreamStatus{Status: model.StreamStatePause, Reason: reason}
	assert.Equal(t, paused, app.getStatus(t, bearer, statusPairTxSid), "the outbound half is paused too")
	assert.Equal(t, paused, app.getStatus(t, bearer, statusPairRxSid))
}

// TestUpdateStatus_SstpSplitRecordHeals: a legacy split record — halves that
// differ, as the superseded per-direction routing could leave behind — is
// healed by a write that matches only ONE half. The write moves both halves, so
// it is a change whichever half already matched and whichever SID names it, and
// the router and receiver are refreshed.
func TestUpdateStatus_SstpSplitRecordHeals(t *testing.T) {
	const reason = "peer maintenance"
	tests := []struct {
		name     string
		startOut model.StreamStatus
		startIn  model.StreamStatus
		sid      string
		status   string
	}{
		{
			name:     "inbound half already matches, named by the rx SID",
			startOut: model.StreamStatus{Status: model.StreamStateEnabled},
			startIn:  model.StreamStatus{Status: model.StreamStatePause, Reason: reason},
			sid:      statusPairRxSid,
			status:   model.StreamStatePause,
		},
		{
			name:     "outbound half already matches, named by the rx SID",
			startOut: model.StreamStatus{Status: model.StreamStatePause, Reason: reason},
			startIn:  model.StreamStatus{Status: model.StreamStateEnabled},
			sid:      statusPairRxSid,
			status:   model.StreamStatePause,
		},
		{
			name:     "outbound half already matches, named by the tx SID",
			startOut: model.StreamStatus{Status: model.StreamStateEnabled, Reason: reason},
			startIn:  model.StreamStatus{Status: model.StreamStatePause},
			sid:      statusPairTxSid,
			status:   model.StreamStateEnabled,
		},
		{
			name:     "a half-disabled pair named by its already-disabled rx SID",
			startOut: model.StreamStatus{Status: model.StreamStateEnabled},
			startIn:  model.StreamStatus{Status: model.StreamStateDisable, Reason: reason},
			sid:      statusPairRxSid,
			status:   model.StreamStateDisable,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := newStatusRefreshApp(t)
			persistStatusPair(t, app, tt.startOut.Status, tt.startOut.Reason, tt.startIn.Status, tt.startIn.Reason)
			bearer := app.pairBearer(t)

			rr := app.postStatus(t, bearer, tt.sid, tt.status, reason)
			require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())

			assert.Len(t, app.router.updated, 1, "healing a split record is a change and refreshes the router")
			assert.Len(t, app.handled, 1, "healing a split record is a change and refreshes the receiver")
			want := model.StreamStatus{Status: tt.status, Reason: reason}
			assert.Equal(t, want, app.getStatus(t, bearer, statusPairTxSid), "outbound half via GET /status")
			assert.Equal(t, want, app.getStatus(t, bearer, statusPairRxSid), "inbound half via GET /status")
		})
	}
}

// TestUpdateStatus_SstpPairNoOpStaysNoOp: a write whose status and reason
// already match BOTH halves is a no-op through either SID — nothing to change,
// so no router or receiver refresh.
func TestUpdateStatus_SstpPairNoOpStaysNoOp(t *testing.T) {
	const reason = "outage"
	for _, status := range []string{model.StreamStateEnabled, model.StreamStatePause, model.StreamStateDisable} {
		for _, sid := range []string{statusPairTxSid, statusPairRxSid} {
			t.Run(status+" via "+sid, func(t *testing.T) {
				app := newStatusRefreshApp(t)
				persistStatusPair(t, app, status, reason, status, reason)
				bearer := app.pairBearer(t)

				rr := app.postStatus(t, bearer, sid, status, reason)
				require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())

				assert.Equal(t, 0, app.refreshes(), "a no-op must not refresh the router or receiver")
				want := model.StreamStatus{Status: status, Reason: reason}
				assert.Equal(t, want, decodeStatus(t, rr))
				assert.Equal(t, want, app.getStatus(t, bearer, statusPairTxSid))
				assert.Equal(t, want, app.getStatus(t, bearer, statusPairRxSid))
			})
		}
	}
}

// TestUpdateStatus_NonSstpStreamUnaffected pins the plain-stream path: the SID
// falls through to the document lookup, a change is applied and refreshed, and
// repeating it is a no-op.
func TestUpdateStatus_NonSstpStreamUnaffected(t *testing.T) {
	const reason = "maintenance"
	app := newStatusRefreshApp(t)
	persistStatusPlain(t, app, model.StreamStateEnabled, "")
	bearer := app.adminBearer(t)

	rr := app.postStatus(t, bearer, statusPlainSid, model.StreamStatePause, reason)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Equal(t, model.StreamStatus{Status: model.StreamStatePause, Reason: reason}, decodeStatus(t, rr))
	assert.Equal(t, []string{statusPlainSid}, app.router.updated)
	assert.Equal(t, []string{statusPlainSid}, app.handled)

	app.resetRefreshes()
	rr = app.postStatus(t, bearer, statusPlainSid, model.StreamStatePause, reason)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Equal(t, 0, app.refreshes(), "repeating the same status is a no-op")

	rr = app.postStatus(t, bearer, "no-such-stream", model.StreamStatePause, reason)
	assert.NotEqual(t, http.StatusOK, rr.Code, "an unknown SID is not found")
}

// TestUpdateStatus_TokenBindingFallback pins #303 item 3 at the handler: with no
// stream_id parameter, a token bound to exactly one stream acts on that stream,
// while a broad-scope token — and a pair bearer binding two SIDs — still 403.
func TestUpdateStatus_TokenBindingFallback(t *testing.T) {
	const reason = "client pause"

	t.Run("stream-bound token resolves to its own stream", func(t *testing.T) {
		app := newStatusRefreshApp(t)
		persistStatusPlain(t, app, model.StreamStateEnabled, "")

		rr := app.postStatus(t, app.boundMgmtBearer(t, statusPlainSid), "", model.StreamStatePause, reason)
		require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
		assert.Equal(t, model.StreamStatus{Status: model.StreamStatePause, Reason: reason}, decodeStatus(t, rr))
		assert.Equal(t, model.StreamStatus{Status: model.StreamStatePause, Reason: reason}, app.getStatus(t, app.adminBearer(t), statusPlainSid))
	})

	t.Run("stream-bound token on a pair's inbound SID resolves to the pair", func(t *testing.T) {
		app := newStatusRefreshApp(t)
		persistStatusPair(t, app, model.StreamStateEnabled, "", model.StreamStateEnabled, "")

		rr := app.postStatus(t, app.boundMgmtBearer(t, statusPairRxSid), "", model.StreamStatePause, reason)
		require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
		bearer := app.pairBearer(t)
		paused := model.StreamStatus{Status: model.StreamStatePause, Reason: reason}
		assert.Equal(t, paused, app.getStatus(t, bearer, statusPairRxSid))
		assert.Equal(t, paused, app.getStatus(t, bearer, statusPairTxSid), "a status write moves both halves (#303)")
	})

	t.Run("broad-scope token with no parameter is forbidden", func(t *testing.T) {
		app := newStatusRefreshApp(t)
		persistStatusPlain(t, app, model.StreamStateEnabled, "")

		rr := app.postStatus(t, app.adminBearer(t), "", model.StreamStatePause, reason)
		assert.Equal(t, http.StatusForbidden, rr.Code)
		assert.Equal(t, 0, app.refreshes())
	})

	t.Run("pair bearer binding two SIDs with no parameter is forbidden", func(t *testing.T) {
		app := newStatusRefreshApp(t)
		persistStatusPair(t, app, model.StreamStateEnabled, "", model.StreamStateEnabled, "")

		rr := app.postStatus(t, app.pairBearer(t), "", model.StreamStatePause, reason)
		assert.Equal(t, http.StatusForbidden, rr.Code)
		assert.Equal(t, 0, app.refreshes())
	})
}

// TestStreamUpdate_BoundTokenRejectsMismatchedBodyStreamId pins the update
// handler against the #303 token fallback: a single-stream token that names no
// stream_id parameter now resolves authCtx.StreamId to its own stream, so a body
// stream_id naming a DIFFERENT stream must be refused (as verify, subject
// add/remove and subject-filter review refuse it) rather than silently applied
// to the token's stream. PUT (replace) and PATCH share the handler.
func TestStreamUpdate_BoundTokenRejectsMismatchedBodyStreamId(t *testing.T) {
	const otherSid = "status-plain-other"
	for _, method := range []string{http.MethodPut, http.MethodPatch} {
		t.Run(method, func(t *testing.T) {
			app := newStatusRefreshApp(t)
			persistStatusPlain(t, app, model.StreamStateEnabled, "")
			require.NoError(t, app.StreamService.PersistStreamStateRecord(context.Background(), &model.StreamStateRecord{
				ProjectId: statusTestProject,
				StreamConfiguration: model.StreamConfiguration{
					Id:       otherSid,
					Delivery: &model.OneOfStreamConfigurationDelivery{PollTransmitMethod: &model.PollTransmitMethod{Method: model.DeliveryPoll}},
				},
				Status: model.StreamStateEnabled,
			}))

			body, err := json.Marshal(map[string]any{"stream_id": otherSid, "description": "retargeted"})
			require.NoError(t, err)
			req := httptest.NewRequest(method, "/stream", bytes.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+app.boundMgmtBearer(t, statusPlainSid))
			rr := httptest.NewRecorder()
			StreamUpdateHandler(app, rr, req)

			assert.Equal(t, http.StatusForbidden, rr.Code, rr.Body.String())
			assert.Equal(t, 0, app.refreshes(), "a refused update must not refresh the router or receiver")
			for _, sid := range []string{statusPlainSid, otherSid} {
				stored, err := app.StreamService.GetStreamState(context.Background(), sid)
				require.NoError(t, err)
				assert.Empty(t, stored.Description, "stream %s must not be modified", sid)
			}
		})
	}
}
