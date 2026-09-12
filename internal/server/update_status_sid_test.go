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
// SSTP pair's inbound half can be set as well as read, and must judge "no
// change" against the half the SID names.

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
// either SID resolves (no 404), paused moves only the half the SID names, and
// disabled couples both halves whichever SID is named (applyStreamStatusToRecord).
// Every write round-trips through GET /status on both SIDs.
func TestUpdateStatus_SstpPairBySID(t *testing.T) {
	const reason = "operator action"
	tests := []struct {
		name        string
		sid         string
		status      string
		wantOut     model.StreamStatus
		wantIn      model.StreamStatus
		wantRespond model.StreamStatus
	}{
		{
			name:        "outbound SID paused moves only the outbound half",
			sid:         statusPairTxSid,
			status:      model.StreamStatePause,
			wantOut:     model.StreamStatus{Status: model.StreamStatePause, Reason: reason},
			wantIn:      model.StreamStatus{Status: model.StreamStateEnabled},
			wantRespond: model.StreamStatus{Status: model.StreamStatePause, Reason: reason},
		},
		{
			name:        "inbound SID paused moves only the inbound half",
			sid:         statusPairRxSid,
			status:      model.StreamStatePause,
			wantOut:     model.StreamStatus{Status: model.StreamStateEnabled},
			wantIn:      model.StreamStatus{Status: model.StreamStatePause, Reason: reason},
			wantRespond: model.StreamStatus{Status: model.StreamStatePause, Reason: reason},
		},
		{
			name:        "outbound SID disabled couples both halves",
			sid:         statusPairTxSid,
			status:      model.StreamStateDisable,
			wantOut:     model.StreamStatus{Status: model.StreamStateDisable, Reason: reason},
			wantIn:      model.StreamStatus{Status: model.StreamStateDisable, Reason: reason},
			wantRespond: model.StreamStatus{Status: model.StreamStateDisable, Reason: reason},
		},
		{
			name:        "inbound SID disabled couples both halves",
			sid:         statusPairRxSid,
			status:      model.StreamStateDisable,
			wantOut:     model.StreamStatus{Status: model.StreamStateDisable, Reason: reason},
			wantIn:      model.StreamStatus{Status: model.StreamStateDisable, Reason: reason},
			wantRespond: model.StreamStatus{Status: model.StreamStateDisable, Reason: reason},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := newStatusRefreshApp(t)
			persistStatusPair(t, app, model.StreamStateEnabled, "", model.StreamStateEnabled, "")
			bearer := app.pairBearer(t)

			rr := app.postStatus(t, bearer, tt.sid, tt.status, reason)
			require.Equal(t, http.StatusOK, rr.Code, "POST /status on %s: %s", tt.sid, rr.Body.String())
			assert.Equal(t, tt.wantRespond, decodeStatus(t, rr), "the response reports the named half")
			assert.Equal(t, 1, len(app.router.updated), "a status change refreshes the router")
			assert.Equal(t, 1, len(app.handled), "a status change refreshes the receiver")

			assert.Equal(t, tt.wantOut, app.getStatus(t, bearer, statusPairTxSid), "outbound half via GET /status")
			assert.Equal(t, tt.wantIn, app.getStatus(t, bearer, statusPairRxSid), "inbound half via GET /status")
		})
	}
}

// TestUpdateStatus_InboundOnlyChangeIsModified is the case the outbound-only
// comparison judged a no-op: the outbound half already holds the requested
// status and reason, the inbound half does not. Naming the inbound SID must
// change the inbound half and run the router/receiver refresh.
func TestUpdateStatus_InboundOnlyChangeIsModified(t *testing.T) {
	const reason = "peer maintenance"
	app := newStatusRefreshApp(t)
	persistStatusPair(t, app, model.StreamStatePause, reason, model.StreamStateEnabled, "")
	bearer := app.pairBearer(t)

	rr := app.postStatus(t, bearer, statusPairRxSid, model.StreamStatePause, reason)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())

	assert.Equal(t, 1, len(app.router.updated), "an inbound-only change must refresh the router")
	assert.Equal(t, 1, len(app.handled), "an inbound-only change must refresh the receiver")
	assert.Equal(t, model.StreamStatus{Status: model.StreamStatePause, Reason: reason}, app.getStatus(t, bearer, statusPairRxSid))
	assert.Equal(t, model.StreamStatus{Status: model.StreamStatePause, Reason: reason}, app.getStatus(t, bearer, statusPairTxSid))
}

// TestUpdateStatus_InboundNoOpStaysNoOp is the converse: the halves differ, the
// inbound half already holds the requested status and reason. Comparing the
// outbound half would call that a change; it is not one.
func TestUpdateStatus_InboundNoOpStaysNoOp(t *testing.T) {
	const reason = "peer maintenance"
	app := newStatusRefreshApp(t)
	persistStatusPair(t, app, model.StreamStateEnabled, "", model.StreamStatePause, reason)
	bearer := app.pairBearer(t)

	rr := app.postStatus(t, bearer, statusPairRxSid, model.StreamStatePause, reason)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())

	assert.Equal(t, 0, app.refreshes(), "a genuine inbound no-op must not refresh the router or receiver")
	assert.Equal(t, model.StreamStatus{Status: model.StreamStatePause, Reason: reason}, decodeStatus(t, rr))
	assert.Equal(t, model.StreamStatus{Status: model.StreamStateEnabled}, app.getStatus(t, bearer, statusPairTxSid))
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

	t.Run("stream-bound token on a pair's inbound SID resolves to that half", func(t *testing.T) {
		app := newStatusRefreshApp(t)
		persistStatusPair(t, app, model.StreamStateEnabled, "", model.StreamStateEnabled, "")

		rr := app.postStatus(t, app.boundMgmtBearer(t, statusPairRxSid), "", model.StreamStatePause, reason)
		require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
		bearer := app.pairBearer(t)
		assert.Equal(t, model.StreamStatus{Status: model.StreamStatePause, Reason: reason}, app.getStatus(t, bearer, statusPairRxSid))
		assert.Equal(t, model.StreamStatus{Status: model.StreamStateEnabled}, app.getStatus(t, bearer, statusPairTxSid))
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
