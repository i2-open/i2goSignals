package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/i2-open/i2goSignals/internal/eventRouter"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Issue #303: PUT/PATCH /stream must resolve the SID the way UpdateStream
// does. UpdateStream already routes an SSTP pair's inbound SID to the pair
// record, but the handler's own lookups keyed on the document _id, so an
// inbound SID found nothing: the credential merge was skipped and the router
// and receiver refresh ran on a nil record.

const streamPairPeerBearer = "Bearer peer-pair-secret"

// routerOnlyApp observes the router refresh but runs the real HandleReceiver,
// so a nil record reaching it fails the way it does in the server.
type routerOnlyApp struct {
	*SignalsApplication
	router *routerStateSpy
}

func (a *routerOnlyApp) GetEventRouter() eventRouter.EventRouter { return a.router }

func (a *statusRefreshApp) putStream(t *testing.T, bearer, sid string, patch model.StreamStateRecord) *httptest.ResponseRecorder {
	t.Helper()
	sa := &routerOnlyApp{SignalsApplication: a.SignalsApplication, router: a.router}
	body, err := json.Marshal(patch)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPut, "/stream?stream_id="+sid, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+bearer)
	rr := httptest.NewRecorder()
	StreamUpdateHandler(sa, rr, req)
	return rr
}

func persistStreamPairWithBearer(t *testing.T, app *statusRefreshApp) {
	t.Helper()
	persistStatusPair(t, app, model.StreamStateEnabled, "", model.StreamStateEnabled, "")
	rec, err := app.StreamService.GetStreamStateBySID(context.Background(), statusPairTxSid)
	require.NoError(t, err)
	rec.SstpMethod.AuthorizationHeader = streamPairPeerBearer
	require.NoError(t, app.StreamService.PersistStreamStateRecord(context.Background(), rec))
}

func TestUpdateStream_PairSidRefreshesPairRecord(t *testing.T) {
	for _, sid := range []string{statusPairTxSid, statusPairRxSid} {
		t.Run(sid, func(t *testing.T) {
			app := newStatusRefreshApp(t)
			persistStatusPair(t, app, model.StreamStateEnabled, "", model.StreamStateEnabled, "")

			var rr *httptest.ResponseRecorder
			require.NotPanics(t, func() {
				rr = app.putStream(t, app.adminBearer(t), sid, model.StreamStateRecord{
					StreamConfiguration: model.StreamConfiguration{Iss: "https://issuer.example/" + sid},
				})
			})
			require.Equal(t, http.StatusOK, rr.Code, "body: %s", rr.Body.String())
			assert.Equal(t, []string{statusPairTxSid}, app.router.updated, "router refreshed with the pair record")

			rec, err := app.StreamService.GetStreamStateBySID(context.Background(), statusPairTxSid)
			require.NoError(t, err)
			target := rec.StreamConfiguration
			if sid == statusPairRxSid {
				target = *rec.SstpInbound
			}
			assert.Equal(t, "https://issuer.example/"+sid, target.Iss, "patch lands on the direction the SID names")
		})
	}
}

func TestUpdateStream_PairSidKeepsMaskedPeerBearer(t *testing.T) {
	for _, sid := range []string{statusPairTxSid, statusPairRxSid} {
		t.Run(sid, func(t *testing.T) {
			app := newStatusRefreshApp(t)
			persistStreamPairWithBearer(t, app)

			rr := app.putStream(t, app.adminBearer(t), sid, model.StreamStateRecord{
				SstpMethod: &model.SstpMethod{AuthorizationHeader: model.MaskedCredentialValue},
			})
			require.Equal(t, http.StatusOK, rr.Code, "body: %s", rr.Body.String())

			rec, err := app.StreamService.GetStreamStateBySID(context.Background(), statusPairTxSid)
			require.NoError(t, err)
			assert.Equal(t, streamPairPeerBearer, rec.SstpMethod.AuthorizationHeader, "an echoed mask must not overwrite the stored bearer")
		})
	}
}
