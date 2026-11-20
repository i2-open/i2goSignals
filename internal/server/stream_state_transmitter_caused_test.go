package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Issue #310: the transmitter-caused flag is shown on the admin stream-state
// surfaces (GET /state, GET /states) so the admin UI can tell a transmitter
// pause from an operator's, and stays off the SSF status response.
func TestStreamState_ShowsTransmitterCaused(t *testing.T) {
	app := newStatusRefreshApp(t)
	persistStatusPlain(t, app, model.StreamStateEnabled, "")
	app.StreamService.UpdateTransmitterCausedStatus(context.Background(), statusPlainSid, model.StreamStatePause, "Transmitter stream is paused: x")
	bearer := app.adminBearer(t)

	req := httptest.NewRequest(http.MethodGet, "/state?stream_id="+statusPlainSid, nil)
	req.Header.Set("Authorization", "Bearer "+bearer)
	rr := httptest.NewRecorder()
	GetStreamStateHandler(app, rr, req)
	require.Equal(t, http.StatusOK, rr.Code, "body: %s", rr.Body.String())
	var one map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &one))
	assert.Equal(t, true, one["transmitter_caused"], "GET /state shows the flag")

	req = httptest.NewRequest(http.MethodGet, "/states", nil)
	req.Header.Set("Authorization", "Bearer "+bearer)
	rr = httptest.NewRecorder()
	ListStreamStatesHandler(app, rr, req)
	require.Equal(t, http.StatusOK, rr.Code, "body: %s", rr.Body.String())
	var all []map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &all))
	require.Len(t, all, 1)
	assert.Equal(t, true, all[0]["transmitter_caused"], "GET /states shows the flag")

	status := app.getStatus(t, bearer, statusPlainSid)
	assert.Equal(t, model.StreamStatus{Status: model.StreamStatePause, Reason: "Transmitter stream is paused: x"}, status,
		"the SSF status response is unchanged")
}
