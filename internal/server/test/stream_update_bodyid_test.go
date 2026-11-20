package test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/i2-open/i2goSignals/pkg/authSupport"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// updateStreamNoQueryParam PATCHes/PUTs the /stream endpoint with NO stream_id
// query parameter, identifying the target only via the stream_id field in the
// body — the way SSF PUT/PATCH carry the full StreamConfiguration, and the way
// the OpenID conformance suite sends update/replace. Returns the HTTP response.
func updateStreamNoQueryParam(t *testing.T, instance *ssfInstance, method string, cfg model.StreamConfiguration) *http.Response {
	t.Helper()
	body, err := json.Marshal(cfg)
	require.NoError(t, err)
	// Note: no "?stream_id=" — the only stream identifier is cfg.Id in the body.
	req, err := http.NewRequest(method, instance.ts.URL+"/stream", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+instance.streamMgmtToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := instance.client.Do(req)
	require.NoError(t, err)
	return resp
}

// TestStreamUpdateResolvesStreamIdFromBody pins the fix for the PUT/PATCH 404:
// when the request omits the stream_id query parameter and supplies it only in
// the StreamConfiguration body, the handler must still locate and update the
// stream (it previously used authCtx.StreamId, which is populated only from the
// query parameter, and 404'd).
func TestStreamUpdateResolvesStreamIdFromBody(t *testing.T) {
	instance, err := createServer(t, "stream_update_bodyid_test", true)
	require.NoError(t, err)
	defer instance.app.Shutdown()

	created, err := instance.CreateStream(pollStreamConfig(), authSupport.ConvertProject(instance.projectId))
	require.NoError(t, err)
	require.NotEmpty(t, created.Id)

	// PATCH with stream_id only in the body.
	patchCfg := model.StreamConfiguration{
		Id:              created.Id,
		Description:     "patched via body stream_id",
		EventsRequested: created.EventsSupported,
	}
	resp := updateStreamNoQueryParam(t, instance, http.MethodPatch, patchCfg)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode, "PATCH with body-only stream_id must succeed (200), not 404")

	var patched model.StreamConfiguration
	body, _ := io.ReadAll(resp.Body)
	require.NoError(t, json.Unmarshal(body, &patched))
	assert.Equal(t, created.Id, patched.Id, "response must echo the same stream")

	// PUT (replace) the same way.
	putCfg := model.StreamConfiguration{
		Id:              created.Id,
		Description:     "replaced via body stream_id",
		EventsRequested: created.EventsSupported,
	}
	resp2 := updateStreamNoQueryParam(t, instance, http.MethodPut, putCfg)
	defer resp2.Body.Close()
	assert.Equal(t, http.StatusOK, resp2.StatusCode, "PUT with body-only stream_id must succeed (200), not 404")
}
