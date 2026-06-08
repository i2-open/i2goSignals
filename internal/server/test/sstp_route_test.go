package test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/i2-open/i2goSignals/pkg/goSetSstp"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/v2/bson"
)

// sstpTestPair provisions an SSTP pair record directly via the storage seam and
// mints the matching pair bearer (StreamIds=[txSid, rxSid]). PairId is the
// on-wire SSF stream_id used in the /sstp/{id} path; txSid/rxSid are the internal
// authorization SIDs the middleware verifies via FindByPairId defense-in-depth.
type sstpTestPair struct {
	pairId string
	txSid  string
	rxSid  string
	bearer string
}

func newSstpTestPair(t *testing.T, instance *ssfInstance, status string) *sstpTestPair {
	t.Helper()

	txSid := bson.NewObjectID().Hex()
	rxSid := bson.NewObjectID().Hex()
	pairId := bson.NewObjectID().Hex()

	rec := &model.StreamStateRecord{
		StreamConfiguration: model.StreamConfiguration{
			Id:  txSid,
			Iss: "DEFAULT",
			Aud: []string{"peer.example.com"},
		},
		SstpInbound: &model.StreamConfiguration{
			Id:  rxSid,
			Iss: "peer.example.com",
			Aud: []string{"DEFAULT"},
		},
		SstpMethod: &model.SstpMethod{
			Role: "responder",
		},
		PairId:    pairId,
		ProjectId: instance.projectId,
		Status:    status,
	}
	err := instance.streamSvc().PersistStreamStateRecord(context.Background(), rec)
	require.NoError(t, err, "persist SSTP pair record")

	bearer, err := instance.GetAuthIssuer().IssueSstpPairToken(txSid, rxSid, instance.projectId, false, nil)
	require.NoError(t, err, "mint SSTP pair token")

	return &sstpTestPair{pairId: pairId, txSid: txSid, rxSid: rxSid, bearer: bearer}
}

func (p *sstpTestPair) post(t *testing.T, instance *ssfInstance, contentType string, bearer string) *http.Response {
	t.Helper()
	url := fmt.Sprintf("http://%s/sstp/%s", instance.host, p.pairId)
	body, _ := json.Marshal(goSetSstp.Message{})
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	require.NoError(t, err)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := instance.client.Do(req)
	require.NoError(t, err)
	return resp
}

func TestSstpRoute(t *testing.T) {
	instance, err := createServer(t, "sstp-route", true)
	require.NoError(t, err)
	defer func() {
		if instance.ts != nil {
			instance.ts.Close()
		}
		instance.app.Shutdown()
	}()

	t.Run("PausedPairReturns200ReturnEventsFalse", func(t *testing.T) {
		pair := newSstpTestPair(t, instance, model.StreamStatePause)
		resp := pair.post(t, instance, goSetSstp.ContentType, pair.bearer)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode, "paused pair returns 200, not 4xx")
		body, _ := io.ReadAll(resp.Body)
		var msg goSetSstp.Message
		require.NoError(t, json.Unmarshal(body, &msg), "response is an SSTP message")
		assert.False(t, msg.ReturnEventsResolved(), "paused pair sets returnEvents=false")
	})

	t.Run("WrongContentTypeReturns415", func(t *testing.T) {
		pair := newSstpTestPair(t, instance, model.StreamStateEnabled)
		resp := pair.post(t, instance, "application/json", pair.bearer)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusUnsupportedMediaType, resp.StatusCode, "wrong content-type is 415")
	})

	t.Run("ContentTypeWithCharsetAccepted", func(t *testing.T) {
		pair := newSstpTestPair(t, instance, model.StreamStateEnabled)
		resp := pair.post(t, instance, "application/sstp+json; charset=utf-8", pair.bearer)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode, "base-type match ignores parameters")
	})

	t.Run("MissingPairReturns4xxWithEnvelope", func(t *testing.T) {
		pair := newSstpTestPair(t, instance, model.StreamStateEnabled)
		// Post to a PairId that does not exist (simulating a deleted pair) but with
		// a valid bearer for a real pair.
		url := fmt.Sprintf("http://%s/sstp/%s", instance.host, bson.NewObjectID().Hex())
		body, _ := json.Marshal(goSetSstp.Message{})
		req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
		require.NoError(t, err)
		req.Header.Set("Content-Type", goSetSstp.ContentType)
		req.Header.Set("Authorization", "Bearer "+pair.bearer)
		resp, err := instance.client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.GreaterOrEqual(t, resp.StatusCode, 400, "deleted pair returns 4xx")
		assert.Less(t, resp.StatusCode, 500, "deleted pair is a client error")
		raw, _ := io.ReadAll(resp.Body)
		var env map[string]any
		require.NoError(t, json.Unmarshal(raw, &env), "body is the SSF error envelope")
		assert.Contains(t, env, "err", "envelope carries an err code")
	})

	t.Run("TokenWithoutSidContainmentReturns401", func(t *testing.T) {
		pair := newSstpTestPair(t, instance, model.StreamStateEnabled)
		// Mint a pair token whose StreamIds are for unrelated SIDs — it does NOT
		// contain this pair's txSid/rxSid, so defense-in-depth must reject it.
		foreignBearer, err := instance.GetAuthIssuer().IssueSstpPairToken(
			bson.NewObjectID().Hex(), bson.NewObjectID().Hex(), instance.projectId, false, nil)
		require.NoError(t, err)

		resp := pair.post(t, instance, goSetSstp.ContentType, foreignBearer)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "bearer not bound to this pair's SIDs is 401")
		raw, _ := io.ReadAll(resp.Body)
		var env map[string]any
		require.NoError(t, json.Unmarshal(raw, &env), "body is the SSF error envelope")
		assert.Contains(t, env, "err", "envelope carries an err code")
	})

	t.Run("MissingBearerReturns401", func(t *testing.T) {
		pair := newSstpTestPair(t, instance, model.StreamStateEnabled)
		resp := pair.post(t, instance, goSetSstp.ContentType, "")
		defer resp.Body.Close()
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "no bearer is 401")
	})

	t.Run("NonPostReturns405", func(t *testing.T) {
		pair := newSstpTestPair(t, instance, model.StreamStateEnabled)
		url := fmt.Sprintf("http://%s/sstp/%s", instance.host, pair.pairId)
		for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete, http.MethodPatch} {
			req, err := http.NewRequest(method, url, nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer "+pair.bearer)
			resp, err := instance.client.Do(req)
			require.NoError(t, err)
			resp.Body.Close()
			assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode, "method %s should be 405", method)
		}
	})
}
