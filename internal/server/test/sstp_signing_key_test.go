package test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/dao/ids"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/goSetPush"
	"github.com/i2-open/i2goSignals/pkg/goSetSstp"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Issue #312, SSTP accepting end: with the pair's signing key suspended, an
// exchange is refused with 503 before anything in it is applied (no inbound SET
// ingested, no ack honored), and the pair takes the key-unavailable pause. Once
// the key is back the key check resumes the pair, and the dialer's resent
// exchange is ingested and its ack applied.
func TestSstpAcceptingEnd_KeyUnavailableRefusesThenResumes(t *testing.T) {
	t.Setenv("I2SIG_PUSH_AUTH_RETRY_DELAY", "100ms")
	t.Setenv("I2SIG_PUSH_AUTH_RETRY_LIMIT", "1000")
	instance, err := createServer(t, "sstp-accepting-key", true)
	require.NoError(t, err)
	defer func() {
		if instance.ts != nil {
			instance.ts.Close()
		}
		instance.app.Shutdown()
	}()
	ctx := context.Background()

	const iss = "https://sstp-accepting-key.example"
	_, err = instance.keySvc().CreateKeyPair(ctx, iss, "sig", instance.projectId)
	require.NoError(t, err)
	txSid, rxSid, pairId := ids.NewObjectID(), ids.NewObjectID(), ids.NewObjectID()
	require.NoError(t, instance.streamSvc().PersistStreamStateRecord(ctx, &model.StreamStateRecord{
		StreamConfiguration: model.StreamConfiguration{
			Id:        txSid,
			Iss:       iss,
			Aud:       []string{"DEFAULT"},
			RouteMode: model.RouteModePublish,
		},
		SstpInbound: &model.StreamConfiguration{
			// The inbound issuer is the local DEFAULT key, so its JWKS resolves.
			Id:  rxSid,
			Iss: "DEFAULT",
			Aud: []string{iss},
		},
		SstpMethod:    &model.SstpMethod{Role: model.SstpRoleResponder},
		PairId:        pairId,
		ProjectId:     instance.projectId,
		Status:        model.StreamStateEnabled,
		InboundStatus: model.StreamStateEnabled,
	}))
	bearer, err := instance.GetAuthIssuer().IssueSstpPairToken(txSid, rxSid, instance.projectId, false, nil)
	require.NoError(t, err)

	// One outbound SET the peer will ack, and one signed inbound SET it sends.
	outbound := goSet.CreateSet(sstpVerifySubject(), iss, []string{"DEFAULT"})
	outbound.AddEventPayload("https://schemas.openid.net/secevent/risc/event-type/account-disabled", map[string]interface{}{})
	_, err = instance.eventSvc().AddEvent(ctx, &outbound, txSid, "")
	require.NoError(t, err)
	require.NoError(t, instance.eventSvc().AddEventToStream(ctx, outbound.ID, txSid))
	inbound := goSet.CreateSet(sstpVerifySubject(), "DEFAULT", []string{iss})
	inbound.AddEventPayload("https://schemas.openid.net/secevent/risc/event-type/account-disabled", map[string]interface{}{})
	defaultKey, err := instance.GetPrivateKey("DEFAULT")
	require.NoError(t, err)
	inboundJws, err := inbound.JWS(jwt.SigningMethodRS256, defaultKey)
	require.NoError(t, err)

	_, _, err = instance.keySvc().SetKeyStatus(ctx, iss, "", dao.KeyStatusSuspended)
	require.NoError(t, err)
	instance.app.EventRouter.(interface{ InvalidateIssuerKey(string) }).InvalidateIssuerKey(iss)

	exchange := func() (int, []byte) {
		body, _ := json.Marshal(goSetSstp.Message{
			Sets:              map[string]string{inbound.ID: inboundJws},
			Ack:               []string{outbound.ID},
			ReturnImmediately: goSetSstp.BoolPtr(true),
		})
		req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("http://%s/sstp/%s", instance.host, pairId), bytes.NewReader(body))
		require.NoError(t, err)
		req.Header.Set("Content-Type", goSetSstp.ContentType)
		req.Header.Set("Authorization", "Bearer "+bearer)
		resp, err := instance.client.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		raw, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, raw
	}

	status, raw := exchange()
	require.Equal(t, http.StatusServiceUnavailable, status, string(raw))
	var refusal goSetPush.DeliveryErr
	require.NoError(t, json.Unmarshal(raw, &refusal))
	assert.Contains(t, refusal.Description, "no active signing key for issuer "+iss+" (RS256)")
	assert.Nil(t, instance.GetEvent(inbound.ID), "no inbound SET of a refused exchange is ingested")
	pending, _ := instance.GetEventIds(txSid, model.PollParameters{MaxEvents: 10, ReturnImmediately: true})
	assert.Equal(t, []string{outbound.ID}, pending, "no ack of a refused exchange is applied")
	paused, err := instance.streamSvc().GetStreamStateByPairId(ctx, pairId)
	require.NoError(t, err)
	assert.Equal(t, model.StreamStatePause, paused.Status)
	assert.Equal(t, model.StreamStatePause, paused.InboundStatus, "both directions stop")
	assert.Equal(t, "SSTP-SRV: no active signing key for issuer "+iss+" (RS256)", paused.ErrorMsg)
	assert.NotNil(t, paused.KeyUnavailableSince)

	_, _, err = instance.keySvc().SetKeyStatus(ctx, iss, "", dao.KeyStatusActive)
	require.NoError(t, err)
	instance.app.EventRouter.(interface{ InvalidateIssuerKey(string) }).InvalidateIssuerKey(iss)
	require.Eventually(t, func() bool {
		rec, err := instance.streamSvc().GetStreamStateByPairId(ctx, pairId)
		return err == nil && rec.Status == model.StreamStateEnabled && rec.KeyUnavailableSince == nil
	}, 5*time.Second, 20*time.Millisecond, "the key check resumes the pair")

	status, raw = exchange()
	require.Equal(t, http.StatusOK, status, string(raw))
	var msg goSetSstp.Message
	require.NoError(t, json.Unmarshal(raw, &msg))
	assert.Contains(t, msg.Ack, inbound.ID, "the resent inbound SET is ingested and acked")
	assert.NotNil(t, instance.GetEvent(inbound.ID))
	pending, _ = instance.GetEventIds(txSid, model.PollParameters{MaxEvents: 10, ReturnImmediately: true})
	assert.Empty(t, pending, "the resent ack is applied")
}
