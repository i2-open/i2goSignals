package test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/goSetSstp"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/v2/bson"
)

// newSstpSigningOnlyPair provisions an enabled SSTP pair whose inbound direction is
// signing-only (#184): the rx-side stream gates trust on each SET's JWS signature
// rather than the stream-scoped bearer. It mirrors newSstpVerifyPair (the inbound
// issuer is the local "DEFAULT" key so its JWKS resolves internally) but flips
// SstpInbound.SigningOnly on. Persisting directly via PersistStreamStateRecord
// bypasses the create-time guardrail (tested elsewhere), which is fine here.
func newSstpSigningOnlyPair(t *testing.T, instance *ssfInstance) *sstpTestPair {
	t.Helper()
	txSid := bson.NewObjectID().Hex()
	rxSid := bson.NewObjectID().Hex()
	pairId := bson.NewObjectID().Hex()

	rec := &model.StreamStateRecord{
		StreamConfiguration: model.StreamConfiguration{
			Id:  txSid,
			Iss: "peer.example.com",
			Aud: []string{"DEFAULT"},
		},
		SstpInbound: &model.StreamConfiguration{
			Id:          rxSid,
			Iss:         "DEFAULT",
			Aud:         []string{"peer.example.com"},
			SigningOnly: true,
		},
		SstpMethod:    &model.SstpMethod{Role: "responder"},
		PairId:        pairId,
		ProjectId:     instance.projectId,
		Status:        model.StreamStateEnabled,
		InboundStatus: model.StreamStateEnabled,
	}
	require.NoError(t, instance.streamSvc().PersistStreamStateRecord(context.Background(), rec))

	bearer, err := instance.GetAuthIssuer().IssueSstpPairToken(txSid, rxSid, instance.projectId, false, nil)
	require.NoError(t, err)
	return &sstpTestPair{pairId: pairId, txSid: txSid, rxSid: rxSid, bearer: bearer}
}

// postSstpSigningOnly POSTs an SSTP message (returnImmediately=true to avoid the
// 30s outbound long-poll) to the pair's /sstp/{id} endpoint. authHeader is set only
// when non-empty, so passing "" exercises the no-Authorization (bearer-bypass) path.
func postSstpSigningOnly(t *testing.T, instance *ssfInstance, pairId, authHeader string, sets map[string]string) *http.Response {
	t.Helper()
	url := fmt.Sprintf("http://%s/sstp/%s", instance.host, pairId)
	body, _ := json.Marshal(goSetSstp.Message{Sets: sets, ReturnImmediately: goSetSstp.BoolPtr(true)})
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", goSetSstp.ContentType)
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	resp, err := instance.client.Do(req)
	require.NoError(t, err)
	return resp
}

// TestSstpSigningOnly exercises the #184 signing-only receive posture on the SSTP
// handler (ReceiveSstpEventHandler, POST /sstp/{id}). When the rx-side stream is
// signing-only and no Authorization header is presented, the bearer gate is
// bypassed but each inbound SET is still signature-verified per-JTI. A presented
// bearer is still enforced.
func TestSstpSigningOnly(t *testing.T) {
	instance, err := createServer(t, "sstp-signing-only", true)
	require.NoError(t, err)
	defer func() {
		if instance.ts != nil {
			instance.ts.Close()
		}
		instance.app.Shutdown()
	}()

	pair := newSstpSigningOnlyPair(t, instance)

	goodInboundSet := func(t *testing.T) (string, string) {
		t.Helper()
		good := goSet.CreateSet(sstpVerifySubject(), "DEFAULT", []string{"peer.example.com"})
		good.AddEventPayload("https://schemas.openid.net/secevent/risc/event-type/account-disabled",
			map[string]interface{}{"reason": "legit"})
		defaultKey, err := instance.GetPrivateKey("DEFAULT")
		require.NoError(t, err)
		goodJws, err := good.JWS(jwt.SigningMethodRS256, defaultKey)
		require.NoError(t, err)
		return good.ID, goodJws
	}

	// (a) No Authorization header + a GOOD inbound SET -> 200, no SetErr for its jti
	// (the bearer gate is bypassed and the signature is accepted).
	t.Run("NoAuth_GoodSet_BearerBypassed", func(t *testing.T) {
		goodJti, goodJws := goodInboundSet(t)

		resp := postSstpSigningOnly(t, instance, pair.pairId, "", map[string]string{goodJti: goodJws})
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var msg goSetSstp.Message
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		require.NoError(t, json.Unmarshal(raw, &msg))
		assert.NotContains(t, msg.SetErrs, goodJti,
			"a correctly-signed inbound SET must be accepted when the signing-only bearer gate is bypassed")
	})

	// (b) No Authorization header + a FORGED inbound SET -> 200 with a per-JTI
	// SetErr (Err == ErrJws); the forged SET must never be persisted.
	t.Run("NoAuth_ForgedSet_Rejected", func(t *testing.T) {
		forged := goSet.CreateSet(sstpVerifySubject(), "DEFAULT", []string{"peer.example.com"})
		forged.AddEventPayload("https://schemas.openid.net/secevent/risc/event-type/account-disabled",
			map[string]interface{}{"reason": "forged"})
		attackerKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		forgedJws, err := forged.JWS(jwt.SigningMethodRS256, attackerKey)
		require.NoError(t, err)
		forgedJti := forged.ID

		resp := postSstpSigningOnly(t, instance, pair.pairId, "", map[string]string{forgedJti: forgedJws})
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var msg goSetSstp.Message
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		require.NoError(t, json.Unmarshal(raw, &msg))
		require.Contains(t, msg.SetErrs, forgedJti, "forged inbound SET must be rejected with a per-JTI error")
		// Signature-invalid rejections carry the canonical v1 problem URI
		// (retryable) rather than the §2.3 keyword — a JWKS refresh can heal
		// a JWKS-lag failure at the peer. See goSetSstp/problem.go emission
		// contract.
		assert.Equal(t, goSetSstp.ProblemSignatureInvalid, msg.SetErrs[forgedJti].Err)
		assert.Nil(t, instance.GetEvent(forgedJti), "forged inbound SET must not be persisted")
	})

	// (c) An Authorization header IS present but invalid (a foreign pair bearer) ->
	// 401, because a presented bearer is enforced even on a signing-only pair.
	t.Run("InvalidBearer_GateEnforced", func(t *testing.T) {
		goodJti, goodJws := goodInboundSet(t)
		foreignBearer, err := instance.GetAuthIssuer().IssueSstpPairToken(
			bson.NewObjectID().Hex(), bson.NewObjectID().Hex(), instance.projectId, false, nil)
		require.NoError(t, err)

		resp := postSstpSigningOnly(t, instance, pair.pairId, "Bearer "+foreignBearer,
			map[string]string{goodJti: goodJws})
		resp.Body.Close()
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode,
			"a presented bearer must still be enforced (not bypassed) on a signing-only SSTP pair")
	})
}
