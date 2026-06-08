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

// newSstpVerifyPair provisions an enabled SSTP pair whose inbound direction's
// issuer is the local "DEFAULT" key (so the inbound JWKS is resolvable). This is
// the fixture for the signature-verification regression (finding #1/#2): the
// inbound side must load a real JWKS so a forged SET is rejected.
func newSstpVerifyPair(t *testing.T, instance *ssfInstance) *sstpTestPair {
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
            // Inbound issuer is the local DEFAULT key so its JWKS resolves
            // internally; inbound audience is the peer.
            Id:  rxSid,
            Iss: "DEFAULT",
            Aud: []string{"peer.example.com"},
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

func (p *sstpTestPair) postSets(t *testing.T, instance *ssfInstance, sets map[string]string) *http.Response {
    t.Helper()
    url := fmt.Sprintf("http://%s/sstp/%s", instance.host, p.pairId)
    // returnImmediately=true: this test exercises inbound SET verification, not
    // the outbound long-poll. Without it the server holds each POST for the full
    // default poll timeout (30s) with nothing to deliver.
    body, _ := json.Marshal(goSetSstp.Message{Sets: sets, ReturnImmediately: goSetSstp.BoolPtr(true)})
    req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
    require.NoError(t, err)
    req.Header.Set("Content-Type", goSetSstp.ContentType)
    req.Header.Set("Authorization", "Bearer "+p.bearer)
    resp, err := instance.client.Do(req)
    require.NoError(t, err)
    return resp
}

func sstpVerifySubject() *goSet.EventSubject {
    return &goSet.EventSubject{
        SubjectIdentifier: goSet.SubjectIdentifier{
            Format:                    "scim",
            UniformResourceIdentifier: goSet.UniformResourceIdentifier{Uri: "/Users/sstp-verify"},
        },
    }
}

// TestSstpInboundSignatureVerification is the regression for findings #1/#2: an
// SSTP pair whose inbound direction has a resolvable JWKS must VERIFY inbound SET
// signatures. Before the fix GetIssuerJwksForReceiver returned nil for a pair
// (FindByID(rxSid) missed and IsReceiver() was false), so ParseReceivedSET
// skipped verification and a forged SET was accepted and persisted.
func TestSstpInboundSignatureVerification(t *testing.T) {
    instance, err := createServer(t, "sstp-inbound-verify", true)
    require.NoError(t, err)
    defer func() {
        if instance.ts != nil {
            instance.ts.Close()
        }
        instance.app.Shutdown()
    }()

    pair := newSstpVerifyPair(t, instance)

    // Forged SET: correct iss/aud, but signed with an attacker key that is NOT
    // the inbound issuer's key.
    forged := goSet.CreateSet(sstpVerifySubject(), "DEFAULT", []string{"peer.example.com"})
    forged.AddEventPayload("https://schemas.openid.net/secevent/risc/event-type/account-disabled",
        map[string]interface{}{"reason": "forged"})
    attackerKey, err := rsa.GenerateKey(rand.Reader, 2048)
    require.NoError(t, err)
    forgedJws, err := forged.JWS(jwt.SigningMethodRS256, attackerKey)
    require.NoError(t, err)
    forgedJti := forged.ID

    resp := pair.postSets(t, instance, map[string]string{forgedJti: forgedJws})
    require.Equal(t, http.StatusOK, resp.StatusCode)
    var msg goSetSstp.Message
    raw, _ := io.ReadAll(resp.Body)
    resp.Body.Close()
    require.NoError(t, json.Unmarshal(raw, &msg))

    // The forged SET must be rejected (a per-JTI setErr) and never persisted.
    require.Contains(t, msg.SetErrs, forgedJti, "forged inbound SET must be rejected with a per-JTI error")
    assert.Nil(t, instance.GetEvent(forgedJti), "forged inbound SET must not be persisted")

    // A correctly-signed SET (signed by the inbound issuer's DEFAULT key) is
    // accepted: no per-JTI error for its JTI.
    good := goSet.CreateSet(sstpVerifySubject(), "DEFAULT", []string{"peer.example.com"})
    good.AddEventPayload("https://schemas.openid.net/secevent/risc/event-type/account-disabled",
        map[string]interface{}{"reason": "legit"})
    defaultKey, err := instance.GetPrivateKey("DEFAULT")
    require.NoError(t, err)
    goodJws, err := good.JWS(jwt.SigningMethodRS256, defaultKey)
    require.NoError(t, err)
    goodJti := good.ID

    resp2 := pair.postSets(t, instance, map[string]string{goodJti: goodJws})
    require.Equal(t, http.StatusOK, resp2.StatusCode)
    var msg2 goSetSstp.Message
    raw2, _ := io.ReadAll(resp2.Body)
    resp2.Body.Close()
    require.NoError(t, json.Unmarshal(raw2, &msg2))
    assert.NotContains(t, msg2.SetErrs, goodJti, "a correctly-signed inbound SET must be accepted")
}
