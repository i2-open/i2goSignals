package services

import (
    "context"
    "strings"
    "testing"
    "time"

    "github.com/i2-open/i2goSignals/internal/dao/memory"
    "github.com/i2-open/i2goSignals/pkg/authSupport"
    "github.com/i2-open/i2goSignals/pkg/ssfModels"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
    "go.mongodb.org/mongo-driver/v2/bson"
)

// TestCreateSstpPair_PairBearerAuthorizesBothSids is the regression for finding
// #7: the responder-minted per-pair bearer must authorize BOTH the tx-side SID
// (== PairId) and the real rx-side SID (== SstpInbound.Id). Previously the rxSid
// was minted as "" before buildSstpRecord generated the inbound SID, so the rx
// side was never authorized and per-direction status/verify naming the inbound
// SID returned 401.
func TestCreateSstpPair_PairBearerAuthorizesBothSids(t *testing.T) {
    svc, _ := sstpFixture(t)

    rec, err := svc.CreateSstpPair(context.Background(), responderBootstrap(), "proj-1", nil)
    require.NoError(t, err)

    txSid := rec.StreamConfiguration.Id
    rxSid := rec.SstpInbound.Id
    require.NotEmpty(t, txSid)
    require.NotEmpty(t, rxSid)
    require.NotEqual(t, txSid, rxSid)

    // Strip "Bearer " and parse the minted token through the same issuer.
    require.True(t, strings.HasPrefix(rec.SstpMethod.AuthorizationHeader, "Bearer "))
    raw := strings.TrimPrefix(rec.SstpMethod.AuthorizationHeader, "Bearer ")
    eat, err := svc.keyService.GetAuthIssuer().ParseAuthToken(raw)
    require.NoError(t, err)

    // StreamIds must be exactly the two real SIDs — no empty entry.
    assert.ElementsMatch(t, []string{txSid, rxSid}, eat.StreamIds,
        "pair bearer must carry both real SIDs with no empty placeholder")
    assert.NotContains(t, eat.StreamIds, "", "pair bearer must not carry an empty SID")

    // Read scope (event) authorizes both directions; write scope (stream) too.
    assert.True(t, eat.IsAuthorized(txSid, []string{authSupport.ScopeEventDelivery}), "tx event read")
    assert.True(t, eat.IsAuthorized(rxSid, []string{authSupport.ScopeEventDelivery}), "rx event read")
    assert.True(t, eat.IsAuthorized(txSid, []string{authSupport.ScopeStreamMgmt}), "tx stream write")
    assert.True(t, eat.IsAuthorized(rxSid, []string{authSupport.ScopeStreamMgmt}), "rx stream write")
}

// TestListReceiverStreams_IncludesSstpPair is the regression for finding #10: an
// SSTP pair (HasInbound()==true) must appear in the receiver enumeration so the
// startup inbound-JWKS preload (LoadReceiverStreams) picks it up. Plain push/poll
// streams must be unaffected.
func TestListReceiverStreams_IncludesSstpPair(t *testing.T) {
    svc, pairRec := createdPair(t)
    ctx := context.Background()

    // Add a plain transmit-only push stream — must NOT appear in receivers.
    txOnly := newReceiverFixture(t, model.DeliveryPush, model.RouteModePublish, "tx-only")
    require.NoError(t, svc.streamDAO.Create(ctx, txOnly))

    // Add a plain receive push stream — must appear in receivers.
    rxOnly := newReceiverFixture(t, model.ReceivePush, model.RouteModeImport, "rx-only")
    require.NoError(t, svc.streamDAO.Create(ctx, rxOnly))

    receivers, err := svc.ListReceiverStreams(ctx)
    require.NoError(t, err)
    rxIDs := map[string]bool{}
    for _, r := range receivers {
        rxIDs[r.StreamConfiguration.Id] = true
    }
    assert.True(t, rxIDs[pairRec.StreamConfiguration.Id], "SSTP pair must be enumerated as a receiver")
    assert.True(t, rxIDs[rxOnly.StreamConfiguration.Id], "plain receive push still a receiver")
    assert.False(t, rxIDs[txOnly.StreamConfiguration.Id], "plain transmit push is not a receiver")

    // And the pair must still be a transmitter (it has both directions).
    transmitters, err := svc.ListTransmitterStreams(ctx)
    require.NoError(t, err)
    txIDs := map[string]bool{}
    for _, t2 := range transmitters {
        txIDs[t2.StreamConfiguration.Id] = true
    }
    assert.True(t, txIDs[pairRec.StreamConfiguration.Id], "SSTP pair must still be enumerated as a transmitter")
    assert.True(t, txIDs[txOnly.StreamConfiguration.Id], "plain transmit push still a transmitter")
    assert.False(t, txIDs[rxOnly.StreamConfiguration.Id], "plain receive push is not a transmitter")
}

// TestGetIssuerJwksForReceiver_SstpPairLoadsInboundJwks is the regression for
// findings #1/#2: for an SSTP pair, the inbound JWKS must be loaded from the
// pair's SstpInbound (inbound iss / iss_jwks_url) and resolved by the inbound
// SID — NOT via FindByID(rxSid) (which misses, _id is the tx SID) returning nil.
// A nil JWKS makes goSetPush.ParseReceivedSET skip signature verification, so a
// forged inbound SET would be accepted; the fix must return a non-nil JWKS so
// verification actually happens.
func TestGetIssuerJwksForReceiver_SstpPairLoadsInboundJwks(t *testing.T) {
    streamDAO := memory.NewStreamDAO()
    keyDAO := memory.NewKeyDAO()
    keyService := NewKeyService(keyDAO, "https://inbound-issuer.example", nil, nil)
    // InitializeTokenKey registers an internal signing key under the issuer; the
    // inbound side references that issuer so the JWKS is resolvable internally.
    require.NoError(t, keyService.InitializeTokenKey(context.Background(), "https://inbound-issuer.example"))
    svc := NewStreamService(streamDAO, keyService, "https://local.example", StreamServiceConfig{})
    ctx := context.Background()

    txSid := bson.NewObjectID()
    rxSid := bson.NewObjectID().Hex()
    rec := &model.StreamStateRecord{
        Id:        txSid,
        ProjectId: "proj-1",
        PairId:    txSid.Hex(),
        StreamConfiguration: model.StreamConfiguration{
            Id:  txSid.Hex(),
            Iss: "https://local.example",
            Aud: []string{"https://peer.example"},
            Delivery: &model.OneOfStreamConfigurationDelivery{
                SstpTransmitMarker: &model.SstpTransmitMarker{Method: model.DeliverySstp},
            },
        },
        SstpInbound: &model.StreamConfiguration{
            Id:  rxSid,
            Iss: "https://inbound-issuer.example",
            Aud: []string{"https://local.example"},
            Delivery: &model.OneOfStreamConfigurationDelivery{
                SstpReceiveMarker: &model.SstpReceiveMarker{Method: model.ReceiveSstp},
            },
        },
        SstpMethod:    &model.SstpMethod{Role: model.SstpRoleResponder},
        Status:        model.StreamStateEnabled,
        InboundStatus: model.StreamStateEnabled,
        CreatedAt:     time.Now(),
    }
    require.NoError(t, streamDAO.Create(ctx, rec))

    // Asking for the rx-side SID must resolve the inbound config and return the
    // inbound issuer's JWKS (non-nil), so signatures are verified on the wire.
    jwks := svc.GetIssuerJwksForReceiver(ctx, rxSid)
    require.NotNil(t, jwks, "inbound JWKS for an SSTP pair must be loaded from SstpInbound, not nil")
}
