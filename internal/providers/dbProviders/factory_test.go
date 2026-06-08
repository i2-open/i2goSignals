package dbProviders

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/v2/bson"
)

// assertDedupParity exercises the slice #156 cross-provider parity check: a
// double-AddEvent on the same JTI must return interfaces.ErrDuplicateJTI on
// the second call. The Persistence record's EventService is wired to the
// underlying provider's EventDAO, so a green assertion proves the dedup
// sentinel propagates correctly through the composition root for this
// variant.
func assertDedupParity(t *testing.T, p *Persistence) {
	t.Helper()
	ctx := context.Background()
	evt := &goSet.SecurityEventToken{Events: map[string]interface{}{"x": "y"}}
	evt.ID = "dedup-parity-jti"
	_, err := p.EventService.AddEvent(ctx, evt, "stream-x", "raw-1")
	assert.NoError(t, err, "first AddEvent should succeed")
	_, err2 := p.EventService.AddEvent(ctx, evt, "stream-x", "raw-2")
	assert.True(t, errors.Is(err2, interfaces.ErrDuplicateJTI),
		"second AddEvent should return ErrDuplicateJTI, got %v", err2)
}

// assertSstpPairParity exercises the slice #159 cross-provider parity check: a
// bidirectional SSTP StreamStateRecord persisted through the StreamService must
// round-trip with both per-direction StreamConfigurations, SstpMethod
// connectivity, PairId, and per-direction status fields intact, and must be
// retrievable by both the inbound (receive-side) SID and the PairId. A green
// assertion proves the new DAO accessors and the bidirectional record shape
// propagate correctly through the composition root for this variant.
func assertSstpPairParity(t *testing.T, p *Persistence) {
	t.Helper()
	ctx := context.Background()

	rec := &model.StreamStateRecord{
		Id:     bson.NewObjectID(),
		PairId: "pair-parity-1",
		StreamConfiguration: model.StreamConfiguration{
			Id:       "tx-parity-1",
			Iss:      "https://tx.parity",
			Delivery: &model.OneOfStreamConfigurationDelivery{SstpTransmitMarker: &model.SstpTransmitMarker{Method: model.DeliverySstp}},
		},
		Status: model.StreamStateEnabled,
		SstpInbound: &model.StreamConfiguration{
			Id:       "rx-parity-1",
			Iss:      "https://rx.parity",
			Delivery: &model.OneOfStreamConfigurationDelivery{SstpReceiveMarker: &model.SstpReceiveMarker{Method: model.ReceiveSstp}},
		},
		SstpMethod: &model.SstpMethod{
			Role:                model.SstpRoleInitiator,
			EndpointUrl:         "https://peer.parity/sstp/pair-peer",
			AuthorizationHeader: "Bearer parity-secret",
			PeerPairId:          "pair-peer",
		},
		InboundStatus:   model.StreamStatePause,
		InboundErrorMsg: "peer down",
	}

	err := p.StreamService.PersistStreamStateRecord(ctx, rec)
	assert.NoError(t, err, "persisting SSTP pair record should succeed")

	byInbound, err := p.StreamService.GetStreamStateByInboundSID(ctx, "rx-parity-1")
	assert.NoError(t, err, "FindByInboundSID should locate the pair")
	if assert.NotNil(t, byInbound) {
		assert.Equal(t, "pair-parity-1", byInbound.PairId)
		assert.Equal(t, model.DeliverySstpPair, byInbound.GetType())
		assert.True(t, byInbound.HasInbound() && byInbound.HasOutbound(), "SSTP pair has both directions")
		if assert.NotNil(t, byInbound.SstpMethod) {
			assert.Equal(t, "Bearer parity-secret", byInbound.SstpMethod.AuthorizationHeader)
			assert.Equal(t, model.SstpRoleInitiator, byInbound.SstpMethod.Role)
		}
		assert.Equal(t, model.StreamStatePause, byInbound.InboundStatus)
		assert.Equal(t, "peer down", byInbound.InboundErrorMsg)
	}

	byPair, err := p.StreamService.GetStreamStateByPairId(ctx, "pair-parity-1")
	assert.NoError(t, err, "FindByPairId should locate the pair")
	if assert.NotNil(t, byPair) {
		assert.Equal(t, "tx-parity-1", byPair.StreamConfiguration.Id)
		if assert.NotNil(t, byPair.SstpInbound) {
			assert.Equal(t, "rx-parity-1", byPair.SstpInbound.Id)
		}
	}

	_, err = p.StreamService.GetStreamStateByInboundSID(ctx, "no-such-rx")
	assert.True(t, errors.Is(err, interfaces.ErrNotFound), "missing inbound SID returns ErrNotFound, got %v", err)
	_, err = p.StreamService.GetStreamStateByPairId(ctx, "no-such-pair")
	assert.True(t, errors.Is(err, interfaces.ErrNotFound), "missing PairId returns ErrNotFound, got %v", err)
}

// TestOpenPersistence_Memory exercises the composition root: the memory
// adapter must produce a complete Persistence (services + Coordinator +
// Storage) so callers can depend on the narrowest seam they need.
func TestOpenPersistence_Memory(t *testing.T) {
	t.Setenv("I2SIG_STORE_MEM_DIRECTORY", t.TempDir())
	p, err := OpenPersistence("memorydb:", "test_persist_mem")
	assert.NoError(t, err)
	assert.NotNil(t, p)
	assert.NotNil(t, p.StreamService, "StreamService must be set")
	assert.NotNil(t, p.KeyService, "KeyService must be set")
	assert.NotNil(t, p.EventService, "EventService must be set")
	assert.NotNil(t, p.ClientService, "ClientService must be set")
	assert.NotNil(t, p.ServerService, "ServerService must be set")
	assert.NotNil(t, p.TokenService, "TokenService must be set")
	assert.NotNil(t, p.SubjectFilterService, "SubjectFilterService must be set")
	assert.NotNil(t, p.SubjectRelayService, "SubjectRelayService must be set")
	assert.NotNil(t, p.Coordinator, "Coordinator must be set")
	assert.NotNil(t, p.Storage, "Storage must be set")

	// Coordinator seam exercises the real (non-stub) MemoryCoordinator.
	ok, _, err := p.Coordinator.TryAcquireOrRenewLease("smoke", "node-A", 5_000_000_000)
	assert.NoError(t, err)
	assert.True(t, ok, "MemoryCoordinator should grant first acquire")

	// events-dedup parity: confirms the EventService wired into the memory
	// provider surfaces interfaces.ErrDuplicateJTI on a duplicate JTI.
	assertDedupParity(t, p)

	// SSTP pair parity: the bidirectional StreamStateRecord round-trips and is
	// retrievable by inbound SID and PairId through the memory provider.
	assertSstpPairParity(t, p)

	_ = p.Storage.Close()
}

// TestOpenPersistence_Fallback proves the Mongo→memory fallback returns a
// complete Persistence record (the same shape as a direct memory open).
func TestOpenPersistence_Fallback(t *testing.T) {
	t.Setenv("I2SIG_STORE_MEM_DIRECTORY", t.TempDir())
	t.Setenv("I2SIG_STORE_MONGO_RESUME_FILE", filepath.Join(t.TempDir(), "mongo_token.json"))
	wrongUrl := "mongodb://nonexistent:27017/?serverSelectionTimeoutMS=1000"

	p, err := OpenPersistence(wrongUrl, "test_persist_fallback")
	assert.NoError(t, err)
	assert.NotNil(t, p)
	assert.NotNil(t, p.StreamService)
	assert.NotNil(t, p.Coordinator)
	assert.NotNil(t, p.Storage)

	// events-dedup parity: the fallback variant must propagate the dedup
	// sentinel through the underlying memory EventDAO.
	assertDedupParity(t, p)

	// SSTP pair parity through the fallback (memory) provider variant.
	assertSstpPairParity(t, p)

	_ = p.Storage.Close()
}

// TestOpenPersistence_FailToMemFalse_Legacy confirms the deprecated
// MONGO_FAILTOMEM=FALSE name still surfaces the Mongo error instead of
// falling back. Coverage of the new I2SIG_STORE_MONGO_FALLBACK_MEM name
// lives in factory_envcompat_test.go.
func TestOpenPersistence_FailToMemFalse_Legacy(t *testing.T) {
	t.Setenv("MONGO_FAILTOMEM", "FALSE")
	t.Setenv("I2SIG_STORE_MONGO_RESUME_FILE", filepath.Join(t.TempDir(), "mongo_token.json"))

	wrongUrl := "mongodb://nonexistent:27017/?serverSelectionTimeoutMS=100"
	p, err := OpenPersistence(wrongUrl, "test_fail")
	assert.Error(t, err, "Deprecated MONGO_FAILTOMEM=FALSE must still surface the connection error")
	assert.Nil(t, p, "Persistence should be nil on failure")
}
