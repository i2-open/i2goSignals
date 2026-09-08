package services

import (
	"context"
	"sync"
	"testing"

	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/dao/memory"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// countingStreamDAO wraps a StreamDAO and counts the two reads the ingest path
// repeats. Everything else passes straight through, so the service under test
// is the real one against the real memory store.
type countingStreamDAO struct {
	interfaces.StreamDAO
	mu           sync.Mutex
	findByID     int
	findByInSID  int
	findByIDKeys []string
}

func (d *countingStreamDAO) FindByID(ctx context.Context, id string) (*model.StreamStateRecord, error) {
	d.mu.Lock()
	d.findByID++
	d.findByIDKeys = append(d.findByIDKeys, id)
	d.mu.Unlock()
	return d.StreamDAO.FindByID(ctx, id)
}

func (d *countingStreamDAO) FindByInboundSID(ctx context.Context, sid string) (*model.StreamStateRecord, error) {
	d.mu.Lock()
	d.findByInSID++
	d.mu.Unlock()
	return d.StreamDAO.FindByInboundSID(ctx, sid)
}

func (d *countingStreamDAO) counts() (int, int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.findByID, d.findByInSID
}

func (d *countingStreamDAO) reset() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.findByID, d.findByInSID, d.findByIDKeys = 0, 0, nil
}

func newCountedStreamService(t *testing.T) (*StreamService, *countingStreamDAO) {
	t.Helper()
	dao := &countingStreamDAO{StreamDAO: memory.NewStreamDAO()}
	return NewStreamService(dao, nil, "https://example.com", StreamServiceConfig{}), dao
}

func seedPlainStream(t *testing.T, svc *StreamService, sid string) {
	t.Helper()
	rec := &model.StreamStateRecord{
		Id:     model.NewRecordId(),
		Status: model.StreamStateEnabled,
		StreamConfiguration: model.StreamConfiguration{
			Id:  sid,
			Iss: "https://issuer.example",
			Aud: []string{"https://rp.example"},
		},
	}
	require.NoError(t, svc.PersistStreamStateRecord(context.Background(), rec))
}

// TestRequestStreamCacheCollapsesRepeatedResolution is the #287 push-path
// claim: the receiver handler and the router's resolveIngressStream both ask
// for the same SID inside one request, and with the memo installed only one of
// them reaches the store.
func TestRequestStreamCacheCollapsesRepeatedResolution(t *testing.T) {
	svc, dao := newCountedStreamService(t)
	seedPlainStream(t, svc, "stream-1")

	t.Run("without a memo every resolution is its own round trip", func(t *testing.T) {
		dao.reset()
		ctx := context.Background()
		for i := 0; i < 3; i++ {
			rec, err := svc.GetStreamState(ctx, "stream-1")
			require.NoError(t, err)
			require.NotNil(t, rec)
		}
		byID, _ := dao.counts()
		assert.Equal(t, 3, byID, "unmemoised reads must behave exactly as before #287")
	})

	t.Run("with a memo the request pays for one", func(t *testing.T) {
		dao.reset()
		ctx := WithRequestStreamCache(context.Background())
		for i := 0; i < 3; i++ {
			rec, err := svc.GetStreamState(ctx, "stream-1")
			require.NoError(t, err)
			require.Equal(t, "stream-1", rec.StreamConfiguration.Id)
		}
		byID, _ := dao.counts()
		assert.Equal(t, 1, byID)
	})

	t.Run("a second request re-reads", func(t *testing.T) {
		dao.reset()
		for i := 0; i < 3; i++ {
			ctx := WithRequestStreamCache(context.Background())
			_, err := svc.GetStreamState(ctx, "stream-1")
			require.NoError(t, err)
		}
		byID, _ := dao.counts()
		assert.Equal(t, 3, byID, "the memo must not outlive the request that made it")
	})
}

// TestRequestStreamCacheRemembersMisses covers the SSTP fall-through: the
// rx-side SID is deliberately probed as a document _id and deliberately misses,
// and re-issuing that miss is one of the round trips #287 removes.
func TestRequestStreamCacheRemembersMisses(t *testing.T) {
	svc, dao := newCountedStreamService(t)
	ctx := WithRequestStreamCache(context.Background())

	for i := 0; i < 4; i++ {
		_, err := svc.GetStreamState(ctx, "no-such-stream")
		require.Error(t, err)
	}
	byID, _ := dao.counts()
	assert.Equal(t, 1, byID)
}

// TestRequestStreamCacheIsIdempotent guards against a nested installation
// silently splitting one request across two memos.
func TestRequestStreamCacheIsIdempotent(t *testing.T) {
	first := WithRequestStreamCache(context.Background())
	second := WithRequestStreamCache(first)
	assert.Same(t, requestStreamCacheFrom(first), requestStreamCacheFrom(second))
}

// TestRequestStreamCacheInvalidatedByWrites is the correctness half: a handler
// that changes a stream and then re-reads it inside the same request must see
// its own write, never the memoised pre-write record.
func TestRequestStreamCacheInvalidatedByWrites(t *testing.T) {
	t.Run("status update", func(t *testing.T) {
		svc, dao := newCountedStreamService(t)
		seedPlainStream(t, svc, "stream-2")
		ctx := WithRequestStreamCache(context.Background())

		before, err := svc.GetStreamState(ctx, "stream-2")
		require.NoError(t, err)
		require.Equal(t, model.StreamStateEnabled, before.Status)

		svc.UpdateStreamStatus(ctx, "stream-2", model.StreamStatePause, "paused by test")

		dao.reset()
		after, err := svc.GetStreamState(ctx, "stream-2")
		require.NoError(t, err)
		byID, _ := dao.counts()
		assert.Equal(t, 1, byID, "the write must have dropped the memoised record")
		assert.Equal(t, model.StreamStatePause, after.Status)
	})

	t.Run("delete", func(t *testing.T) {
		svc, _ := newCountedStreamService(t)
		seedPlainStream(t, svc, "stream-3")
		ctx := WithRequestStreamCache(context.Background())

		_, err := svc.GetStreamState(ctx, "stream-3")
		require.NoError(t, err)

		require.NoError(t, svc.DeleteStream(ctx, "stream-3"))

		_, err = svc.GetStreamState(ctx, "stream-3")
		assert.Error(t, err, "a deleted stream must not keep resolving from the memo")
	})
}

// TestStreamConfigChangeIsLiveForTheNextRequest is the acceptance criterion
// stated directly: because the memo dies with its request, a configuration
// change made anywhere — another node, an admin call, this process — is in
// effect for the very next request. There is no TTL to wait out.
func TestStreamConfigChangeIsLiveForTheNextRequest(t *testing.T) {
	svc, _ := newCountedStreamService(t)
	seedPlainStream(t, svc, "stream-4")

	first := WithRequestStreamCache(context.Background())
	rec, err := svc.GetStreamState(first, "stream-4")
	require.NoError(t, err)
	require.Equal(t, model.StreamStateEnabled, rec.Status)

	// Changed outside any request that holds a memo.
	svc.UpdateStreamStatus(context.Background(), "stream-4", model.StreamStateDisable, "disabled elsewhere")

	next := WithRequestStreamCache(context.Background())
	rec, err = svc.GetStreamState(next, "stream-4")
	require.NoError(t, err)
	assert.Equal(t, model.StreamStateDisable, rec.Status)
}

// TestSeedRequestStreamServesSstpPairResolution is the #287 SSTP-server claim.
// SstpServerHandler is handed the pair by the HTTP layer; seeding it means
// resolveIngressStream's three-probe walk over the rx-side SID costs one store
// read (the FindByID miss the seed says nothing about) instead of three.
func TestSeedRequestStreamServesSstpPairResolution(t *testing.T) {
	svc, dao := newCountedStreamService(t)
	txSid, rxSid := "pair-tx", "pair-rx"
	pair := &model.StreamStateRecord{
		Id:     model.NewRecordId(),
		PairId: "pair-1",
		Status: model.StreamStateEnabled,
		StreamConfiguration: model.StreamConfiguration{
			Id:       txSid,
			Iss:      "https://local.example",
			Delivery: &model.OneOfStreamConfigurationDelivery{SstpTransmitMarker: &model.SstpTransmitMarker{Method: model.DeliverySstp}},
		},
		SstpInbound: &model.StreamConfiguration{
			Id:       rxSid,
			Iss:      "https://peer.example",
			Delivery: &model.OneOfStreamConfigurationDelivery{SstpReceiveMarker: &model.SstpReceiveMarker{Method: model.ReceiveSstp}},
		},
		SstpMethod: &model.SstpMethod{Role: model.SstpRoleResponder, PeerPairId: "peer-pair-1"},
	}
	require.NoError(t, svc.PersistStreamStateRecord(context.Background(), pair))

	// Unseeded: the walk resolveIngressStream performs on an rx-side SID.
	unseeded := WithRequestStreamCache(context.Background())
	dao.reset()
	_, err := svc.GetStreamState(unseeded, rxSid)
	require.Error(t, err)
	got, err := svc.GetStreamStateBySID(unseeded, rxSid)
	require.NoError(t, err)
	require.Equal(t, txSid, got.StreamConfiguration.Id)
	byID, byInSID := dao.counts()
	require.Equal(t, 1, byID, "even unseeded, the repeated FindByID(rxSid) is memoised")
	require.Equal(t, 1, byInSID)

	// Seeded: nothing but the one FindByID miss reaches the store, and the
	// record handed back is the one the HTTP layer already resolved.
	seeded := WithRequestStreamCache(context.Background())
	SeedRequestStream(seeded, pair)
	dao.reset()
	_, err = svc.GetStreamState(seeded, rxSid)
	require.Error(t, err)
	got, err = svc.GetStreamStateBySID(seeded, rxSid)
	require.NoError(t, err)
	assert.Same(t, pair, got)
	byID, byInSID = dao.counts()
	assert.Equal(t, 1, byID)
	assert.Equal(t, 0, byInSID, "the seeded inbound-SID answer must not be re-fetched")

	// The seed states only what the store would return anyway: it must not
	// invent an answer for a SID this record does not carry. GetStreamStateBySID
	// probes FindByID twice for an unknown SID and the memo folds those into one,
	// but the answer is still the store's — not found.
	dao.reset()
	_, err = svc.GetStreamStateBySID(seeded, "unrelated-sid")
	require.Error(t, err)
	byID, byInSID = dao.counts()
	assert.Equal(t, 1, byID)
	assert.Equal(t, 1, byInSID)
}
