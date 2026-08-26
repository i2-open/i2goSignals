package services

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/i2-open/i2goSignals/pkg/dao/ids"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newSstpPairFixture builds an enabled SSTP pair whose inbound leg verifies
// against jwksUrl. The tx-side SID (== the document _id) and the rx-side SID are
// deliberately different values, which is the whole point of these tests: the
// receiver cache is keyed by the INBOUND SID (ADR 0018) while DeleteStream is
// called with the document _id.
func newSstpPairFixture(t *testing.T, jwksUrl string) (rec *model.StreamStateRecord, txSid, rxSid string) {
	t.Helper()
	oid := model.NewRecordId()
	rxSid = ids.NewObjectID()
	rec = &model.StreamStateRecord{
		Id:        oid,
		ProjectId: "proj-1",
		PairId:    oid.Hex(),
		StreamConfiguration: model.StreamConfiguration{
			Id:  oid.Hex(),
			Iss: "https://local.example",
			Aud: []string{"https://peer.example"},
			Delivery: &model.OneOfStreamConfigurationDelivery{
				SstpTransmitMarker: &model.SstpTransmitMarker{Method: model.DeliverySstp},
			},
		},
		SstpInbound: &model.StreamConfiguration{
			Id:            rxSid,
			Iss:           "https://peer.example",
			IssuerJWKSUrl: jwksUrl,
			Aud:           []string{"https://local.example"},
			Delivery: &model.OneOfStreamConfigurationDelivery{
				SstpReceiveMarker: &model.SstpReceiveMarker{Method: model.ReceiveSstp},
			},
		},
		SstpMethod:    &model.SstpMethod{Role: model.SstpRoleResponder},
		Status:        model.StreamStateEnabled,
		InboundStatus: model.StreamStateEnabled,
		CreatedAt:     time.Now(),
	}
	return rec, oid.Hex(), rxSid
}

// cachedSids returns the receiver-cache keys currently resident.
func cachedSids(svc *StreamService) []string {
	svc.mu.RLock()
	defer svc.mu.RUnlock()
	sids := make([]string, 0, len(svc.receiverStreams))
	for sid := range svc.receiverStreams {
		sids = append(sids, sid)
	}
	return sids
}

// TestDeleteStream_EvictsSstpPairEntryNamedByTxSid is the regression bar for the
// eviction-key gap found reviewing GH #264. An SSTP pair's cache entry is keyed
// by SstpInbound.Id, but DeleteStream is called with the document _id / tx-side
// SID — including from the pair-create rollback paths in stream_service_sstp.go.
// Deleting by key alone left the entry resident for the life of the process.
func TestDeleteStream_EvictsSstpPairEntryNamedByTxSid(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	jwksSrv := newFlakyJwksServer(t, "delete-evict-tx", &key.PublicKey)
	jwksSrv.healthy.Store(true)

	h := newRetryHarness(t)
	ctx := context.Background()

	rec, txSid, rxSid := newSstpPairFixture(t, jwksSrv.URL)
	require.NoError(t, h.streamDAO.Create(ctx, rec))

	// Populate the cache through the receive path: the entry lands under rxSid.
	require.NotNil(t, h.svc.GetIssuerJwksForReceiver(ctx, rxSid),
		"precondition: the inbound JWKS must resolve so an entry is cached")
	require.Contains(t, cachedSids(h.svc), rxSid,
		"precondition: the pair's entry is keyed by the inbound SID")

	// Delete the pair the way every production caller does — by document _id.
	require.NoError(t, h.svc.DeleteStream(ctx, txSid))

	assert.NotContains(t, cachedSids(h.svc), rxSid,
		"deleting a pair must evict its inbound cache entry, not orphan it")
	assert.Empty(t, cachedSids(h.svc), "no receiver-cache entry may outlive its stream")
}

// TestEvictReceiverEntries_MatchesEitherPairIdentity covers the other identities
// a caller can hold for a pair. This exercises the evictor directly rather than
// DeleteStream because the DAO deletes by document _id only — FindByInboundSID
// resolves a pair for reads, but Delete(rxSid) is "not found", so
// delete-by-inbound-SID is not a serviceable operation. Eviction still matches
// on it so the cache cannot outlive its record if a future caller names it.
func TestEvictReceiverEntries_MatchesEitherPairIdentity(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	jwksSrv := newFlakyJwksServer(t, "delete-evict-rx", &key.PublicKey)
	jwksSrv.healthy.Store(true)

	for _, tc := range []struct {
		name string
		// nameFor picks which of the pair's identities the caller holds.
		nameFor func(txSid, rxSid string) string
	}{
		{"tx-side SID (document _id)", func(tx, _ string) string { return tx }},
		{"inbound SID (cache key)", func(_, rx string) string { return rx }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newRetryHarness(t)
			ctx := context.Background()

			rec, txSid, rxSid := newSstpPairFixture(t, jwksSrv.URL)
			require.NoError(t, h.streamDAO.Create(ctx, rec))
			require.NotNil(t, h.svc.GetIssuerJwksForReceiver(ctx, rxSid))
			require.Contains(t, cachedSids(h.svc), rxSid)

			h.svc.evictReceiverEntries(tc.nameFor(txSid, rxSid))

			assert.Empty(t, cachedSids(h.svc),
				"either identity must evict the pair's entry")
		})
	}
}

// TestDeleteStream_EvictsPlainReceiverEntry guards the path that already worked,
// so the sweep does not regress it.
func TestDeleteStream_EvictsPlainReceiverEntry(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	jwksSrv := newFlakyJwksServer(t, "delete-evict-plain", &key.PublicKey)
	jwksSrv.healthy.Store(true)

	h := newRetryHarness(t)
	ctx := context.Background()

	rec := newJwksReceiverFixture(t, "https://tx.example", jwksSrv.URL)
	require.NoError(t, h.streamDAO.Create(ctx, rec))
	sid := rec.StreamConfiguration.Id

	require.NotNil(t, h.svc.GetIssuerJwksForReceiver(ctx, sid))
	require.Contains(t, cachedSids(h.svc), sid)

	require.NoError(t, h.svc.DeleteStream(ctx, sid))
	assert.Empty(t, cachedSids(h.svc))
}

// TestDeleteStream_LeavesOtherStreamsCached pins the sweep's blast radius: it
// must evict the named stream's entries and nothing else.
func TestDeleteStream_LeavesOtherStreamsCached(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	jwksSrv := newFlakyJwksServer(t, "delete-evict-scope", &key.PublicKey)
	jwksSrv.healthy.Store(true)

	h := newRetryHarness(t)
	ctx := context.Background()

	pair, txSid, rxSid := newSstpPairFixture(t, jwksSrv.URL)
	require.NoError(t, h.streamDAO.Create(ctx, pair))

	survivor := newJwksReceiverFixture(t, "https://tx.example", jwksSrv.URL)
	require.NoError(t, h.streamDAO.Create(ctx, survivor))
	survivorSid := survivor.StreamConfiguration.Id

	require.NotNil(t, h.svc.GetIssuerJwksForReceiver(ctx, rxSid))
	require.NotNil(t, h.svc.GetIssuerJwksForReceiver(ctx, survivorSid))
	require.Len(t, cachedSids(h.svc), 2)

	require.NoError(t, h.svc.DeleteStream(ctx, txSid))

	assert.ElementsMatch(t, []string{survivorSid}, cachedSids(h.svc),
		"only the deleted stream's entries may be evicted")
}
