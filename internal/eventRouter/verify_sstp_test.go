package eventRouter

import (
	"context"
	"testing"

	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/v2/bson"
)

// persistSstpPairRecord builds a minimal bidirectional SSTP record honoring the
// aliasing invariant (tx Id == PairId == document _id hex) and persists it via
// the storage seam, so verify-routing can be exercised without the peer-cascade
// machinery.
func persistSstpPairRecord(t *testing.T, h *testHarness) *model.StreamStateRecord {
	t.Helper()
	mid := bson.NewObjectID()
	pairId := mid.Hex()
	rec := &model.StreamStateRecord{
		Id: mid,
		StreamConfiguration: model.StreamConfiguration{
			Id:  pairId,
			Iss: "https://tx.issuer.example",
			Aud: []string{"https://tx.audience.example"},
			Delivery: &model.OneOfStreamConfigurationDelivery{
				SstpTransmitMarker: &model.SstpTransmitMarker{Method: model.DeliverySstp},
			},
		},
		SstpInbound: &model.StreamConfiguration{
			Id:  bson.NewObjectID().Hex(),
			Iss: "https://rx.issuer.example",
			Aud: []string{"https://rx.audience.example"},
			Delivery: &model.OneOfStreamConfigurationDelivery{
				SstpReceiveMarker: &model.SstpReceiveMarker{Method: model.ReceiveSstp},
			},
		},
		PairId:        pairId,
		Status:        model.StreamStateEnabled,
		InboundStatus: model.StreamStateEnabled,
	}
	require.NoError(t, h.streamService.PersistStreamStateRecord(context.Background(), rec))
	return rec
}

// TestGenerateVerifyEvent_SstpTxSide: POST /verify against the tx-side SID emits
// a verify SET scoped to the primary (outbound) direction's iss/aud. (Q40)
func TestGenerateVerifyEvent_SstpTxSide(t *testing.T) {
	h := newTestRouter(t)
	rec := persistSstpPairRecord(t, h)

	got, err := h.router.GenerateVerifyEvent(rec.StreamConfiguration.Id, "tx-state")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "https://tx.issuer.example", got.Event.Issuer,
		"tx-side verify must be scoped to the primary direction's issuer")
}

// TestGenerateVerifyEvent_SstpRxSide: POST /verify against the rx-side SID
// resolves the inbound direction and emits a verify SET scoped to its iss/aud
// rather than 404ing. (Q40)
func TestGenerateVerifyEvent_SstpRxSide(t *testing.T) {
	h := newTestRouter(t)
	rec := persistSstpPairRecord(t, h)

	got, err := h.router.GenerateVerifyEvent(rec.SstpInbound.Id, "rx-state")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "https://rx.issuer.example", got.Event.Issuer,
		"rx-side verify must be scoped to the inbound direction's issuer")
}
