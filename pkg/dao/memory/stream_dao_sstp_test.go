package memory

import (
	"context"
	"errors"
	"testing"

	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"go.mongodb.org/mongo-driver/v2/bson"
)

func newSstpRecord(txSid, rxSid, pairId string) *model.StreamStateRecord {
	return &model.StreamStateRecord{
		Id:     bson.NewObjectID(),
		PairId: pairId,
		StreamConfiguration: model.StreamConfiguration{
			Id:       txSid,
			Delivery: &model.OneOfStreamConfigurationDelivery{SstpTransmitMarker: &model.SstpTransmitMarker{Method: model.DeliverySstp}},
		},
		SstpInbound: &model.StreamConfiguration{
			Id:       rxSid,
			Delivery: &model.OneOfStreamConfigurationDelivery{SstpReceiveMarker: &model.SstpReceiveMarker{Method: model.ReceiveSstp}},
		},
		SstpMethod: &model.SstpMethod{Role: model.SstpRoleResponder, PeerPairId: "peer-" + pairId},
		Status:     model.StreamStateEnabled,
	}
}

func TestStreamDAOMemory_FindByInboundSID(t *testing.T) {
	dao := NewStreamDAO()
	ctx := context.Background()
	_ = dao.Create(ctx, newSstpRecord("tx-1", "rx-1", "pair-1"))

	got, err := dao.FindByInboundSID(ctx, "rx-1")
	if err != nil {
		t.Fatalf("FindByInboundSID failed: %v", err)
	}
	if got.PairId != "pair-1" {
		t.Errorf("got PairId %q, want pair-1", got.PairId)
	}
}

func TestStreamDAOMemory_FindByInboundSID_NotFound(t *testing.T) {
	dao := NewStreamDAO()
	ctx := context.Background()
	_ = dao.Create(ctx, newSstpRecord("tx-1", "rx-1", "pair-1"))

	_, err := dao.FindByInboundSID(ctx, "no-such-rx")
	if !errors.Is(err, interfaces.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestStreamDAOMemory_FindByPairId(t *testing.T) {
	dao := NewStreamDAO()
	ctx := context.Background()
	_ = dao.Create(ctx, newSstpRecord("tx-1", "rx-1", "pair-1"))
	_ = dao.Create(ctx, newSstpRecord("tx-2", "rx-2", "pair-2"))

	got, err := dao.FindByPairId(ctx, "pair-2")
	if err != nil {
		t.Fatalf("FindByPairId failed: %v", err)
	}
	if got.StreamConfiguration.Id != "tx-2" {
		t.Errorf("got tx SID %q, want tx-2", got.StreamConfiguration.Id)
	}
}

func TestStreamDAOMemory_FindByPairId_NotFound(t *testing.T) {
	dao := NewStreamDAO()
	ctx := context.Background()
	_, err := dao.FindByPairId(ctx, "missing")
	if !errors.Is(err, interfaces.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}
