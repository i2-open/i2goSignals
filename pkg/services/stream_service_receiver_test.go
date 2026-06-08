package services

import (
    "context"
    "testing"
    "time"

    "github.com/i2-open/i2goSignals/pkg/dao/memory"
    "github.com/i2-open/i2goSignals/pkg/ssfModels"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
    "go.mongodb.org/mongo-driver/v2/bson"
)

// TestStreamService_ListReceiverStreams verifies that StreamService.ListReceiverStreams
// returns exactly the streams whose delivery direction makes this server a receiver
// (ReceivePush or ReceivePoll), independent of RouteMode.
//
// Before this slice, the predicate diverged between adapters:
//   - StreamDAOMongo.FindReceiverStreams filtered RouteMode == "import"
//   - StreamDAOMemory.FindReceiverStreams used IsReceiver() (delivery-method based)
//
// Those are not equivalent: a ReceivePush stream can be in any RouteMode, and
// a transmitter-side stream could in principle be in RouteModeImport. The
// delivery-method predicate is the correct one and now lives in the service layer.
func TestStreamService_ListReceiverStreams(t *testing.T) {
    fixtures := []struct {
        name        string
        method      string
        routeMode   string
        wantInclude bool
    }{
        {
            name:        "ReceivePush is a receiver regardless of RouteMode",
            method:      model.ReceivePush,
            routeMode:   model.RouteModeImport,
            wantInclude: true,
        },
        {
            name:        "ReceivePoll is a receiver regardless of RouteMode",
            method:      model.ReceivePoll,
            routeMode:   model.RouteModeImport,
            wantInclude: true,
        },
        {
            name:        "DeliveryPush is not a receiver",
            method:      model.DeliveryPush,
            routeMode:   model.RouteModePublish,
            wantInclude: false,
        },
        {
            name:        "DeliveryPoll is not a receiver",
            method:      model.DeliveryPoll,
            routeMode:   model.RouteModePublish,
            wantInclude: false,
        },
        {
            name:        "DeliveryPush in RouteModeForward is still not a receiver",
            method:      model.DeliveryPush,
            routeMode:   model.RouteModeForward,
            wantInclude: false,
        },
    }

    streamDAO := memory.NewStreamDAO()
    keyDAO := memory.NewKeyDAO()
    keyService := NewKeyService(keyDAO, "http://test", nil, nil)
    svc := NewStreamService(streamDAO, keyService, "http://test", StreamServiceConfig{})
    ctx := context.Background()

    expectedIDs := map[string]bool{}
    for _, f := range fixtures {
        rec := newReceiverFixture(t, f.method, f.routeMode, f.name)
        require.NoError(t, streamDAO.Create(ctx, rec))
        if f.wantInclude {
            expectedIDs[rec.StreamConfiguration.Id] = true
        }
    }

    got, err := svc.ListReceiverStreams(ctx)
    require.NoError(t, err)

    gotIDs := map[string]bool{}
    for _, s := range got {
        gotIDs[s.StreamConfiguration.Id] = true
    }

    assert.Equal(t, expectedIDs, gotIDs,
        "ListReceiverStreams must return exactly the streams whose delivery method is a receiver")
}

func newReceiverFixture(t *testing.T, method, routeMode, label string) *model.StreamStateRecord {
    t.Helper()
    id := bson.NewObjectID()
    cfg := model.StreamConfiguration{
        Id:        id.Hex(),
        Iss:       "test-issuer",
        RouteMode: routeMode,
        Delivery:  &model.OneOfStreamConfigurationDelivery{},
    }
    switch method {
    case model.ReceivePush:
        cfg.Delivery.PushReceiveMethod = &model.PushReceiveMethod{Method: method}
    case model.ReceivePoll:
        cfg.Delivery.PollReceiveMethod = &model.PollReceiveMethod{Method: method}
    case model.DeliveryPush:
        cfg.Delivery.PushTransmitMethod = &model.PushTransmitMethod{Method: method}
    case model.DeliveryPoll:
        cfg.Delivery.PollTransmitMethod = &model.PollTransmitMethod{Method: method}
    default:
        t.Fatalf("unknown delivery method %q in fixture %q", method, label)
    }
    return &model.StreamStateRecord{
        Id:                  id,
        ProjectId:           "test-project",
        StreamConfiguration: cfg,
        Status:              model.StreamStateEnabled,
        CreatedAt:           time.Now(),
    }
}
