package memory_provider

import (
    "context"
    "sync/atomic"
    "testing"
    "time"

    interfaces "github.com/i2-open/i2goSignals/pkg/dao"
    "github.com/i2-open/i2goSignals/pkg/dao/memory"
    "github.com/i2-open/i2goSignals/pkg/ssfModels"
    "github.com/stretchr/testify/assert"
    "go.mongodb.org/mongo-driver/v2/bson"
)

// TestNotifyingDAOs_TriggerOnEverySuccessfulMutation is the tracer bullet
// for #44: a per-DAO decorator wraps the memory adapter's mutating methods
// and calls a single notify() callback after each successful write. This
// replaces the BaseProvider WriteHook plumbing (which is being removed).
//
// The test exercises every mutating DAO method through its decorator and
// asserts the notifier counter advances exactly once per successful call.
func TestNotifyingDAOs_TriggerOnEverySuccessfulMutation(t *testing.T) {
    var count int32
    notify := func() { atomic.AddInt32(&count, 1) }

    ctx := context.Background()

    streamDAO := newNotifyingStreamDAO(memory.NewStreamDAO(), notify)
    eventDAO := newNotifyingEventDAO(memory.NewEventDAO(), notify)
    keyDAO := newNotifyingKeyDAO(memory.NewKeyDAO(), notify)
    clientDAO := newNotifyingClientDAO(memory.NewClientDAO(), notify)
    serverDAO := newNotifyingServerDAO(memory.NewServerDAO(), notify)
    tokenDAO := newNotifyingTokenDAO(memory.NewTokenDAO(), notify)

    expected := int32(0)

    // StreamDAO: Create, Update, UpdateStatus, UpdateRemoteAddress, Delete
    state := &model.StreamStateRecord{StreamConfiguration: model.StreamConfiguration{Id: "s1"}}
    assert.NoError(t, streamDAO.Create(ctx, state))
    expected++
    assert.NoError(t, streamDAO.Update(ctx, state))
    expected++
    assert.NoError(t, streamDAO.UpdateStatus(ctx, "s1", model.StreamStateEnabled, ""))
    expected++
    assert.NoError(t, streamDAO.UpdateRemoteAddress(ctx, "s1", &model.RemoteIP{IP: "1.2.3.4"}))
    expected++
    assert.NoError(t, streamDAO.Delete(ctx, "s1"))
    expected++

    // EventDAO: Insert, AddPending, RemovePending, MarkDelivered, ClearPendingForStream
    rec := &model.AgEventRecord{Jti: "j1"}
    assert.NoError(t, eventDAO.Insert(ctx, rec))
    expected++
    assert.NoError(t, eventDAO.AddPending(ctx, "j1", "s1"))
    expected++
    delivered, err := eventDAO.RemovePending(ctx, "j1", "s1")
    assert.NoError(t, err)
    assert.NotNil(t, delivered)
    expected++
    if delivered != nil {
        assert.NoError(t, eventDAO.MarkDelivered(ctx, delivered, time.Now()))
        expected++
    }
    _, err = eventDAO.ClearPendingForStream(ctx, "s1")
    assert.NoError(t, err)
    expected++

    // KeyDAO: Insert, DeleteByKid, Insert, DeleteByKeyName
    keyRec := &interfaces.JwkKeyRec{KeyName: "k1", Kid: "kid1"}
    assert.NoError(t, keyDAO.Insert(ctx, keyRec))
    expected++
    assert.NoError(t, keyDAO.DeleteByKid(ctx, "kid1"))
    expected++
    keyRec2 := &interfaces.JwkKeyRec{KeyName: "k2", Kid: "kid2"}
    assert.NoError(t, keyDAO.Insert(ctx, keyRec2))
    expected++
    assert.NoError(t, keyDAO.DeleteByKeyName(ctx, "k2"))
    expected++

    // ClientDAO: Insert, Delete
    cli := &model.SsfClient{Id: bson.NewObjectID(), ProjectIds: []string{"p1"}}
    assert.NoError(t, clientDAO.Insert(ctx, cli))
    expected++
    assert.NoError(t, clientDAO.Delete(ctx, cli.Id.Hex()))
    expected++

    // ServerDAO: Create, Update, Delete
    srv := &model.Server{Id: bson.NewObjectID(), Alias: "alias1", ProjectId: "p1"}
    assert.NoError(t, serverDAO.Create(ctx, srv))
    expected++
    assert.NoError(t, serverDAO.Update(ctx, srv))
    expected++
    assert.NoError(t, serverDAO.Delete(ctx, srv.Id.Hex()))
    expected++

    // TokenDAO: Insert, Revoke, DeleteExpired
    tok := &model.TokenRecord{
        JTI:       "t1",
        ClientID:  "c1",
        ProjectID: "p1",
        Type:      "stream",
        ExpiresAt: time.Now().Add(-time.Hour),
    }
    assert.NoError(t, tokenDAO.Insert(ctx, tok))
    expected++
    assert.NoError(t, tokenDAO.Revoke(ctx, "t1"))
    expected++
    assert.NoError(t, tokenDAO.DeleteExpired(ctx))
    expected++

    assert.Equal(t, expected, atomic.LoadInt32(&count),
        "decorator should call notify exactly once per successful mutation across every DAO")
}

// TestNotifyingDAOs_DoNotTriggerOnFailedMutation makes sure we don't
// MarkDirty when the underlying DAO returned an error. Updating a stream
// that doesn't exist returns ErrNotFound — the counter must stay at zero.
func TestNotifyingDAOs_DoNotTriggerOnFailedMutation(t *testing.T) {
    var count int32
    notify := func() { atomic.AddInt32(&count, 1) }

    ctx := context.Background()

    streamDAO := newNotifyingStreamDAO(memory.NewStreamDAO(), notify)
    err := streamDAO.Update(ctx, &model.StreamStateRecord{StreamConfiguration: model.StreamConfiguration{Id: "missing"}})
    assert.Error(t, err)
    assert.Equal(t, int32(0), atomic.LoadInt32(&count),
        "decorator must not call notify when the underlying DAO returned an error")
}
