package eventRouter

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/i2-open/i2goSignals/internal/providers/cluster"
	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/dao/memory"
	"github.com/i2-open/i2goSignals/pkg/services"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fixedFence is a coordinator whose every lease carries token.
type fixedFence struct {
	cluster.ClusterCoordinator
	token int64
}

func (f fixedFence) GetLeaseOwner(string) (string, time.Time, int64, error) {
	return "node-a", time.Now().Add(time.Minute), f.token, nil
}

func windowDays(n int) *int { return &n }

// ackRouter is a bare router over a memory store holding one push stream sid
// with the given per-stream retention window, and one pending reference j1.
func ackRouter(t *testing.T, window services.EffectiveWindowFunc, days *int) (*router, *memory.EventDAOMemory, string) {
	t.Helper()
	dao := memory.NewEventDAO()
	sid := model.NewRecordId().Hex()
	require.NoError(t, dao.AddPending(context.Background(), interfaces.PendingRef{Jti: "j1", AckJti: "j1"}, sid))
	r := &router{
		eventService:      services.NewEventService(dao),
		pushStreams:       map[string]model.StreamStateRecord{sid: {RetentionWindowDays: days}},
		pollStreams:       map[string]model.StreamStateRecord{},
		sstpClientStreams: map[string]model.StreamStateRecord{},
		sstpServerStreams: map[string]model.StreamStateRecord{},
		retentionWindow:   window,
	}
	return r, dao, sid
}

func deliveredExpireAt(t *testing.T, dao *memory.EventDAOMemory, sid string) (*time.Time, bool) {
	t.Helper()
	list, err := dao.ListDeliveredForStream(context.Background(), sid)
	require.NoError(t, err)
	for _, e := range list {
		if e.Jti == "j1" {
			return e.ExpireAt, true
		}
	}
	return nil, false
}

// A finite window resolved from the stream record the router holds is written
// as expireAt = ackDate + window at acknowledgement (#360, seam S1).
func TestAckEvents_FiniteWindowWritesExpireAt(t *testing.T) {
	r, dao, sid := ackRouter(t, services.DefaultEffectiveWindow, windowDays(3))
	before := time.Now()
	require.NoError(t, r.ackEvents(context.Background(), []string{"j1"}, sid, services.NoFencingToken))
	after := time.Now()

	expireAt, ok := deliveredExpireAt(t, dao, sid)
	require.True(t, ok, "j1 delivered")
	require.NotNil(t, expireAt)
	window := 3 * 24 * time.Hour
	assert.False(t, expireAt.Before(before.Add(window).Truncate(time.Millisecond)), "expireAt %v before ack+window", expireAt)
	assert.False(t, expireAt.After(after.Add(window)), "expireAt %v after ack+window", expireAt)
}

// No resolver (community), a nil window and a non-positive window all keep
// the reference forever: no expireAt is written.
func TestAckEvents_KeepForeverWritesNoExpireAt(t *testing.T) {
	cases := map[string]struct {
		window services.EffectiveWindowFunc
		days   *int
	}{
		"no resolver":  {nil, windowDays(3)},
		"nil window":   {services.DefaultEffectiveWindow, nil},
		"zero window":  {services.DefaultEffectiveWindow, windowDays(0)},
		"negative":     {services.DefaultEffectiveWindow, windowDays(-1)},
		"nil override": {func(*model.StreamStateRecord) *int { return nil }, windowDays(3)},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			r, dao, sid := ackRouter(t, c.window, c.days)
			require.NoError(t, r.ackEvents(context.Background(), []string{"j1"}, sid, services.NoFencingToken))
			expireAt, ok := deliveredExpireAt(t, dao, sid)
			require.True(t, ok, "j1 delivered")
			assert.Nil(t, expireAt)
		})
	}
}

// An ack for a stream the router does not hold writes no expireAt.
func TestAckEvents_UnknownStreamWritesNoExpireAt(t *testing.T) {
	r, dao, sid := ackRouter(t, services.DefaultEffectiveWindow, windowDays(3))
	r.pushStreams = map[string]model.StreamStateRecord{}
	require.NoError(t, r.ackEvents(context.Background(), []string{"j1"}, sid, services.NoFencingToken))
	expireAt, ok := deliveredExpireAt(t, dao, sid)
	require.True(t, ok)
	assert.Nil(t, expireAt)
}

// The expireAt path keeps the ack fence (#334): a leased stream's ack with a
// stale token is refused before it writes; the current token is accepted.
func TestAckEvents_ExpireAtPathKeepsFence(t *testing.T) {
	r, dao, sid := ackRouter(t, services.DefaultEffectiveWindow, windowDays(3))
	r.coordinator = fixedFence{token: 7}

	err := r.ackEvents(context.Background(), []string{"j1"}, sid, 6)
	require.Error(t, err)
	assert.True(t, errors.Is(err, services.ErrStaleFencingToken))
	_, ok := deliveredExpireAt(t, dao, sid)
	assert.False(t, ok, "a fenced ack must not write")

	require.NoError(t, r.ackEvents(context.Background(), []string{"j1"}, sid, 7))
	expireAt, ok := deliveredExpireAt(t, dao, sid)
	require.True(t, ok)
	assert.NotNil(t, expireAt)
}
