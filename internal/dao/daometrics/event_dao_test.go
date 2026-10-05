package daometrics_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/i2-open/i2goSignals/internal/dao/daometrics"
	"github.com/i2-open/i2goSignals/internal/providers/dbProviders"
	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/dao/memory"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// histo returns the sample count and sum of the named histogram series whose
// labels match want, gathered from reg. A missing series reads as (0, 0).
func histo(t *testing.T, reg *prometheus.Registry, name string, want map[string]string) (uint64, float64) {
	t.Helper()
	families, err := reg.Gather()
	require.NoError(t, err)
	for _, mf := range families {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			if labelsMatch(m, want) {
				return m.GetHistogram().GetSampleCount(), m.GetHistogram().GetSampleSum()
			}
		}
	}
	return 0, 0
}

func labelsMatch(m *dto.Metric, want map[string]string) bool {
	got := map[string]string{}
	for _, lp := range m.GetLabel() {
		got[lp.GetName()] = lp.GetValue()
	}
	if len(got) != len(want) {
		return false
	}
	for k, v := range want {
		if got[k] != v {
			return false
		}
	}
	return true
}

func privateRegistry(t *testing.T, m *daometrics.Metrics) *prometheus.Registry {
	t.Helper()
	reg := prometheus.NewRegistry()
	for _, c := range m.Collectors() {
		require.NoError(t, reg.Register(c))
	}
	return reg
}

const (
	durName  = "goSignals_dao_op_duration_seconds"
	sizeName = "goSignals_dao_batch_size"
)

// TestMemoryProvider_EventDAOIsInstrumented drives InsertMany and
// AddPendingMany through the memory provider's live EventDAO (the instance the
// router's EventService writes through) and asserts both histograms observe
// them on the process-wide Default metrics.
func TestMemoryProvider_EventDAOIsInstrumented(t *testing.T) {
	t.Setenv("I2SIG_STORE_MEM_DIRECTORY", t.TempDir())
	reg := privateRegistry(t, daometrics.Default)

	p, err := dbProviders.OpenPersistence("memorydb:", "test_daometrics_mem")
	require.NoError(t, err)
	defer func() { _ = p.Storage.Close() }()

	ctx := context.Background()
	insOK := map[string]string{"op": "InsertMany", "outcome": "ok"}
	addOK := map[string]string{"op": "AddPendingMany", "outcome": "ok"}
	insBefore, _ := histo(t, reg, durName, insOK)
	addBefore, _ := histo(t, reg, durName, addOK)
	insSizeBefore, insSizeSumBefore := histo(t, reg, sizeName, map[string]string{"op": "InsertMany"})
	addSizeBefore, addSizeSumBefore := histo(t, reg, sizeName, map[string]string{"op": "AddPendingMany"})

	recs := []*model.EventRecord{{Jti: "daom-1"}, {Jti: "daom-2"}, {Jti: "daom-3"}}
	_, err = p.EventDAO.InsertMany(ctx, recs)
	require.NoError(t, err)
	require.NoError(t, p.EventDAO.AddPendingMany(ctx, refsFrom([]string{"daom-1", "daom-2"}), "stream-1"))

	n, _ := histo(t, reg, durName, insOK)
	assert.Equal(t, insBefore+1, n, "InsertMany ok latency observed")
	n, _ = histo(t, reg, durName, addOK)
	assert.Equal(t, addBefore+1, n, "AddPendingMany ok latency observed")

	n, sum := histo(t, reg, sizeName, map[string]string{"op": "InsertMany"})
	assert.Equal(t, insSizeBefore+1, n)
	assert.Equal(t, insSizeSumBefore+3, sum, "InsertMany batch size is the record count")
	n, sum = histo(t, reg, sizeName, map[string]string{"op": "AddPendingMany"})
	assert.Equal(t, addSizeBefore+1, n)
	assert.Equal(t, addSizeSumBefore+2, sum, "AddPendingMany batch size is the JTI count")

	// The router's EventService writes through the same instrumented DAO.
	before, _ := histo(t, reg, durName, map[string]string{"op": "Insert", "outcome": "ok"})
	evRec := &model.EventRecord{Jti: "daom-svc"}
	require.NoError(t, p.EventDAO.Insert(ctx, evRec))
	after, _ := histo(t, reg, durName, map[string]string{"op": "Insert", "outcome": "ok"})
	assert.Equal(t, before+1, after)
}

// failingEventDAO is a memory EventDAO whose batch writes fail at the batch
// level — the memory store itself never fails them.
type failingEventDAO struct {
	*memory.EventDAOMemory
}

var errBoom = errors.New("boom")

func (f failingEventDAO) InsertMany(context.Context, []*model.EventRecord) ([]error, error) {
	return nil, errBoom
}

func (f failingEventDAO) AddPendingMany(context.Context, []interfaces.PendingRef, string) error {
	return errBoom
}

// TestWrap_OkAndErrorOutcomes asserts the outcome label and batch-size
// histogram on both the ok and error paths, against a private Metrics.
func TestWrap_OkAndErrorOutcomes(t *testing.T) {
	ctx := context.Background()
	m := daometrics.NewMetrics()
	reg := privateRegistry(t, m)

	ok := daometrics.Wrap(memory.NewEventDAO(), m)
	bad := daometrics.Wrap(failingEventDAO{memory.NewEventDAO()}, m)

	_, err := ok.InsertMany(ctx, []*model.EventRecord{{Jti: "a"}, {Jti: "b"}})
	require.NoError(t, err)
	require.NoError(t, ok.AddPendingMany(ctx, refsFrom([]string{"a"}), "s"))

	_, err = bad.InsertMany(ctx, []*model.EventRecord{{Jti: "c"}})
	assert.ErrorIs(t, err, errBoom, "errors pass through verbatim")
	assert.ErrorIs(t, bad.AddPendingMany(ctx, refsFrom([]string{"c", "d", "e"}), "s"), errBoom)

	for _, tc := range []struct {
		op, outcome string
	}{
		{"InsertMany", "ok"}, {"InsertMany", "error"},
		{"AddPendingMany", "ok"}, {"AddPendingMany", "error"},
	} {
		n, _ := histo(t, reg, durName, map[string]string{"op": tc.op, "outcome": tc.outcome})
		assert.Equal(t, uint64(1), n, "%s/%s latency observed once", tc.op, tc.outcome)
	}

	n, sum := histo(t, reg, sizeName, map[string]string{"op": "InsertMany"})
	assert.Equal(t, uint64(2), n)
	assert.Equal(t, float64(3), sum)
	n, sum = histo(t, reg, sizeName, map[string]string{"op": "AddPendingMany"})
	assert.Equal(t, uint64(2), n)
	assert.Equal(t, float64(4), sum)
}

// TestWrap_EveryMethodObserved calls every EventDAO method once through the
// decorator and asserts each records a latency sample labelled by its Go
// method name.
func TestWrap_EveryMethodObserved(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := daometrics.NewMetrics()
	reg := privateRegistry(t, m)
	d := daometrics.Wrap(memory.NewEventDAO(), m)

	_ = d.Insert(ctx, &model.EventRecord{Jti: "j"})
	_, _ = d.InsertMany(ctx, []*model.EventRecord{{Jti: "k"}})
	_, _ = d.FindByJTI(ctx, "j")
	_, _ = d.FindByJTIs(ctx, []string{"j"})
	_, _ = d.FindByTimeRange(ctx, time.Now(), nil, nil)
	_ = d.AddPending(ctx, refOf("j"), "s")
	_ = d.AddPendingMany(ctx, refsFrom([]string{"k"}), "s")
	_, _ = d.EnsurePending(ctx, "q", selfAck([]string{"s"}))
	_, _, _ = pageJtis(d.GetPendingForStream(ctx, "s", 10))
	_, _ = d.RemovePendingMany(ctx, []string{"k"}, "s")
	_, _ = d.InsertWithPending(ctx, []*model.EventRecord{{Jti: "w"}}, pendingRefsOf(map[string][]string{"s": {"w"}}))
	_, _ = d.ClearPendingForStream(ctx, "s")
	_, _ = d.Ack(ctx, interfaces.AckBatch{StreamID: "s", Jtis: []string{"j"}, AckDate: time.Now()})
	_, _ = d.ResetPendingAckJti(ctx, "s")
	_, _ = d.SweepExpired(ctx, time.Now(), time.Now(), 1)
	_, _ = d.MigrateLegacyDeliveries(ctx, nil)
	_, _ = d.ListDeliveredForStream(ctx, "s")
	_ = d.RemoveDelivered(ctx, "j", "s")
	_, _ = d.DeleteBodyIfUnreferenced(ctx, "j")
	_, _ = d.CountRetainedForStream(ctx, "s")
	// The memory WatchPending blocks until its context ends; hand it a done one.
	done, stop := context.WithCancel(ctx)
	stop()
	_ = d.WatchPending(done, func(interfaces.PendingRef, string) {})

	for _, op := range []string{
		"Insert", "InsertMany", "FindByJTI", "FindByJTIs", "FindByTimeRange",
		"AddPending", "AddPendingMany", "EnsurePending", "GetPendingForStream",
		"RemovePendingMany", "InsertWithPending", "ClearPendingForStream",
		"Ack", "ResetPendingAckJti", "SweepExpired", "MigrateLegacyDeliveries", "ListDeliveredForStream",
		"RemoveDelivered", "DeleteBodyIfUnreferenced", "CountRetainedForStream",
		"WatchPending",
	} {
		ok, _ := histo(t, reg, durName, map[string]string{"op": op, "outcome": "ok"})
		bad, _ := histo(t, reg, durName, map[string]string{"op": op, "outcome": "error"})
		assert.Equal(t, uint64(1), ok+bad, "%s observed once", op)
	}

	for _, op := range []string{"InsertMany", "AddPendingMany", "FindByJTIs", "RemovePendingMany", "Ack"} {
		n, sum := histo(t, reg, sizeName, map[string]string{"op": op})
		assert.Equal(t, uint64(1), n, "%s batch size observed", op)
		assert.Equal(t, float64(1), sum, "%s batch size", op)
	}
}
