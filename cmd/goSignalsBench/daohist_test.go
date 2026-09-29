package main

import (
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
)

const daoBefore = `# TYPE goSignals_dao_op_duration_seconds histogram
goSignals_dao_op_duration_seconds_bucket{op="InsertMany",outcome="ok",le="0.001"} 1
goSignals_dao_op_duration_seconds_bucket{op="InsertMany",outcome="ok",le="0.01"} 2
goSignals_dao_op_duration_seconds_bucket{op="InsertMany",outcome="ok",le="+Inf"} 2
goSignals_dao_op_duration_seconds_sum{op="InsertMany",outcome="ok"} 0.006
goSignals_dao_op_duration_seconds_count{op="InsertMany",outcome="ok"} 2
goSignals_dao_op_duration_seconds_bucket{op="FindByJTI",outcome="ok",le="0.001"} 4
goSignals_dao_op_duration_seconds_bucket{op="FindByJTI",outcome="ok",le="0.01"} 4
goSignals_dao_op_duration_seconds_bucket{op="FindByJTI",outcome="ok",le="+Inf"} 4
goSignals_dao_op_duration_seconds_sum{op="FindByJTI",outcome="ok"} 0.002
goSignals_dao_op_duration_seconds_count{op="FindByJTI",outcome="ok"} 4
goSignals_dao_batch_size_bucket{op="InsertMany",le="1"} 2
`

// After: InsertMany gained 100 ok calls (all in 1ms..10ms) and 2 error calls
// above 10ms; FindByJTI is unchanged; AddPendingMany is new.
const daoAfter = `goSignals_dao_op_duration_seconds_bucket{op="InsertMany",outcome="ok",le="0.001"} 1
goSignals_dao_op_duration_seconds_bucket{op="InsertMany",outcome="ok",le="0.01"} 102
goSignals_dao_op_duration_seconds_bucket{op="InsertMany",outcome="ok",le="+Inf"} 102
goSignals_dao_op_duration_seconds_sum{op="InsertMany",outcome="ok"} 0.506
goSignals_dao_op_duration_seconds_count{op="InsertMany",outcome="ok"} 102
goSignals_dao_op_duration_seconds_bucket{op="InsertMany",outcome="error",le="0.001"} 0
goSignals_dao_op_duration_seconds_bucket{op="InsertMany",outcome="error",le="0.01"} 0
goSignals_dao_op_duration_seconds_bucket{op="InsertMany",outcome="error",le="+Inf"} 2
goSignals_dao_op_duration_seconds_sum{op="InsertMany",outcome="error"} 0.1
goSignals_dao_op_duration_seconds_count{op="InsertMany",outcome="error"} 2
goSignals_dao_op_duration_seconds_bucket{op="FindByJTI",outcome="ok",le="0.001"} 4
goSignals_dao_op_duration_seconds_bucket{op="FindByJTI",outcome="ok",le="0.01"} 4
goSignals_dao_op_duration_seconds_bucket{op="FindByJTI",outcome="ok",le="+Inf"} 4
goSignals_dao_op_duration_seconds_sum{op="FindByJTI",outcome="ok"} 0.002
goSignals_dao_op_duration_seconds_count{op="FindByJTI",outcome="ok"} 4
goSignals_dao_op_duration_seconds_bucket{op="AddPendingMany",outcome="ok",le="0.001"} 10
goSignals_dao_op_duration_seconds_bucket{op="AddPendingMany",outcome="ok",le="0.01"} 10
goSignals_dao_op_duration_seconds_bucket{op="AddPendingMany",outcome="ok",le="+Inf"} 10
goSignals_dao_op_duration_seconds_sum{op="AddPendingMany",outcome="ok"} 0.005
goSignals_dao_op_duration_seconds_count{op="AddPendingMany",outcome="ok"} 10
`

func mustParseDao(t *testing.T, text string) daoHistograms {
	t.Helper()
	h, err := parseDaoHistograms(strings.NewReader(text))
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func near(a, b float64) bool { return math.Abs(a-b) < 1e-6 }

func TestParseDaoHistogramsSumsOutcomes(t *testing.T) {
	h := mustParseDao(t, daoAfter)
	im := h["InsertMany"]
	if im == nil {
		t.Fatal("InsertMany missing")
	}
	if im.Count != 104 || !near(im.Sum, 0.606) {
		t.Errorf("InsertMany count/sum = %v/%v, want 104/0.606", im.Count, im.Sum)
	}
	if got := im.Buckets[math.Inf(1)]; got != 104 {
		t.Errorf("+Inf bucket = %v, want 104", got)
	}
	if _, ok := h["batch_size"]; ok {
		t.Error("batch-size series must not be parsed as an op")
	}
}

func TestDiffAndSummarizeDao(t *testing.T) {
	d := diffDaoHistograms(mustParseDao(t, daoBefore), mustParseDao(t, daoAfter))
	if _, ok := d["FindByJTI"]; ok {
		t.Error("FindByJTI had no calls during the run and should be dropped")
	}
	stats := summarizeDao(d)
	im := stats["InsertMany"]
	if im.Calls != 102 {
		t.Errorf("InsertMany calls = %d, want 102", im.Calls)
	}
	if !near(im.TotalMs, 600) || !near(im.MeanMs, 600.0/102) {
		t.Errorf("InsertMany total/mean = %v/%v", im.TotalMs, im.MeanMs)
	}
	// 100 of 102 calls sit in (1ms, 10ms]: rank 51 -> 1 + 9*51/100 ms.
	if !near(im.P50Ms, 1+9*0.51) {
		t.Errorf("InsertMany p50 = %v, want %v", im.P50Ms, 1+9*0.51)
	}
	// rank 96.9 is still inside (1ms, 10ms].
	if !near(im.P95Ms, 1+9*0.969) {
		t.Errorf("InsertMany p95 = %v, want %v", im.P95Ms, 1+9*0.969)
	}
	ap := stats["AddPendingMany"]
	if ap.Calls != 10 || !near(ap.P50Ms, 0.5) {
		t.Errorf("AddPendingMany = %+v, want 10 calls p50 0.5ms", ap)
	}
	if got := dominantDaoOp(stats); got != "InsertMany" {
		t.Errorf("dominant op = %q, want InsertMany", got)
	}
}

func TestQuantileInfBucketReportsHighestFiniteBound(t *testing.T) {
	h := &opHistogram{Buckets: map[float64]float64{0.01: 0, math.Inf(1): 5}}
	if got := h.quantile(0.5); !near(got, 0.01) {
		t.Errorf("quantile in +Inf bucket = %v, want 0.01", got)
	}
	if got := (&opHistogram{Buckets: map[float64]float64{}}).quantile(0.5); got != 0 {
		t.Errorf("empty histogram quantile = %v, want 0", got)
	}
}

func TestDominantDaoOpSkipsWatchPending(t *testing.T) {
	stats := map[string]daoOpStats{"WatchPending": {TotalMs: 1e6}, "AddPendingMany": {TotalMs: 3}}
	if got := dominantDaoOp(stats); got != "AddPendingMany" {
		t.Errorf("dominant op = %q, want AddPendingMany", got)
	}
}

func TestJournalFromStatusAndDiff(t *testing.T) {
	status := func(syncs, writes int64, micros int32) bson.M {
		return bson.M{"host": "mongo1:30001", "wiredTiger": bson.M{"log": bson.M{
			wtLogSyncs: syncs, wtLogWrites: writes, wtLogFlushes: int32(7),
			wtLogBytes: float64(1024), wtLogSyncMicros: micros,
		}}}
	}
	before, err := journalFromStatus(mustRaw(t, status(100, 1000, 5000)))
	if err != nil {
		t.Fatal(err)
	}
	after, err := journalFromStatus(mustRaw(t, status(10100, 21000, 25000)))
	if err != nil {
		t.Fatal(err)
	}
	r := diffJournal(before, after, 5000)
	if r.Host != "mongo1:30001" || r.Syncs != 10000 || r.Writes != 20000 || r.Flushes != 0 || !near(r.SyncMs, 20) {
		t.Errorf("diff = %+v", r)
	}
	if !near(r.SyncsPerSET, 2) || !near(r.WritesPerSET, 4) {
		t.Errorf("per-SET = %v/%v, want 2/4", r.SyncsPerSET, r.WritesPerSET)
	}
	if diffJournal(nil, after, 1) != nil {
		t.Error("diff with a missing snapshot must be nil")
	}
}

func TestJournalFromStatusRejectsMissingSections(t *testing.T) {
	for name, st := range map[string]bson.M{
		"no wiredTiger": {"host": "x"},
		"no log":        {"wiredTiger": bson.M{}},
		"no syncs":      {"wiredTiger": bson.M{"log": bson.M{wtLogWrites: int64(1)}}},
		"non-numeric":   {"wiredTiger": bson.M{"log": bson.M{wtLogSyncs: "x", wtLogWrites: int64(1)}}},
	} {
		if _, err := journalFromStatus(mustRaw(t, st)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func mustRaw(t *testing.T, doc bson.M) bson.Raw {
	t.Helper()
	b, err := bson.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestBackupExistingKeepsPreviousPEM(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "issuer.pem")
	now := time.Date(2026, 9, 28, 18, 41, 0, 0, time.UTC)
	if got, err := backupExisting(path, now); err != nil || got != "" {
		t.Fatalf("missing file: got %q, %v; want no backup", got, err)
	}
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := backupExisting(path, now)
	if err != nil {
		t.Fatal(err)
	}
	if want := path + ".20260928T184100Z.bak"; got != want {
		t.Errorf("backup = %q, want %q", got, want)
	}
	if b, err := os.ReadFile(got); err != nil || string(b) != "old" {
		t.Errorf("backup content = %q, %v", b, err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("original should have been moved, stat err = %v", err)
	}
}
