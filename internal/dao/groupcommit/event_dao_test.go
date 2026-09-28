package groupcommit

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"testing"
	"time"

	mongodao "github.com/i2-open/i2goSignals/internal/dao/mongo"
	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/dao/ids"
	"github.com/i2-open/i2goSignals/pkg/dao/memory"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// The tests assert only on stored documents and returned errors — never on
// how callers were split into batches, which is timing-dependent.

var batched = Config{Window: 2 * time.Millisecond, Max: 8}

// storeFactory returns a fresh, empty EventDAO.
type storeFactory func(t *testing.T) interfaces.EventDAO

func memoryStore(t *testing.T) interfaces.EventDAO { return memory.NewEventDAO() }

// testDbUrl is the docker dev-stack replica set the other Mongo DAO tests use.
const testDbUrl = "mongodb://root:dockTest@mongo1:30001,mongo2:30002,mongo3:30003/?retryWrites=true&replicaSet=dbrs&readPreference=primary&serverSelectionTimeoutMS=5000&connectTimeoutMS=10000&authSource=admin&authMechanism=SCRAM-SHA-256"

var (
	mongoOnce   sync.Once
	mongoClient *mongo.Client
	mongoErr    error
)

// mongoStore returns an EventDAO over freshly dropped collections carrying the
// production sparse-unique JTI index (ADR 0017), or skips without Mongo.
func mongoStore(t *testing.T) interfaces.EventDAO {
	t.Helper()
	mongoOnce.Do(func() {
		c, err := mongo.Connect(options.Client().ApplyURI(testDbUrl))
		if err == nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			err = c.Ping(ctx, nil)
			cancel()
		}
		mongoClient, mongoErr = c, err
	})
	if mongoErr != nil {
		t.Skip("Mongo unavailable: " + mongoErr.Error())
	}
	ctx := context.Background()
	db := mongoClient.Database("test_group_commit")
	ev, pend, del := db.Collection("events"), db.Collection("pending"), db.Collection("delivered")
	for _, c := range []*mongo.Collection{ev, pend, del} {
		require.NoError(t, c.Drop(ctx))
	}
	_, err := ev.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "jti", Value: 1}},
		Options: options.Index().SetName("eventJtiUnique").SetUnique(true).SetSparse(true),
	})
	require.NoError(t, err)
	return mongodao.NewEventDAO(ev, pend, del)
}

var stores = map[string]storeFactory{"memory": memoryStore, "mongo": mongoStore}

// streamIDs are valid ObjectID hex strings so the Mongo store accepts them.
var streamIDs = []string{ids.NewObjectID(), ids.NewObjectID(), ids.NewObjectID()}

func rec(jti string) *model.EventRecord {
	return &model.EventRecord{Jti: jti, Original: "tok-" + jti, Sid: streamIDs[0]}
}

// outcome is what a scenario observed: every caller's errors and the stored
// state they produced.
type outcome struct {
	errs    map[string]string   // caller key -> error text ("" for nil)
	stored  []string            // sorted JTIs found by FindByJTI
	pending map[string][]string // stream -> sorted pending JTIs
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// scenario drives a concurrent ingest burst through dao: single Inserts, small
// InsertManys each carrying a duplicate at a known index, one pre-existing
// duplicate JTI, and AddPending/AddPendingMany across several streams.
func scenario(t *testing.T, dao interfaces.EventDAO) outcome {
	t.Helper()
	ctx := context.Background()
	require.NoError(t, dao.Insert(ctx, rec("existing")))

	var mu sync.Mutex
	out := outcome{errs: map[string]string{}, pending: map[string][]string{}}
	record := func(k string, err error) {
		mu.Lock()
		out.errs[k] = errText(err)
		mu.Unlock()
	}
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			jti := fmt.Sprintf("single-%02d", i)
			if i == 17 {
				jti = "existing"
			}
			record(fmt.Sprintf("insert-%02d", i), dao.Insert(ctx, rec(jti)))
		}(i)
	}
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			recs := []*model.EventRecord{
				rec(fmt.Sprintf("many-%02d-a", i)),
				rec("existing"),
				rec(fmt.Sprintf("many-%02d-b", i)),
			}
			res, err := dao.InsertMany(ctx, recs)
			k := fmt.Sprintf("many-%02d", i)
			record(k, err)
			assert.Len(t, res, len(recs))
			for j, e := range res {
				record(fmt.Sprintf("%s[%d]", k, j), e)
			}
		}(i)
	}
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sid := streamIDs[i%len(streamIDs)]
			if i%5 == 0 {
				jtis := []string{fmt.Sprintf("p-%02d-a", i), fmt.Sprintf("p-%02d-b", i)}
				record(fmt.Sprintf("pendmany-%02d", i), dao.AddPendingMany(ctx, jtis, sid))
				return
			}
			record(fmt.Sprintf("pend-%02d", i), dao.AddPending(ctx, fmt.Sprintf("p-%02d", i), sid))
		}(i)
	}
	wg.Wait()

	var probe []string
	probe = append(probe, "existing")
	for i := 0; i < 40; i++ {
		probe = append(probe, fmt.Sprintf("single-%02d", i))
	}
	for i := 0; i < 10; i++ {
		probe = append(probe, fmt.Sprintf("many-%02d-a", i), fmt.Sprintf("many-%02d-b", i))
	}
	for _, jti := range probe {
		r, err := dao.FindByJTI(ctx, jti)
		require.NoError(t, err)
		if r != nil {
			out.stored = append(out.stored, r.Jti)
		}
	}
	sort.Strings(out.stored)
	for _, sid := range streamIDs {
		jtis, _, err := dao.GetPendingForStream(ctx, sid, 1000)
		require.NoError(t, err)
		sort.Strings(jtis)
		out.pending[sid] = jtis
	}
	return out
}

func TestScenarioPerCallerOutcomes(t *testing.T) {
	for name, store := range stores {
		t.Run(name, func(t *testing.T) {
			got := scenario(t, Wrap(store(t), batched))
			dup := interfaces.ErrDuplicateJTI.Error()
			for k, e := range got.errs {
				switch {
				case k == "insert-17":
					assert.Equal(t, dup, e, k)
				case len(k) == len("many-00[1]") && k[len(k)-3:] == "[1]":
					assert.Equal(t, dup, e, k)
				default:
					assert.Empty(t, e, k)
				}
			}
			assert.Len(t, got.stored, 1+39+20)
			total := 0
			for _, jtis := range got.pending {
				total += len(jtis)
			}
			assert.Equal(t, 24+6*2, total)
		})
	}
}

// TestWindowZeroIdentical runs the same scenario unbatched (window 0) and
// batched and asserts identical stored state and errors.
func TestWindowZeroIdentical(t *testing.T) {
	for name, store := range stores {
		t.Run(name, func(t *testing.T) {
			raw := store(t)
			require.Same(t, raw, Wrap(raw, Config{Window: 0, Max: DefaultMax}),
				"window 0 must forward calls 1:1 to the inner DAO")
			off := scenario(t, raw)
			on := scenario(t, Wrap(store(t), batched))
			assert.Equal(t, off, on)
		})
	}
}

func TestMaxOverflowKeepsAlignment(t *testing.T) {
	dao := Wrap(memory.NewEventDAO(), Config{Window: 5 * time.Millisecond, Max: 4})
	ctx := context.Background()
	require.NoError(t, dao.Insert(ctx, rec("dup")))
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			recs := []*model.EventRecord{rec(fmt.Sprintf("o-%02d-a", i)), rec("dup"), rec(fmt.Sprintf("o-%02d-b", i))}
			res, err := dao.InsertMany(ctx, recs)
			assert.NoError(t, err)
			assert.Equal(t, []error{nil, interfaces.ErrDuplicateJTI, nil}, res)
		}(i)
	}
	wg.Wait()
	// A call at or above Max bypasses the batcher with the same semantics.
	big := []*model.EventRecord{rec("big-1"), rec("big-2"), rec("dup"), rec("big-3")}
	res, err := dao.InsertMany(ctx, big)
	require.NoError(t, err)
	assert.Equal(t, []error{nil, nil, interfaces.ErrDuplicateJTI, nil}, res)
}

// failingDAO fails every bulk write as a whole.
type failingDAO struct {
	interfaces.EventDAO
	err error
}

func (f failingDAO) InsertMany(context.Context, []*model.EventRecord) ([]error, error) {
	return nil, f.err
}
func (f failingDAO) AddPendingMany(context.Context, []string, string) error { return f.err }

func TestWholeBatchFailureReachesEveryCaller(t *testing.T) {
	boom := errors.New("connection reset")
	dao := Wrap(failingDAO{EventDAO: memory.NewEventDAO(), err: boom}, batched)
	ctx := context.Background()
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(3)
		go func(i int) {
			defer wg.Done()
			assert.ErrorIs(t, dao.Insert(ctx, rec(fmt.Sprintf("f-%d", i))), boom)
		}(i)
		go func(i int) {
			defer wg.Done()
			res, err := dao.InsertMany(ctx, []*model.EventRecord{rec(fmt.Sprintf("fm-%d", i))})
			assert.Nil(t, res)
			assert.ErrorIs(t, err, boom)
		}(i)
		go func(i int) {
			defer wg.Done()
			assert.ErrorIs(t, dao.AddPending(ctx, fmt.Sprintf("fp-%d", i), streamIDs[0]), boom)
		}(i)
	}
	wg.Wait()
}

// gatedDAO blocks bulk inserts until released and records the context each
// write ran on.
type gatedDAO struct {
	interfaces.EventDAO
	entered chan struct{}
	release chan struct{}
	ctxErr  chan error
}

func (g *gatedDAO) InsertMany(ctx context.Context, recs []*model.EventRecord) ([]error, error) {
	g.entered <- struct{}{}
	<-g.release
	g.ctxErr <- ctx.Err()
	return g.EventDAO.InsertMany(ctx, recs)
}

func TestCallerCancellationDoesNotCancelBatch(t *testing.T) {
	inner := &gatedDAO{
		EventDAO: memory.NewEventDAO(),
		entered:  make(chan struct{}, 1),
		release:  make(chan struct{}),
		ctxErr:   make(chan error, 1),
	}
	// Max 2: the two callers fill the batch, so they are certainly in one write.
	dao := Wrap(inner, Config{Window: time.Hour, Max: 2})

	cancelCtx, cancel := context.WithCancel(context.Background())
	aErr, bErr := make(chan error, 1), make(chan error, 1)
	go func() { aErr <- dao.Insert(cancelCtx, rec("a")) }()
	go func() { bErr <- dao.Insert(context.Background(), rec("b")) }()

	<-inner.entered
	cancel()
	assert.ErrorIs(t, <-aErr, context.Canceled, "the cancelled caller returns at once")
	close(inner.release)
	require.NoError(t, <-bErr)
	assert.NoError(t, <-inner.ctxErr, "the batch runs on a detached context")

	for _, jti := range []string{"a", "b"} {
		r, err := inner.FindByJTI(context.Background(), jti)
		require.NoError(t, err)
		assert.NotNil(t, r, jti)
	}

	// An already-cancelled caller never joins a batch.
	assert.ErrorIs(t, dao.Insert(cancelCtx, rec("c")), context.Canceled)
	r, err := inner.FindByJTI(context.Background(), "c")
	require.NoError(t, err)
	assert.Nil(t, r)
}

func TestConfigFromEnv(t *testing.T) {
	t.Setenv(EnvWindow, "")
	t.Setenv(EnvMax, "")
	assert.Equal(t, Config{Window: DefaultWindow, Max: DefaultMax}, ConfigFromEnv())
	assert.True(t, ConfigFromEnv().Enabled(), "batching is on by default")

	t.Setenv(EnvWindow, "0")
	assert.False(t, ConfigFromEnv().Enabled())

	t.Setenv(EnvWindow, "500us")
	t.Setenv(EnvMax, "64")
	assert.Equal(t, Config{Window: 500 * time.Microsecond, Max: 64}, ConfigFromEnv())

	t.Setenv(EnvWindow, "soon")
	t.Setenv(EnvMax, "-3")
	assert.Equal(t, Config{Window: DefaultWindow, Max: DefaultMax}, ConfigFromEnv())

	t.Setenv(EnvWindow, "1ms")
	t.Setenv(EnvMax, "1")
	assert.False(t, ConfigFromEnv().Enabled(), "max 1 disables batching")
}

// ingestScenario drives concurrent InsertWithPending callers through dao. Each
// caller queues its records on its own stream, one of its records repeats a
// pre-existing JTI, and the last caller queues on two streams — so a coalesced
// write must keep every caller's markers on that caller's streams only, and a
// duplicate must leave no marker anywhere.
func ingestScenario(t *testing.T, dao interfaces.EventDAO) outcome {
	t.Helper()
	ctx := context.Background()
	require.NoError(t, dao.Insert(ctx, rec("existing")))

	var mu sync.Mutex
	out := outcome{errs: map[string]string{}, pending: map[string][]string{}}
	var wg sync.WaitGroup
	const callers = 12
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			a, b := fmt.Sprintf("ing-%02d-a", i), fmt.Sprintf("ing-%02d-b", i)
			recs := []*model.EventRecord{rec(a), rec("existing"), rec(b)}
			sid := streamIDs[i%2]
			pending := map[string][]string{sid: {a, "existing", b}}
			if i == callers-1 {
				pending[streamIDs[2]] = []string{b}
			}
			res, err := dao.InsertWithPending(ctx, recs, pending)
			mu.Lock()
			defer mu.Unlock()
			k := fmt.Sprintf("ing-%02d", i)
			out.errs[k] = errText(err)
			assert.Len(t, res, len(recs))
			for j, e := range res {
				out.errs[fmt.Sprintf("%s[%d]", k, j)] = errText(e)
			}
		}(i)
	}
	wg.Wait()
	for i := 0; i < callers; i++ {
		for _, s := range []string{"a", "b"} {
			r, err := dao.FindByJTI(ctx, fmt.Sprintf("ing-%02d-%s", i, s))
			require.NoError(t, err)
			if r != nil {
				out.stored = append(out.stored, r.Jti)
			}
		}
	}
	sort.Strings(out.stored)
	for _, sid := range streamIDs {
		jtis, _, err := dao.GetPendingForStream(ctx, sid, 1000)
		require.NoError(t, err)
		sort.Strings(jtis)
		out.pending[sid] = jtis
	}
	return out
}

func TestInsertWithPendingCoalescesPerCaller(t *testing.T) {
	for name, store := range stores {
		t.Run(name, func(t *testing.T) {
			got := ingestScenario(t, Wrap(store(t), batched))
			dup := interfaces.ErrDuplicateJTI.Error()
			for k, e := range got.errs {
				if len(k) == len("ing-00[1]") && k[len(k)-3:] == "[1]" {
					assert.Equal(t, dup, e, k)
				} else {
					assert.Empty(t, e, k)
				}
			}
			assert.Len(t, got.stored, 24)
			var even, odd []string
			for i := 0; i < 12; i++ {
				pair := []string{fmt.Sprintf("ing-%02d-a", i), fmt.Sprintf("ing-%02d-b", i)}
				if i%2 == 0 {
					even = append(even, pair...)
				} else {
					odd = append(odd, pair...)
				}
			}
			sort.Strings(even)
			sort.Strings(odd)
			assert.Equal(t, even, got.pending[streamIDs[0]])
			assert.Equal(t, odd, got.pending[streamIDs[1]])
			assert.Equal(t, []string{"ing-11-b"}, got.pending[streamIDs[2]])

			unbatched := ingestScenario(t, Wrap(store(t), Config{}))
			assert.Equal(t, unbatched, got)
		})
	}
}
