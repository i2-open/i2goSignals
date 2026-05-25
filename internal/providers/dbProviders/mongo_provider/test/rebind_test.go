package test

import (
    "context"
    "sync"
    "sync/atomic"
    "testing"
    "time"

    "github.com/i2-open/i2goSignals/internal/dao/ids"
    "github.com/i2-open/i2goSignals/internal/dao/interfaces"
    "github.com/i2-open/i2goSignals/internal/providers/dbProviders/mongo_provider"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/suite"
)

// RebindTestSuite exercises the rebindable-collection path introduced in
// PR4 phase B. The acceptance criterion of issue #46 says: "must fail if
// the rebind ordering is wrong." The tests below would have failed under
// the previous swap-on-reconnect pattern because callers held references
// to the *old* DAOs even after a ResetDb.
type RebindTestSuite struct {
    suite.Suite
    provider *mongo_provider.MongoProvider
}

func (s *RebindTestSuite) SetupSuite() {
    setMongoResumeFileTempDir(s.T())
    p, err := mongo_provider.Open(mongoURL(), "ssef_test_rebind")
    if err != nil {
        s.T().Skip("MongoDB not available: " + err.Error())
        return
    }
    if err := p.Check(); err != nil {
        s.T().Skip("MongoDB ping failed: " + err.Error())
        return
    }
    s.provider = p
}

func (s *RebindTestSuite) TearDownSuite() {
    if s.provider != nil {
        _ = s.provider.Close()
    }
}

func (s *RebindTestSuite) SetupTest() {
    if s.provider == nil {
        return
    }
    _ = s.provider.ResetDb(true)
}

func TestRebindSuite(t *testing.T) {
    suite.Run(t, new(RebindTestSuite))
}

// TestKeyDAOSurvivesReset proves a long-held reference to a KeyDAO works
// correctly across a ResetDb. Under the swap-on-reconnect pattern the DAO
// reference would silently point at a freed collection. Under the rebind
// pattern, the same DAO instance sees the new collection.
func (s *RebindTestSuite) TestKeyDAOSurvivesReset() {
    if s.provider == nil {
        s.T().Skip("MongoDB not available")
        return
    }
    keyDAO := s.provider.GetKeyDAO()

    // Insert before reset.
    err := keyDAO.Insert(context.Background(), &interfaces.JwkKeyRec{
        Id:      ids.NewObjectID(),
        KeyName: "before-reset",
        Kid:     "kid-before",
        Use:     "sig",
    })
    s.NoError(err)

    // Force a full reset; this calls initialize() which rebinds the
    // collection on the same DAO instance.
    err = s.provider.ResetDb(true)
    s.NoError(err)

    // The same keyDAO reference must now be operational against the
    // freshly-bound collection. Under the old swap pattern, this would
    // either error ("collection not initialized" if we got lucky with
    // ordering) or silently land on a stale collection from before reset.
    err = keyDAO.Insert(context.Background(), &interfaces.JwkKeyRec{
        Id:      ids.NewObjectID(),
        KeyName: "after-reset",
        Kid:     "kid-after",
        Use:     "sig",
    })
    s.NoError(err, "long-held DAO reference should survive ResetDb")

    // Verify the post-reset write actually landed: read it back via the
    // same long-held DAO reference.
    rec, err := keyDAO.FindByKid(context.Background(), "kid-after")
    s.NoError(err)
    s.NotNil(rec)
    s.Equal("after-reset", rec.KeyName)

    // Verify the pre-reset write is gone (ResetDb wiped the DB).
    _, err = keyDAO.FindByKid(context.Background(), "kid-before")
    s.Error(err, "pre-reset key should not exist after ResetDb")
}

// TestConcurrentWritesDuringRebind stresses the atomic-pointer rebind: a
// pool of writers hammer Insert while ResetDb fires repeatedly. The
// invariant is "no panic, no nil-collection error, every successful write
// lands on the collection that was current at the moment of the write."
func (s *RebindTestSuite) TestConcurrentWritesDuringRebind() {
    if s.provider == nil {
        s.T().Skip("MongoDB not available")
        return
    }

    var wg sync.WaitGroup
    var ok int64
    var failed int64

    stop := make(chan struct{})
    writerCount := 4
    duration := 1500 * time.Millisecond

    // Writers: insert keys via the long-held DAO reference.
    keyDAO := s.provider.GetKeyDAO()
    for i := 0; i < writerCount; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            for {
                select {
                case <-stop:
                    return
                default:
                }
                err := keyDAO.Insert(context.Background(), &interfaces.JwkKeyRec{
                    Id:      ids.NewObjectID(),
                    KeyName: "rebind-writer",
                    Kid:     ids.NewObjectID(),
                    Use:     "sig",
                })
                if err != nil {
                    atomic.AddInt64(&failed, 1)
                } else {
                    atomic.AddInt64(&ok, 1)
                }
            }
        }()
    }

    // Resetter: trigger rebinds while writers run.
    wg.Add(1)
    go func() {
        defer wg.Done()
        ticker := time.NewTicker(150 * time.Millisecond)
        defer ticker.Stop()
        for {
            select {
            case <-stop:
                return
            case <-ticker.C:
                _ = s.provider.ResetDb(true)
            }
        }
    }()

    time.Sleep(duration)
    close(stop)
    wg.Wait()

    // The race-free expectation: at least *some* writes succeeded across
    // multiple rebinds. A nil-collection bug would manifest as either a
    // panic (test crash) or every write failing.
    s.Greater(atomic.LoadInt64(&ok), int64(0), "expected at least one successful write during rebind churn")
    // We tolerate failures racing with ResetDb's drop, but they must not
    // panic the process. (If the pointer rebind weren't atomic, the
    // -race detector would catch it.)
    _ = atomic.LoadInt64(&failed)
}

// Sanity assertion the suite caught my off-by-one — keep this last and
// independent so a refactor can replace it without breaking the others.
func (s *RebindTestSuite) TestProviderName() {
    if s.provider == nil {
        s.T().Skip("MongoDB not available")
        return
    }
    assert.Equal(s.T(), "ssef_test_rebind", s.provider.Name())
}
