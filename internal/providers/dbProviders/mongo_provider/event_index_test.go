package mongo_provider

import (
    "context"
    "errors"
    "path/filepath"
    "testing"
    "time"

    mongodao "github.com/i2-open/i2goSignals/internal/dao/mongo"
    interfaces "github.com/i2-open/i2goSignals/pkg/dao"
    model "github.com/i2-open/i2goSignals/pkg/ssfModels"
    "go.mongodb.org/mongo-driver/v2/bson"
)

// openEventIdxProvider opens a fresh provider against the live Mongo and
// resets the database so index assertions start from a clean collection.
// Skips when Mongo is unreachable.
func openEventIdxProvider(t *testing.T) *MongoProvider {
    t.Helper()
    t.Setenv("I2SIG_STORE_MONGO_RESUME_FILE", filepath.Join(t.TempDir(), "mongo_token.json"))
    p, err := Open(ttlMongoURL(), "eventidxtest")
    if err != nil {
        t.Skip("Mongo client error: " + err.Error())
    }
    if err := p.Check(); err != nil {
        t.Skip("Mongo Server not available: " + err.Error())
    }
    if err := p.ResetDb(true); err != nil {
        t.Fatalf("ResetDb: %v", err)
    }
    t.Cleanup(func() { _ = p.Close() })
    return p
}

// findEventJtiIndex returns the spec entry for eventJtiUnique on the event
// collection, or nil when absent.
func findEventJtiIndex(t *testing.T, p *MongoProvider) (sparse, unique bool, found bool) {
    t.Helper()
    specs, err := p.eventCol.Indexes().ListSpecifications(context.Background(), nil)
    if err != nil {
        t.Fatalf("ListSpecifications: %v", err)
    }
    for _, s := range specs {
        if s.Name == eventJtiIndexName {
            sparseV := false
            if s.Sparse != nil {
                sparseV = *s.Sparse
            }
            uniqueV := false
            if s.Unique != nil {
                uniqueV = *s.Unique
            }
            return sparseV, uniqueV, true
        }
    }
    return false, false, false
}

// TestEventJtiIndex_CreatedOnFreshDb: a fresh database's createIndexes run
// installs the sparse-unique eventJtiUnique index on eventCol.jti.
func TestEventJtiIndex_CreatedOnFreshDb(t *testing.T) {
    p := openEventIdxProvider(t)
    sparse, unique, found := findEventJtiIndex(t, p)
    if !found {
        t.Fatalf("event jti index %q not found", eventJtiIndexName)
    }
    if !unique {
        t.Errorf("event jti index should be unique")
    }
    if !sparse {
        t.Errorf("event jti index should be sparse")
    }
}

// TestEventJtiIndex_StartupSafetyNet: when pre-existing duplicate JTIs are
// present in eventCol, createIndexes must NOT abort startup. It logs a WARN
// and continues with the index absent. Subsequent inserts succeed (dedup
// guarantee is off, by design — documented in the slice).
func TestEventJtiIndex_StartupSafetyNet(t *testing.T) {
    p := openEventIdxProvider(t)
    ctx := context.Background()

    // Drop the unique index that was just created on the fresh DB so we can
    // simulate the pre-existing-duplicates path.
    if err := p.eventCol.Indexes().DropOne(ctx, eventJtiIndexName); err != nil {
        t.Fatalf("could not drop %s: %v", eventJtiIndexName, err)
    }

    // Insert two records with the SAME JTI — only possible without the unique
    // index. This is the "pre-existing duplicates" state from a legacy
    // collection.
    _, err := p.eventCol.InsertOne(ctx, bson.M{"jti": "legacy-dup", "i": 1})
    if err != nil {
        t.Fatalf("first legacy insert: %v", err)
    }
    _, err = p.eventCol.InsertOne(ctx, bson.M{"jti": "legacy-dup", "i": 2})
    if err != nil {
        t.Fatalf("second legacy insert: %v", err)
    }

    // Re-run createIndexes. Must NOT error.
    if err := p.createIndexes(ctx); err != nil {
        t.Fatalf("createIndexes with pre-existing duplicates must not return error, got %v", err)
    }

    // Index must be absent (Mongo refused to build it).
    if _, _, found := findEventJtiIndex(t, p); found {
        t.Fatalf("event jti index must be absent after pre-existing duplicates")
    }

    // Insert through the DAO surface must NOT return ErrDuplicateJTI — the
    // guarantee is off, by design.
    dao := mongodao.NewEventDAO(p.eventCol, p.pendingCol, p.deliveredCol)
    rec := &model.AgEventRecord{Jti: "legacy-dup", SortTime: time.Now()}
    err = dao.Insert(ctx, rec)
    if err != nil && errors.Is(err, interfaces.ErrDuplicateJTI) {
        t.Fatalf("dedup guarantee should be OFF when index is absent, got ErrDuplicateJTI")
    }
}
