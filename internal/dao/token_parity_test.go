package dao_test

import (
    "context"
    "testing"
    "time"

    interfaces "github.com/i2-open/i2goSignals/pkg/dao"
    "github.com/i2-open/i2goSignals/internal/dao/memory"
    "github.com/i2-open/i2goSignals/internal/dao/mongo"
    "github.com/i2-open/i2goSignals/pkg/ssfModels"
    "github.com/stretchr/testify/require"
    drivermongo "go.mongodb.org/mongo-driver/v2/mongo"
    "go.mongodb.org/mongo-driver/v2/mongo/options"
)

// TestDbUrl mirrors the connection string used by the per-adapter mongo
// suites; the parity test skips the mongo arm when Mongo is unreachable.
const TestDbUrl = "mongodb://root:dockTest@mongo1:30001,mongo2:30002,mongo3:30003/?retryWrites=true&replicaSet=dbrs&readPreference=primary&serverSelectionTimeoutMS=5000&connectTimeoutMS=10000&authSource=admin&authMechanism=SCRAM-SHA-256"

// daoFactory builds a fresh, empty TokenDAO for one parity sub-test. The
// returned cleanup releases any backing resources.
type daoFactory struct {
    name string
    open func(t *testing.T) (dao interfaces.TokenDAO, cleanup func())
}

func tokenDAOFactories() []daoFactory {
    return []daoFactory{
        {
            name: "memory",
            open: func(t *testing.T) (interfaces.TokenDAO, func()) {
                return memory.NewTokenDAO(), func() {}
            },
        },
        {
            name: "mongo",
            open: func(t *testing.T) (interfaces.TokenDAO, func()) {
                opts := options.Client().ApplyURI(TestDbUrl)
                client, err := drivermongo.Connect(opts)
                if err != nil {
                    t.Skip("Mongo connection error: " + err.Error())
                }
                if err = client.Ping(context.Background(), nil); err != nil {
                    t.Skip("Mongo ping error: " + err.Error())
                }
                col := client.Database("test_db").Collection("tokens_parity")
                _ = col.Drop(context.Background())
                return mongo.NewTokenDAO(col), func() {
                    _ = col.Drop(context.Background())
                    _ = client.Disconnect(context.Background())
                }
            },
        },
    }
}

// TestTokenDAO_RecordRedemption_Parity enforces that the Mongo and memory
// TokenDAO adapters implement RecordRedemption identically: the first
// redemption sets ip/time and a count of 1, and a second redemption
// increments the count and overwrites the last-redemption ip/time.
func TestTokenDAO_RecordRedemption_Parity(t *testing.T) {
    for _, f := range tokenDAOFactories() {
        t.Run(f.name, func(t *testing.T) {
            dao, cleanup := f.open(t)
            defer cleanup()
            ctx := context.Background()

            jti := "iat-parity-1"
            require.NoError(t, dao.Insert(ctx, &model.TokenRecord{
                JTI:       jti,
                ProjectID: "p1",
                Type:      model.TokenTypeIAT,
                IssuedAt:  time.Now().UTC(),
            }))

            t1 := time.Now().UTC().Truncate(time.Millisecond)
            require.NoError(t, dao.RecordRedemption(ctx, jti, "10.0.0.1", t1))

            rec, err := dao.FindByJTI(ctx, jti)
            require.NoError(t, err)
            require.Equal(t, int64(1), rec.RedemptionCount)
            require.Equal(t, "10.0.0.1", rec.LastRedemptionIP)
            require.WithinDuration(t, t1, rec.LastRedemptionAt, time.Second)

            t2 := t1.Add(time.Minute)
            require.NoError(t, dao.RecordRedemption(ctx, jti, "10.0.0.2", t2))

            rec, err = dao.FindByJTI(ctx, jti)
            require.NoError(t, err)
            require.Equal(t, int64(2), rec.RedemptionCount)
            require.Equal(t, "10.0.0.2", rec.LastRedemptionIP)
            require.WithinDuration(t, t2, rec.LastRedemptionAt, time.Second)
        })
    }
}

// TestTokenDAO_FindAll_Parity enforces that the Mongo and memory TokenDAO
// adapters implement FindAll identically: it returns every tracked token
// across all projects (used by the admin/root caller-scoped list) and round
// trips the StreamID join key.
func TestTokenDAO_FindAll_Parity(t *testing.T) {
    for _, f := range tokenDAOFactories() {
        t.Run(f.name, func(t *testing.T) {
            dao, cleanup := f.open(t)
            defer cleanup()
            ctx := context.Background()

            require.NoError(t, dao.Insert(ctx, &model.TokenRecord{
                JTI:       "all-iat",
                ProjectID: "p1",
                Type:      model.TokenTypeIAT,
                IssuedAt:  time.Now().UTC(),
            }))
            require.NoError(t, dao.Insert(ctx, &model.TokenRecord{
                JTI:       "all-stream",
                ProjectID: "p2",
                Type:      model.TokenTypeStream,
                StreamID:  "stream-hex-1",
                IssuedAt:  time.Now().UTC(),
            }))

            all, err := dao.FindAll(ctx)
            require.NoError(t, err)
            require.Len(t, all, 2)

            byJTI := map[string]*model.TokenRecord{}
            for _, r := range all {
                byJTI[r.JTI] = r
            }
            require.Contains(t, byJTI, "all-iat")
            require.Contains(t, byJTI, "all-stream")
            require.Equal(t, "stream-hex-1", byJTI["all-stream"].StreamID)
        })
    }
}
