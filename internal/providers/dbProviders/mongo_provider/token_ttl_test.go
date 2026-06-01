package mongo_provider

import (
    "context"
    "os"
    "path/filepath"
    "testing"
    "time"

    mongodao "github.com/i2-open/i2goSignals/internal/dao/mongo"
    model "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// Slice #131 (PRD #128): Mongo TTL auto-expiry for token records driven by
// I2SIG_TOKEN_RETENTION. The TTL index is created on the token collection's
// expiry field (`exp`) at provider startup and adjusted in place via collMod
// when the configured retention changes.

const testMongoURL = "mongodb://root:dockTest@mongo1:30001,mongo2:30002,mongo3:30003/?retryWrites=true&replicaSet=dbrs&readPreference=primary&serverSelectionTimeoutMS=5000&connectTimeoutMS=10000&authSource=admin&authMechanism=SCRAM-SHA-256"

func ttlMongoURL() string {
    if u := os.Getenv("MONGO_URL"); u != "" {
        return u
    }
    return testMongoURL
}

// openTTLProvider opens a fresh provider against the live Mongo and resets the
// database so index assertions start from a clean collection. Skips when Mongo
// is unreachable.
func openTTLProvider(t *testing.T) *MongoProvider {
    t.Helper()
    t.Setenv("I2SIG_STORE_MONGO_RESUME_FILE", filepath.Join(t.TempDir(), "mongo_token.json"))
    p, err := Open(ttlMongoURL(), "ttltest")
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

// findTokenTTLIndex returns the expireAfterSeconds for the TTL index on the
// token collection's `exp` field, or (nil, true=found?) info.
func findTokenTTLIndex(t *testing.T, p *MongoProvider) (expireAfter int32, found bool) {
    t.Helper()
    specs, err := p.tokenCol.Indexes().ListSpecifications(context.Background(), nil)
    if err != nil {
        t.Fatalf("ListSpecifications: %v", err)
    }
    for _, s := range specs {
        if s.ExpireAfterSeconds != nil && string(s.KeysDocument) != "" {
            // The TTL index must be keyed on the exp field.
            if s.Name == tokenTTLIndexName {
                return *s.ExpireAfterSeconds, true
            }
        }
    }
    return 0, false
}

func TestTokenRetentionSeconds_Default(t *testing.T) {
    t.Setenv(CEnvTokenRetention, "")
    if got := tokenRetentionSeconds(); got != CDefTokenRetentionSeconds {
        t.Errorf("tokenRetentionSeconds() = %d, want default %d", got, CDefTokenRetentionSeconds)
    }
    if CDefTokenRetentionSeconds != 30*24*60*60 {
        t.Errorf("CDefTokenRetentionSeconds = %d, want 2592000 (30 days)", CDefTokenRetentionSeconds)
    }
}

func TestTokenRetentionSeconds_Override(t *testing.T) {
    t.Setenv(CEnvTokenRetention, "120")
    if got := tokenRetentionSeconds(); got != 120 {
        t.Errorf("tokenRetentionSeconds() = %d, want 120", got)
    }
}

func TestTokenRetentionSeconds_InvalidFallsBackToDefault(t *testing.T) {
    t.Setenv(CEnvTokenRetention, "not-a-number")
    if got := tokenRetentionSeconds(); got != CDefTokenRetentionSeconds {
        t.Errorf("tokenRetentionSeconds() = %d, want default %d on invalid input", got, CDefTokenRetentionSeconds)
    }
}

// AC: A TTL index exists on the token expiry field with expireAfterSeconds
// driven by I2SIG_TOKEN_RETENTION. Asserted by reading index metadata, not by
// waiting on Mongo's reaper.
func TestTokenTTLIndex_CreatedWithConfiguredRetention(t *testing.T) {
    t.Setenv(CEnvTokenRetention, "300")
    p := openTTLProvider(t)

    got, found := findTokenTTLIndex(t, p)
    if !found {
        t.Fatalf("TTL index %q not found on token collection", tokenTTLIndexName)
    }
    if got != 300 {
        t.Errorf("TTL expireAfterSeconds = %d, want 300", got)
    }
}

// AC: Retention can be changed via collMod without re-creating the collection.
// The reconcile mechanism (invoked once per connect by ensureTokenTTLIndex) is
// exercised directly here: on a restart with a changed I2SIG_TOKEN_RETENTION it
// collMods the existing index in place.
func TestTokenTTLIndex_AdjustViaCollMod(t *testing.T) {
    t.Setenv(CEnvTokenRetention, "300")
    p := openTTLProvider(t)

    if got, found := findTokenTTLIndex(t, p); !found || got != 300 {
        t.Fatalf("precondition: expireAfterSeconds=%d found=%v, want 300/true", got, found)
    }

    // Reconcile with a different retention; must collMod the existing index.
    if err := p.reconcileTokenTTLIndex(context.Background(), 600); err != nil {
        t.Fatalf("reconcileTokenTTLIndex adjust: %v", err)
    }
    if got, found := findTokenTTLIndex(t, p); !found || got != 600 {
        t.Errorf("after collMod expireAfterSeconds=%d found=%v, want 600/true", got, found)
    }

    // Same value again must be a no-op (no error).
    if err := p.reconcileTokenTTLIndex(context.Background(), 600); err != nil {
        t.Fatalf("reconcileTokenTTLIndex no-op: %v", err)
    }
    if got, _ := findTokenTTLIndex(t, p); got != 600 {
        t.Errorf("after no-op expireAfterSeconds=%d, want 600", got)
    }
}

// ensureTokenTTLIndex reconciles at most once per process: after the first
// reconcile, a subsequent call with a different value is a no-op (the desired
// retention is fixed for the process lifetime; a change takes effect on
// restart). This avoids the per-reconnect ListSpecifications round-trip.
func TestTokenTTLIndex_EnsureOncePerProcess(t *testing.T) {
    t.Setenv(CEnvTokenRetention, "300")
    p := openTTLProvider(t)

    // Startup already ensured at 300; a further ensure with a new value must
    // NOT touch the index (guarded by tokenTTLEnsured).
    if err := p.ensureTokenTTLIndex(context.Background(), 600); err != nil {
        t.Fatalf("ensureTokenTTLIndex: %v", err)
    }
    if got, found := findTokenTTLIndex(t, p); !found || got != 300 {
        t.Errorf("expireAfterSeconds=%d found=%v, want 300/true (guard should skip)", got, found)
    }
}

// AC: Revoked-but-unexpired records remain present and report active:false.
// Because the TTL is measured from `exp` (which is in the future here), the
// reaper cannot have removed the record yet, so revocations stay auditable.
func TestTokenTTLIndex_RevokedUnexpiredStaysPresentAndInactive(t *testing.T) {
    t.Setenv(CEnvTokenRetention, "300")
    p := openTTLProvider(t)

    dao := mongodao.NewTokenDAO(p.tokenCol)
    ctx := context.Background()

    rec := &model.TokenRecord{
        JTI:       "ttl-revoked-unexpired",
        ProjectID: "proj-1",
        Type:      model.TokenTypeIAT,
        Scopes:    []string{"go.signals.register"},
        IssuedAt:  time.Now().UTC(),
        ExpiresAt: time.Now().UTC().Add(1 * time.Hour), // not yet expired
    }
    if err := dao.Insert(ctx, rec); err != nil {
        t.Fatalf("Insert: %v", err)
    }
    if err := dao.Revoke(ctx, rec.JTI); err != nil {
        t.Fatalf("Revoke: %v", err)
    }

    // Still present: FindByJTI returns the record.
    got, err := dao.FindByJTI(ctx, rec.JTI)
    if err != nil {
        t.Fatalf("FindByJTI after revoke: %v", err)
    }
    if got == nil || got.RevokedAt.IsZero() {
        t.Fatalf("revoked-but-unexpired record missing or not marked revoked: %+v", got)
    }

    // Reports active:false via introspection (same active rule the service uses).
    resp, err := p.GetTokenService().IntrospectToken(ctx, rec.JTI)
    if err != nil {
        t.Fatalf("IntrospectToken: %v", err)
    }
    if resp.Active {
        t.Errorf("revoked-but-unexpired token reported active:true, want active:false")
    }
}
