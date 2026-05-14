package mongo_provider

import "testing"

// Slice #67: v0.11.0 STORE_MONGO env-var renames.
// Constants must use the canonical new names; readers (here and in
// event_router.go) must use envcompat for fallback to legacy names.

func TestConstants_StoreMongoV011Names(t *testing.T) {
    cases := []struct{ got, want, label string }{
        {CEnvDbName, "I2SIG_STORE_MONGO_DBNAME", "CEnvDbName"},
        {CEnvMongoWatchEnabled, "I2SIG_STORE_MONGO_WATCH_ENABLED", "CEnvMongoWatchEnabled"},
    }
    for _, c := range cases {
        if c.got != c.want {
            t.Errorf("%s = %q, want %q", c.label, c.got, c.want)
        }
    }
}
