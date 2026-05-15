package mongo_provider

import "testing"

// Slice #67: v0.11.0 STORE_MONGO env-var renames.
// Slice #69: SPIFFE_MONGO_ENABLED renamed to I2SIG_SPIFFE_MONGO_ENABLED.
// Constants must use the canonical new names; readers (here and in
// event_router.go) must use envcompat for fallback to legacy names.

func TestConstants_StoreMongoV011Names(t *testing.T) {
    cases := []struct{ got, want, label string }{
        {CEnvDbName, "I2SIG_STORE_MONGO_DBNAME", "CEnvDbName"},
        {CEnvMongoWatchEnabled, "I2SIG_STORE_MONGO_WATCH_ENABLED", "CEnvMongoWatchEnabled"},
        {CEnvSpiffeMongoEnabled, "I2SIG_SPIFFE_MONGO_ENABLED", "CEnvSpiffeMongoEnabled"},
    }
    for _, c := range cases {
        if c.got != c.want {
            t.Errorf("%s = %q, want %q", c.label, c.got, c.want)
        }
    }
}

// Slice #69 tracer: the SPIFFE-mTLS-for-Mongo gate must read through
// envcompat so the deprecated SPIFFE_MONGO_ENABLED still flips the
// switch and the new I2SIG_SPIFFE_MONGO_ENABLED wins when both are set.

func TestSpiffeMongoEnabled_OldNameStillWorks(t *testing.T) {
    t.Setenv("I2SIG_SPIFFE_MONGO_ENABLED", "")
    t.Setenv("SPIFFE_MONGO_ENABLED", "true")

    if !spiffeMongoEnabled() {
        t.Error("spiffeMongoEnabled = false, want true (deprecated SPIFFE_MONGO_ENABLED=\"true\" should still gate the feature)")
    }
}

func TestSpiffeMongoEnabled_NewNameTakesPrecedence(t *testing.T) {
    t.Setenv("I2SIG_SPIFFE_MONGO_ENABLED", "false")
    t.Setenv("SPIFFE_MONGO_ENABLED", "true")

    if spiffeMongoEnabled() {
        t.Error("spiffeMongoEnabled = true, want false (new I2SIG_SPIFFE_MONGO_ENABLED=\"false\" must win)")
    }
}

func TestSpiffeMongoEnabled_NeitherSetReturnsFalse(t *testing.T) {
    t.Setenv("I2SIG_SPIFFE_MONGO_ENABLED", "")
    t.Setenv("SPIFFE_MONGO_ENABLED", "")

    if spiffeMongoEnabled() {
        t.Error("spiffeMongoEnabled = true, want false when neither name is set")
    }
}
