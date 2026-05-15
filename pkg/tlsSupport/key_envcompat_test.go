package tlsSupport

import "testing"

// Slice #69 tracer: GetCertKeyPaths must read TLS cert/key paths through
// envcompat so the deprecated SERVER_CERT_PATH / SERVER_KEY_PATH still
// resolve (with a one-time WARN, asserted in envcompat's own tests), and
// the new I2SIG_TLS_CERT_PATH / I2SIG_TLS_KEY_PATH win when both are set.

func TestGetCertKeyPaths_OldNamesStillWork(t *testing.T) {
    t.Setenv("I2SIG_TLS_CERT_PATH", "")
    t.Setenv("I2SIG_TLS_KEY_PATH", "")
    t.Setenv("SERVER_CERT_PATH", "/old/cert.pem")
    t.Setenv("SERVER_KEY_PATH", "/old/key.pem")

    certFile, keyFile := GetCertKeyPaths()

    if certFile != "/old/cert.pem" {
        t.Errorf("certFile = %q, want %q (deprecated SERVER_CERT_PATH should still work)", certFile, "/old/cert.pem")
    }
    if keyFile != "/old/key.pem" {
        t.Errorf("keyFile = %q, want %q (deprecated SERVER_KEY_PATH should still work)", keyFile, "/old/key.pem")
    }
}

func TestGetCertKeyPaths_NewNamesTakePrecedence(t *testing.T) {
    t.Setenv("I2SIG_TLS_CERT_PATH", "/new/cert.pem")
    t.Setenv("I2SIG_TLS_KEY_PATH", "/new/key.pem")
    t.Setenv("SERVER_CERT_PATH", "/old/cert.pem")
    t.Setenv("SERVER_KEY_PATH", "/old/key.pem")

    certFile, keyFile := GetCertKeyPaths()

    if certFile != "/new/cert.pem" {
        t.Errorf("certFile = %q, want %q (new I2SIG_TLS_CERT_PATH must win)", certFile, "/new/cert.pem")
    }
    if keyFile != "/new/key.pem" {
        t.Errorf("keyFile = %q, want %q (new I2SIG_TLS_KEY_PATH must win)", keyFile, "/new/key.pem")
    }
}

// Slice #69 tracer: TLS enablement gating must read through envcompat so
// the deprecated TLS_ENABLED still flips the switch (with a one-time
// WARN) and the new I2SIG_TLS_ENABLED takes precedence when both are set.

func TestTlsEnabledFromEnv_OldNameStillWorks(t *testing.T) {
    t.Setenv("I2SIG_TLS_ENABLED", "")
    t.Setenv("TLS_ENABLED", "true")

    if !tlsEnabledFromEnv() {
        t.Error("tlsEnabledFromEnv = false, want true (deprecated TLS_ENABLED=\"true\" should still enable TLS)")
    }
}

func TestTlsEnabledFromEnv_NewNameTakesPrecedence(t *testing.T) {
    t.Setenv("I2SIG_TLS_ENABLED", "false")
    t.Setenv("TLS_ENABLED", "true")

    if tlsEnabledFromEnv() {
        t.Error("tlsEnabledFromEnv = true, want false (new I2SIG_TLS_ENABLED=\"false\" must win over deprecated TLS_ENABLED=\"true\")")
    }
}

func TestTlsEnabledFromEnv_QuotedValueIsStripped(t *testing.T) {
    // Preserves the historical stripQuotes behavior so docker-compose entries
    // like I2SIG_TLS_ENABLED='"true"' still enable TLS.
    t.Setenv("TLS_ENABLED", "")
    t.Setenv("I2SIG_TLS_ENABLED", `"true"`)

    if !tlsEnabledFromEnv() {
        t.Error("tlsEnabledFromEnv = false, want true (surrounding quotes should be stripped)")
    }
}

func TestTlsEnabledFromEnv_NeitherSetReturnsFalse(t *testing.T) {
    t.Setenv("I2SIG_TLS_ENABLED", "")
    t.Setenv("TLS_ENABLED", "")

    if tlsEnabledFromEnv() {
        t.Error("tlsEnabledFromEnv = true, want false when neither name is set")
    }
}

// Slice #69 tracer: CA-cert resolution must read through envcompat
// (I2SIG_TLS_CA_CERT wins, deprecated CA_CERT still works) and must NOT
// honor CERT_CA_PUB_KEY (alias dropped in v0.11.0).

func TestCaCertPathFromEnv_OldNameStillWorks(t *testing.T) {
    t.Setenv("I2SIG_TLS_CA_CERT", "")
    t.Setenv("CERT_CA_PUB_KEY", "")
    t.Setenv("CA_CERT", "/legacy/ca.pem")

    got := caCertPathFromEnv()
    if got != "/legacy/ca.pem" {
        t.Errorf("caCertPathFromEnv = %q, want %q (deprecated CA_CERT should still work)", got, "/legacy/ca.pem")
    }
}

func TestCaCertPathFromEnv_NewNameTakesPrecedence(t *testing.T) {
    t.Setenv("I2SIG_TLS_CA_CERT", "/new/ca.pem")
    t.Setenv("CA_CERT", "/legacy/ca.pem")
    t.Setenv("CERT_CA_PUB_KEY", "/dropped/ca.pem")

    got := caCertPathFromEnv()
    if got != "/new/ca.pem" {
        t.Errorf("caCertPathFromEnv = %q, want %q (new I2SIG_TLS_CA_CERT must win)", got, "/new/ca.pem")
    }
}

func TestCaCertPathFromEnv_CertCaPubKeyAliasIsDropped(t *testing.T) {
    // CERT_CA_PUB_KEY was previously honored as an alias for CA_CERT. With
    // the v0.11.0 rationalization it must not be read anywhere; only
    // CA_CERT (legacy) and I2SIG_TLS_CA_CERT (new) are valid.
    t.Setenv("I2SIG_TLS_CA_CERT", "")
    t.Setenv("CA_CERT", "")
    t.Setenv("CERT_CA_PUB_KEY", "/dropped/ca.pem")

    got := caCertPathFromEnv()
    if got != "" {
        t.Errorf("caCertPathFromEnv = %q, want \"\" (CERT_CA_PUB_KEY must no longer be honored)", got)
    }
}
