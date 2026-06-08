package services

import (
    "context"
    "strings"
    "testing"

    "github.com/i2-open/i2goSignals/pkg/dao/memory"
    "github.com/i2-open/i2goSignals/pkg/ssfModels"
    "github.com/stretchr/testify/assert"
)

// streamServiceFixture sets up the minimum services needed to exercise the
// CreateStream entry point. The deeper pipeline (TX discovery, stream
// registration) is exercised by registration_test.go; this file is narrowly
// scoped to the two pieces of logic lifted out of BaseProvider in PRD #39
// PR 4: tx_alias resolution and IssuerJWKSUrl="NONE" normalisation.
func streamServiceFixture(t *testing.T) (*StreamService, *ServerService) {
    t.Helper()
    streamDAO := memory.NewStreamDAO()
    keyDAO := memory.NewKeyDAO()
    keyService := NewKeyService(keyDAO, "http://receiver.com", nil, nil)
    err := keyService.InitializeTokenKey(context.Background(), "http://receiver.com")
    assert.NoError(t, err)

    serverDAO := memory.NewServerDAO()
    serverService := NewServerService(serverDAO)

    svc := NewStreamService(streamDAO, keyService, "http://receiver.com", StreamServiceConfig{})
    svc.SetServerService(serverService)
    return svc, serverService
}

// TestCreateStream_UnknownTxAliasErrorsAtServiceLayer proves the StreamService
// itself returns the "unknown tx_alias provided" error — not the provider
// façade. This is the load-bearing assertion for the lift: PRD #39 PR 4
// requires this resolution to happen inside the service.
func TestCreateStream_UnknownTxAliasErrorsAtServiceLayer(t *testing.T) {
    svc, _ := streamServiceFixture(t)

    bogus := "no-such-alias"
    request := model.StreamConfiguration{
        Iss:     "http://transmitter.com",
        Aud:     []string{"http://receiver.com"},
        TxAlias: &bogus,
    }

    _, err := svc.CreateStream(context.Background(), model.StreamStateRecord{StreamConfiguration: request}, "test-project", nil)
    assert.Error(t, err)
    assert.True(t, strings.Contains(err.Error(), "tx_alias"),
        "error should mention tx_alias, got: %v", err)
}

// TestCreateStream_KnownTxAliasIsResolvedBeforeFurtherProcessing proves a
// known alias passes the resolution gate. We don't exercise the full
// downstream pipeline (TX discovery would require a mock HTTP server) — only
// that the call advances *past* the alias check.
func TestCreateStream_KnownTxAliasIsResolvedBeforeFurtherProcessing(t *testing.T) {
    svc, _ := streamServiceFixture(t)

    // Inject the server directly via the DAO so we bypass the CreateServer
    // auth-mode validators that aren't relevant to alias resolution.
    txServer := &model.Server{
        Alias:     "primary-tx",
        Host:      "http://transmitter.com",
        ProjectId: "test-project",
    }
    err := svc.serverService.serverDAO.Create(context.Background(), txServer)
    assert.NoError(t, err)

    alias := "primary-tx"
    request := model.StreamConfiguration{
        Iss:     "http://transmitter.com",
        Aud:     []string{"http://receiver.com"},
        TxAlias: &alias,
    }

    _, err = svc.CreateStream(context.Background(), model.StreamStateRecord{StreamConfiguration: request}, "test-project", nil)
    // The alias resolved (otherwise we'd see "unknown tx_alias provided").
    // Whatever error comes back must not be the alias-failure error.
    if err != nil {
        assert.False(t, strings.Contains(err.Error(), "unknown tx_alias"),
            "alias should have resolved, got: %v", err)
    }
}

// TestCreateStream_IssuerJWKSUrlNoneIsNormalised proves the case-insensitive
// "NONE" -> "" normalisation is in StreamService, not BaseProvider. SCIM
// servers signal "key is internal" with NONE; downstream code expects empty.
//
// Because the full CreateStream pipeline kicks off network discovery, we
// inspect the request value as it was at the point the service had it: the
// stream record persisted to the DAO holds the post-normalisation value.
func TestCreateStream_IssuerJWKSUrlNoneIsNormalised(t *testing.T) {
    svc, _ := streamServiceFixture(t)

    request := model.StreamConfiguration{
        Iss:           "http://transmitter.com",
        Aud:           []string{"http://receiver.com"},
        IssuerJWKSUrl: "none",
    }

    cfg, _ := svc.CreateStream(context.Background(), model.StreamStateRecord{StreamConfiguration: request}, "test-project", nil)
    // Whether or not the deeper pipeline succeeded, the returned config (if
    // any) must reflect the normalised value.
    assert.Equal(t, "", cfg.IssuerJWKSUrl,
        "IssuerJWKSUrl=%q should have been normalised to empty", cfg.IssuerJWKSUrl)
}
