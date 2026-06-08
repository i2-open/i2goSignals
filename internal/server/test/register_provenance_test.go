package test

import (
    "context"
    "errors"
    "net/http"
    "testing"
    "time"

    interfaces "github.com/i2-open/i2goSignals/pkg/dao"
    "github.com/i2-open/i2goSignals/internal/dao/memory"
    "github.com/i2-open/i2goSignals/internal/services"
    "github.com/i2-open/i2goSignals/pkg/authSupport"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

// redemptionFailDAO wraps the memory TokenDAO but always fails
// RecordRedemption, to exercise the best-effort posture at /register.
type redemptionFailDAO struct {
    interfaces.TokenDAO
}

func (d redemptionFailDAO) RecordRedemption(context.Context, string, string, time.Time) error {
    return errors.New("simulated redemption write failure")
}

// TestRegisterRecordsProvenance is the demoable end-to-end of issue #130: a
// /register call redeems the IAT (count + last-redemption IP/time on the IAT's
// record) and the minted stream-client token's lineage Parent is the IAT JTI.
// Provenance is read back through introspection.
func TestRegisterRecordsProvenance(t *testing.T) {
    t.Setenv("I2SIG_BOOTSTRAP_TOKEN", "")
    instance, err := createServer(t, "register_provenance_test", true)
    require.NoError(t, err)
    defer instance.app.Shutdown()

    ctx := context.Background()
    iatEat, err := instance.GetAuthIssuer().ParseAuthToken(instance.iatToken)
    require.NoError(t, err)
    iatJTI := iatEat.ID

    status, clientToken, _ := registerClientToken(t, instance, instance.iatToken,
        []string{authSupport.ScopeStreamMgmt, authSupport.ScopeEventDelivery})
    require.Equal(t, http.StatusOK, status)

    // The IAT's record now shows one redemption with a last-redemption IP/time.
    iatIntro, err := instance.tokenSvc().IntrospectToken(ctx, iatJTI)
    require.NoError(t, err)
    assert.Equal(t, int64(1), iatIntro.RedemptionCount, "register must redeem the IAT once")
    assert.NotEmpty(t, iatIntro.LastRedemptionIP, "register must capture a last-redemption IP")
    assert.NotZero(t, iatIntro.LastRedemptionAt, "register must capture a last-redemption time")

    // The minted stream-client token's lineage parent is the IAT JTI.
    clientEat, err := instance.GetAuthIssuer().ParseAuthToken(clientToken)
    require.NoError(t, err)
    clientIntro, err := instance.tokenSvc().IntrospectToken(ctx, clientEat.ID)
    require.NoError(t, err)
    assert.Equal(t, iatJTI, clientIntro.Parent, "stream-client token parent must be the IAT JTI")
}

// TestRegisterRedemptionIsBestEffort proves a redemption write failure logs at
// WARN and never blocks registration (the TrackToken posture, ADR 0007).
func TestRegisterRedemptionIsBestEffort(t *testing.T) {
    t.Setenv("I2SIG_BOOTSTRAP_TOKEN", "")
    instance, err := createServer(t, "register_best_effort_test", true)
    require.NoError(t, err)
    defer instance.app.Shutdown()

    // Swap in a TokenService whose RecordRedemption always fails.
    failing := services.NewTokenService(redemptionFailDAO{TokenDAO: memory.NewTokenDAO()})
    instance.app.TokenService = failing

    status, _ := registerClient(t, instance, instance.iatToken,
        []string{authSupport.ScopeStreamMgmt, authSupport.ScopeEventDelivery})
    require.Equal(t, http.StatusOK, status,
        "a failed redemption write must not fail registration")
}
