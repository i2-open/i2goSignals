package eventRouter

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/i2-open/i2goSignals/pkg/goSetSstp"
	"github.com/i2-open/i2goSignals/pkg/services"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Issue #312: an SSTP pair whose transmit direction signs and has no active
// signing key takes the key-unavailable pause at either end. The accepting end
// checks the key before an exchange applies anything; the dialing end pauses
// when it cannot sign what it would send.

const sstpNoKeyIssuer = "https://sstp-no-key.example"

func persistedPair(t *testing.T, h *sstpRunnerHarness, rec *model.StreamStateRecord) *model.StreamStateRecord {
	t.Helper()
	require.NoError(t, h.router.streamService.PersistStreamStateRecord(context.Background(), rec))
	resolved, err := h.router.streamService.GetStreamStateByPairId(context.Background(), rec.PairId)
	require.NoError(t, err)
	return resolved
}

func (h *sstpRunnerHarness) storedPair(t *testing.T, pairId string) *model.StreamStateRecord {
	t.Helper()
	rec, err := h.router.streamService.GetStreamStateByPairId(context.Background(), pairId)
	require.NoError(t, err)
	return rec
}

func TestCheckSstpSigningKey_NoKeyPausesThePairAndNamesTheKey(t *testing.T) {
	h := newSstpRunnerHarness(t)
	rec := sstpServerPairState("sstp-tx-nokey", "sstp-rx-nokey", "pair-nokey")
	rec.StreamConfiguration.RouteMode = model.RouteModePublish
	rec.StreamConfiguration.Iss = sstpNoKeyIssuer
	resolved := persistedPair(t, h, rec)

	err := h.router.CheckSstpSigningKey(resolved)

	require.Error(t, err)
	assert.Equal(t, services.NoActiveSigningKeyReason(sstpNoKeyIssuer, ""), err.Error())
	stored := h.storedPair(t, "pair-nokey")
	assert.Equal(t, model.StreamStatePause, stored.Status)
	assert.Equal(t, model.StreamStatePause, stored.InboundStatus, "pausing a pair stops both directions")
	assert.Equal(t, "SSTP-SRV: "+services.NoActiveSigningKeyReason(sstpNoKeyIssuer, ""), stored.ErrorMsg)
	assert.NotNil(t, stored.KeyUnavailableSince, "the pair carries the key-unavailable marker")

	// The pair is paused now, so the next exchange is not checked again.
	assert.NoError(t, h.router.CheckSstpSigningKey(stored))
}

func TestCheckSstpSigningKey_ForwardOrKeyedPairPasses(t *testing.T) {
	h := newSstpRunnerHarness(t)
	forward := sstpServerPairState("sstp-tx-fw", "sstp-rx-fw", "pair-fw")
	forward.StreamConfiguration.Iss = sstpNoKeyIssuer // Forward re-signs nothing
	assert.NoError(t, h.router.CheckSstpSigningKey(persistedPair(t, h, forward)))
	assert.Equal(t, model.StreamStateEnabled, h.storedPair(t, "pair-fw").Status)

	keyed := sstpServerPairState("sstp-tx-keyed", "sstp-rx-keyed", "pair-keyed")
	keyed.StreamConfiguration.RouteMode = model.RouteModePublish
	keyed.StreamConfiguration.Iss = "DEFAULT" // the memory provider's pre-provisioned signing issuer
	assert.NoError(t, h.router.CheckSstpSigningKey(persistedPair(t, h, keyed)))
	assert.Equal(t, model.StreamStateEnabled, h.storedPair(t, "pair-keyed").Status)
}

// TestSstpServer_SigningFailureSendsNoSetsAndPauses: a key that stops signing
// between the check and the drain sends none of the batch rather than a message
// that silently leaves SETs out, and pauses the pair with the marker; every SET
// stays pending.
func TestSstpServer_SigningFailureSendsNoSetsAndPauses(t *testing.T) {
	h := newSstpRunnerHarness(t)
	txSid, pairId := "sstp-tx-signfail", "pair-signfail"
	rec := sstpServerPairState(txSid, "sstp-rx-signfail", pairId)
	rec.StreamConfiguration.RouteMode = model.RouteModePublish
	rec.StreamConfiguration.Iss = "DEFAULT"
	resolved := persistedPair(t, h, rec)
	for _, jti := range []string{"sstp-signfail-1", "sstp-signfail-2"} {
		h.persistOutboundEvent(t, txSid, jti)
	}

	wrong, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	h.router.signingKeys.put("DEFAULT", "", wrong, "wrong")

	resp := h.router.SstpServerHandler(context.Background(), resolved, goSetSstp.Message{}, nil)

	assert.Empty(t, resp.Sets, "no SET is sent")
	require.NotNil(t, resp.ReturnEvents)
	assert.False(t, *resp.ReturnEvents, "the pair is paused, as the response says")
	stored := h.storedPair(t, pairId)
	assert.Equal(t, model.StreamStatePause, stored.Status)
	assert.NotNil(t, stored.KeyUnavailableSince)
	pending, _ := h.router.eventService.GetEventIds(context.Background(), txSid, model.PollParameters{MaxEvents: 10, ReturnImmediately: true})
	assert.Len(t, pending, 2, "both SETs stay pending")
}

// TestPauseForSigningKey_DialingEnd: the dialing end's pause stores the reason
// and marker on the pair and on this router's copy, so the dial loop's next
// refresh sees the pause and exits; the key check then resumes it through the
// enabled path once the key is back.
func TestPauseForSigningKey_DialingEnd(t *testing.T) {
	h := newSstpRunnerHarness(t)
	rec := sstpServerPairState("sstp-tx-dial", "sstp-rx-dial", "pair-dial")
	rec.SstpMethod.Role = model.SstpRoleInitiator
	rec.StreamConfiguration.RouteMode = model.RouteModePublish
	rec.StreamConfiguration.Iss = sstpNoKeyIssuer
	resolved := persistedPair(t, h, rec)
	h.router.UpdateStreamState(resolved.DeepCopy())
	live, ok := h.router.RefreshPair("pair-dial")
	require.True(t, ok)

	h.router.PauseForSigningKey(&live, errors.New("sstp: no signing key"))

	reason := "SSTP-CLIENT: " + services.NoActiveSigningKeyReason(sstpNoKeyIssuer, "")
	stored := h.storedPair(t, "pair-dial")
	assert.Equal(t, model.StreamStatePause, stored.Status)
	assert.Equal(t, reason, stored.ErrorMsg)
	require.NotNil(t, stored.KeyUnavailableSince)
	refreshed, _ := h.router.RefreshPair("pair-dial")
	assert.Equal(t, model.StreamStatePause, refreshed.Status, "the dial loop's next refresh sees the pause")

	// Still missing past the limit: disabled with the reason, no marker.
	h.router.checkKeyUnavailablePauses(keyCheckAt(stored.KeyUnavailableSince.Add(150 * time.Second)))
	stored = h.storedPair(t, "pair-dial")
	assert.Equal(t, model.StreamStateDisable, stored.Status)
	assert.Equal(t, reason, stored.ErrorMsg)
	assert.Nil(t, stored.KeyUnavailableSince)
	refreshed, _ = h.router.RefreshPair("pair-dial")
	assert.Equal(t, model.StreamStateDisable, refreshed.Status, "the router's copy follows the disable")
}
