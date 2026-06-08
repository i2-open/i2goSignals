package services

import (
	"context"
	"testing"

	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestUpdateStreamStatus_SstpPerDirectionRouting: naming the tx-side SID writes
// Status/ErrorMsg; naming the rx-side SID writes InboundStatus/InboundErrorMsg.
// (Q39, Q41)
func TestUpdateStreamStatus_SstpPerDirectionRouting(t *testing.T) {
	t.Run("tx side writes Status", func(t *testing.T) {
		svc, rec := createdPair(t)
		svc.UpdateStreamStatus(context.Background(), rec.StreamConfiguration.Id, model.StreamStatePause, "tx throttled")

		got, err := svc.GetStreamStateByPairId(context.Background(), rec.PairId)
		require.NoError(t, err)
		assert.Equal(t, model.StreamStatePause, got.Status)
		assert.Equal(t, "tx throttled", got.ErrorMsg)
		// inbound untouched
		assert.Equal(t, model.StreamStateEnabled, got.InboundStatus)
		assert.Empty(t, got.InboundErrorMsg)
	})

	t.Run("rx side writes InboundStatus", func(t *testing.T) {
		svc, rec := createdPair(t)
		svc.UpdateStreamStatus(context.Background(), rec.SstpInbound.Id, model.StreamStatePause, "rx throttled")

		got, err := svc.GetStreamStateByPairId(context.Background(), rec.PairId)
		require.NoError(t, err)
		assert.Equal(t, model.StreamStatePause, got.InboundStatus)
		assert.Equal(t, "rx throttled", got.InboundErrorMsg)
		// tx untouched
		assert.Equal(t, model.StreamStateEnabled, got.Status)
		assert.Empty(t, got.ErrorMsg)
	})
}

// TestUpdateStreamStatus_SstpPausePerDirectionLeavesOtherUnchanged: Pause on one
// direction does not touch the other. (Q39, Q41)
func TestUpdateStreamStatus_SstpPausePerDirectionLeavesOtherUnchanged(t *testing.T) {
	svc, rec := createdPair(t)
	svc.UpdateStreamStatus(context.Background(), rec.SstpInbound.Id, model.StreamStatePause, "")

	got, err := svc.GetStreamStateByPairId(context.Background(), rec.PairId)
	require.NoError(t, err)
	assert.Equal(t, model.StreamStatePause, got.InboundStatus)
	assert.Equal(t, model.StreamStateEnabled, got.Status, "tx must stay enabled")
}

// TestUpdateStreamStatus_SstpDisableCouplesBothDirections: Disabled is a
// pair-level lifecycle event — naming only the tx SID (or only the rx SID) still
// disables BOTH directions. (Q39)
func TestUpdateStreamStatus_SstpDisableCouplesBothDirections(t *testing.T) {
	t.Run("named via tx SID", func(t *testing.T) {
		svc, rec := createdPair(t)
		svc.UpdateStreamStatus(context.Background(), rec.StreamConfiguration.Id, model.StreamStateDisable, "shutting down")

		got, err := svc.GetStreamStateByPairId(context.Background(), rec.PairId)
		require.NoError(t, err)
		assert.Equal(t, model.StreamStateDisable, got.Status)
		assert.Equal(t, model.StreamStateDisable, got.InboundStatus)
	})

	t.Run("named via rx SID", func(t *testing.T) {
		svc, rec := createdPair(t)
		svc.UpdateStreamStatus(context.Background(), rec.SstpInbound.Id, model.StreamStateDisable, "shutting down")

		got, err := svc.GetStreamStateByPairId(context.Background(), rec.PairId)
		require.NoError(t, err)
		assert.Equal(t, model.StreamStateDisable, got.Status)
		assert.Equal(t, model.StreamStateDisable, got.InboundStatus)
	})
}

// TestUpdateStreamStatus_SstpEnablePerDirection: Enabled honors per-direction
// routing — re-enable one direction without affecting the other. (Q39, Q41)
func TestUpdateStreamStatus_SstpEnablePerDirection(t *testing.T) {
	svc, rec := createdPair(t)
	// Pause both, then re-enable only the tx side.
	svc.UpdateStreamStatus(context.Background(), rec.StreamConfiguration.Id, model.StreamStatePause, "")
	svc.UpdateStreamStatus(context.Background(), rec.SstpInbound.Id, model.StreamStatePause, "")

	svc.UpdateStreamStatus(context.Background(), rec.StreamConfiguration.Id, model.StreamStateEnabled, "")

	got, err := svc.GetStreamStateByPairId(context.Background(), rec.PairId)
	require.NoError(t, err)
	assert.Equal(t, model.StreamStateEnabled, got.Status)
	assert.Equal(t, model.StreamStatePause, got.InboundStatus, "rx must stay paused")
}
