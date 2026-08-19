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

// TestApplyStreamStatusToRecord_PairPredicateAcceptsEitherSignal exercises the
// routing helper directly, on the two half-formed record shapes findSstpPairBySID
// can admit but buildSstpRecord never produces: SstpMethod without an inbound
// leg (its FindByID branch checks GetType only) and an inbound leg without
// SstpMethod (its FindByInboundSID branch checks SstpInbound.Id only). Neither
// is reachable from today's construction site, which is exactly why a
// single-signal "is a pair" test survives the integration tests while silently
// mis-routing here — both single-signal spellings fail open, in opposite
// directions.
func TestApplyStreamStatusToRecord_PairPredicateAcceptsEitherSignal(t *testing.T) {
	const rxSid = "rx-sid"

	inboundLeg := func() *model.StreamConfiguration {
		return &model.StreamConfiguration{Id: rxSid}
	}

	t.Run("SstpMethod with no inbound leg still couples on Disable", func(t *testing.T) {
		rec := &model.StreamStateRecord{
			SstpMethod:    &model.SstpMethod{Role: model.SstpRoleResponder},
			Status:        model.StreamStateEnabled,
			InboundStatus: model.StreamStateEnabled,
		}
		applyStreamStatusToRecord(rec, "tx-sid", model.StreamStateDisable, "gone")

		assert.Equal(t, model.StreamStateDisable, rec.Status)
		assert.Equal(t, model.StreamStateDisable, rec.InboundStatus,
			"a disable is pair-level (Q39); gating on SstpInbound alone would drop the coupling")
		assert.Equal(t, "gone", rec.InboundErrorMsg)
	})

	t.Run("inbound leg with no SstpMethod still routes the rx SID inbound", func(t *testing.T) {
		rec := &model.StreamStateRecord{
			SstpInbound:   inboundLeg(),
			Status:        model.StreamStateEnabled,
			InboundStatus: model.StreamStateEnabled,
		}
		applyStreamStatusToRecord(rec, rxSid, model.StreamStatePause, "quiesced")

		assert.Equal(t, model.StreamStatePause, rec.InboundStatus,
			"naming the rx SID must write the inbound leg")
		assert.Equal(t, "quiesced", rec.InboundErrorMsg)
		assert.Equal(t, model.StreamStateEnabled, rec.Status,
			"gating on GetType alone would have written the TX leg instead")
		assert.Empty(t, rec.ErrorMsg)
	})

	t.Run("a plain receiver is never a pair", func(t *testing.T) {
		rec := &model.StreamStateRecord{Status: model.StreamStateEnabled}
		applyStreamStatusToRecord(rec, "sid", model.StreamStateDisable, "boom")

		assert.Equal(t, model.StreamStateDisable, rec.Status)
		assert.Empty(t, rec.InboundStatus,
			"a receiver has one direction and must not gain an inbound status")
		assert.Empty(t, rec.InboundErrorMsg)
	})
}
