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

// TestUpdateStreamStatus_SstpEnablePerDirection: between non-disabled halves,
// Enabled honors per-direction routing — re-enable one direction without
// affecting the other. (Q39, Q41)
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

// TestUpdateStreamStatus_SstpLeavingDisabledCouplesBothDirections: disabled is
// pair-level on the way OUT as well as in (#303), so enabling or pausing a
// disabled pair through either SID moves both halves, reason included — a pair
// is never left with one half disabled.
func TestUpdateStreamStatus_SstpLeavingDisabledCouplesBothDirections(t *testing.T) {
	for _, status := range []string{model.StreamStateEnabled, model.StreamStatePause} {
		for _, side := range []string{"tx", "rx"} {
			t.Run(status+" via "+side+" SID", func(t *testing.T) {
				svc, rec := createdPair(t)
				sid := rec.StreamConfiguration.Id
				if side == "rx" {
					sid = rec.SstpInbound.Id
				}
				svc.UpdateStreamStatus(context.Background(), rec.StreamConfiguration.Id, model.StreamStateDisable, "outage")
				svc.UpdateStreamStatus(context.Background(), sid, status, "recovering")

				got, err := svc.GetStreamStateByPairId(context.Background(), rec.PairId)
				require.NoError(t, err)
				assert.Equal(t, status, got.Status, "outbound half leaves disabled too")
				assert.Equal(t, "recovering", got.ErrorMsg)
				assert.Equal(t, status, got.InboundStatus, "inbound half leaves disabled too")
				assert.Equal(t, "recovering", got.InboundErrorMsg)
			})
		}
	}
}

// TestApplyStreamStatusToRecord_DisabledIsPairLevel exercises the rule on the
// record directly, including the legacy split shape (one half disabled) that
// the old per-direction exit could leave behind: any status write heals it,
// through either SID, while pause/enable between non-disabled halves stays
// per-direction.
func TestApplyStreamStatusToRecord_DisabledIsPairLevel(t *testing.T) {
	pair := func(outStatus, inStatus string) *model.StreamStateRecord {
		return &model.StreamStateRecord{
			StreamConfiguration: model.StreamConfiguration{Id: "tx-sid"},
			SstpInbound:         &model.StreamConfiguration{Id: "rx-sid"},
			SstpMethod:          &model.SstpMethod{Role: model.SstpRoleResponder},
			Status:              outStatus,
			ErrorMsg:            "was " + outStatus,
			InboundStatus:       inStatus,
			InboundErrorMsg:     "was " + inStatus,
		}
	}
	type half struct{ status, reason string }
	tests := []struct {
		name            string
		rec             *model.StreamStateRecord
		sid, status     string
		wantOut, wantIn half
	}{
		{"into disabled via tx", pair(model.StreamStateEnabled, model.StreamStatePause), "tx-sid", model.StreamStateDisable,
			half{model.StreamStateDisable, "now"}, half{model.StreamStateDisable, "now"}},
		{"into disabled via rx", pair(model.StreamStateEnabled, model.StreamStatePause), "rx-sid", model.StreamStateDisable,
			half{model.StreamStateDisable, "now"}, half{model.StreamStateDisable, "now"}},
		{"out of disabled via enabled on tx", pair(model.StreamStateDisable, model.StreamStateDisable), "tx-sid", model.StreamStateEnabled,
			half{model.StreamStateEnabled, "now"}, half{model.StreamStateEnabled, "now"}},
		{"out of disabled via enabled on rx", pair(model.StreamStateDisable, model.StreamStateDisable), "rx-sid", model.StreamStateEnabled,
			half{model.StreamStateEnabled, "now"}, half{model.StreamStateEnabled, "now"}},
		{"out of disabled via paused on tx", pair(model.StreamStateDisable, model.StreamStateDisable), "tx-sid", model.StreamStatePause,
			half{model.StreamStatePause, "now"}, half{model.StreamStatePause, "now"}},
		{"out of disabled via paused on rx", pair(model.StreamStateDisable, model.StreamStateDisable), "rx-sid", model.StreamStatePause,
			half{model.StreamStatePause, "now"}, half{model.StreamStatePause, "now"}},
		{"legacy split heals when its enabled half is named", pair(model.StreamStateEnabled, model.StreamStateDisable), "tx-sid", model.StreamStateEnabled,
			half{model.StreamStateEnabled, "now"}, half{model.StreamStateEnabled, "now"}},
		{"legacy split heals when its disabled half is named", pair(model.StreamStateDisable, model.StreamStatePause), "tx-sid", model.StreamStatePause,
			half{model.StreamStatePause, "now"}, half{model.StreamStatePause, "now"}},
		{"pause between non-disabled halves stays on rx", pair(model.StreamStateEnabled, model.StreamStateEnabled), "rx-sid", model.StreamStatePause,
			half{model.StreamStateEnabled, "was enabled"}, half{model.StreamStatePause, "now"}},
		{"enable between non-disabled halves stays on tx", pair(model.StreamStatePause, model.StreamStatePause), "tx-sid", model.StreamStateEnabled,
			half{model.StreamStateEnabled, "now"}, half{model.StreamStatePause, "was paused"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			applyStreamStatusToRecord(tt.rec, tt.sid, tt.status, "now")
			assert.Equal(t, tt.wantOut, half{tt.rec.Status, tt.rec.ErrorMsg}, "outbound half")
			assert.Equal(t, tt.wantIn, half{tt.rec.InboundStatus, tt.rec.InboundErrorMsg}, "inbound half")
		})
	}
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
