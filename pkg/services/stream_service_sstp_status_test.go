package services

import (
	"context"
	"testing"

	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestUpdateStreamStatus_SstpPairCouplesBothHalves: a pair shares one HTTP
// exchange, so every status write (enabled, paused, disabled) moves BOTH halves,
// reason included, whichever SID names the pair — the same single status a
// push/poll stream carries (#303). GET /status then reads the same status and
// reason back through either SID.
func TestUpdateStreamStatus_SstpPairCouplesBothHalves(t *testing.T) {
	transitions := []struct{ from, to string }{
		{model.StreamStateEnabled, model.StreamStatePause},
		{model.StreamStateEnabled, model.StreamStateDisable},
		{model.StreamStatePause, model.StreamStateEnabled},
		{model.StreamStatePause, model.StreamStateDisable},
		{model.StreamStateDisable, model.StreamStateEnabled},
		{model.StreamStateDisable, model.StreamStatePause},
	}
	for _, tr := range transitions {
		for _, side := range []string{"tx", "rx"} {
			t.Run(tr.from+" to "+tr.to+" via "+side+" SID", func(t *testing.T) {
				ctx := context.Background()
				svc, rec := createdPair(t)
				txSid, rxSid := rec.StreamConfiguration.Id, rec.SstpInbound.Id
				// Seed both halves at the starting status through both SIDs, so the
				// start does not depend on the rule under test.
				if tr.from != model.StreamStateEnabled {
					svc.UpdateStreamStatus(ctx, txSid, tr.from, "start")
					svc.UpdateStreamStatus(ctx, rxSid, tr.from, "start")
				}
				sid := txSid
				if side == "rx" {
					sid = rxSid
				}

				svc.UpdateStreamStatus(ctx, sid, tr.to, "operator action")

				got, err := svc.GetStreamStateByPairId(ctx, rec.PairId)
				require.NoError(t, err)
				want := model.StreamStatus{Status: tr.to, Reason: "operator action"}
				assert.Equal(t, want, model.StreamStatus{Status: got.Status, Reason: got.ErrorMsg}, "outbound half")
				assert.Equal(t, want, model.StreamStatus{Status: got.InboundStatus, Reason: got.InboundErrorMsg}, "inbound half")
				for _, readSid := range []string{txSid, rxSid} {
					status, err := svc.GetStatus(ctx, readSid)
					require.NoError(t, err)
					assert.Equal(t, want, *status, "GET /status via %s", readSid)
				}
			})
		}
	}
}

// TestUpdateStreamStatus_PairPredicateAcceptsEitherSignal drives the two
// half-formed record shapes findSstpPairBySID can admit but buildSstpRecord
// never produces — SstpMethod without an inbound leg (its FindByID branch
// checks GetType only) and an inbound leg without SstpMethod (its
// FindByInboundSID branch checks SstpInbound.Id only) — through the SID that
// resolves each. Both must couple the halves; a plain stream has only its
// primary half and must not gain an inbound status.
func TestUpdateStreamStatus_PairPredicateAcceptsEitherSignal(t *testing.T) {
	tests := []struct {
		name     string
		rec      *model.StreamStateRecord
		sid      string
		wantPair bool
	}{
		{
			name: "SstpMethod with no inbound leg, named by its tx SID",
			rec: &model.StreamStateRecord{
				StreamConfiguration: model.StreamConfiguration{Id: "method-only-tx"},
				SstpMethod:          &model.SstpMethod{Role: model.SstpRoleResponder},
				Status:              model.StreamStateEnabled,
				InboundStatus:       model.StreamStateEnabled,
			},
			sid:      "method-only-tx",
			wantPair: true,
		},
		{
			name: "inbound leg with no SstpMethod, named by its rx SID",
			rec: &model.StreamStateRecord{
				StreamConfiguration: model.StreamConfiguration{Id: "inbound-only-tx"},
				SstpInbound:         &model.StreamConfiguration{Id: "inbound-only-rx"},
				Status:              model.StreamStateEnabled,
				InboundStatus:       model.StreamStateEnabled,
			},
			sid:      "inbound-only-rx",
			wantPair: true,
		},
		{
			name: "a plain stream is never a pair",
			rec: &model.StreamStateRecord{
				StreamConfiguration: model.StreamConfiguration{Id: "plain-sid"},
				Status:              model.StreamStateEnabled,
			},
			sid:      "plain-sid",
			wantPair: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			svc, _ := sstpFixture(t)
			require.NoError(t, svc.PersistStreamStateRecord(ctx, tt.rec))

			svc.UpdateStreamStatus(ctx, tt.sid, model.StreamStatePause, "quiesced")

			got, err := svc.GetStreamState(ctx, tt.rec.StreamConfiguration.Id)
			require.NoError(t, err)
			assert.Equal(t, model.StreamStatePause, got.Status)
			assert.Equal(t, "quiesced", got.ErrorMsg)
			if tt.wantPair {
				assert.Equal(t, model.StreamStatePause, got.InboundStatus, "a pair couples the inbound half")
				assert.Equal(t, "quiesced", got.InboundErrorMsg)
				return
			}
			assert.Empty(t, got.InboundStatus, "a plain stream has one half and must not gain an inbound status")
			assert.Empty(t, got.InboundErrorMsg)
		})
	}
}

// TestStatusReads_InboundStoreFailureIsNotErrNotFound (#305): GET and POST
// /status resolve a SID through the inbound-SID lookup as well as FindByID. An
// rx SID is not a document id, so FindByID finds nothing; when the inbound
// lookup then fails with a store error, that error is returned rather than
// ErrNotFound (a 404).
func TestStatusReads_InboundStoreFailureIsNotErrNotFound(t *testing.T) {
	ctx := context.Background()
	svc, dao := lookupFailingPair(t)
	dao.failByInbound = true

	_, err := svc.GetStatus(ctx, lookupPairRxSid)
	assert.ErrorIs(t, err, errLookupStoreDown, "GetStatus")
	assert.NotErrorIs(t, err, interfaces.ErrNotFound, "GetStatus")

	_, err = svc.GetStreamStateBySID(ctx, lookupPairRxSid)
	assert.ErrorIs(t, err, errLookupStoreDown, "GetStreamStateBySID")
	assert.NotErrorIs(t, err, interfaces.ErrNotFound, "GetStreamStateBySID")
}
