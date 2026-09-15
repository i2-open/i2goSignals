package services

import (
	"context"
	"testing"
	"time"

	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Issue #312: a signing poll transmitter or SSTP pair with no active signing key
// takes a key-unavailable pause, stored with KeyUnavailableSince. Only
// UpdateKeyUnavailablePause sets the marker; every other status write clears it.

// TestUpdateKeyUnavailablePause_PollTransmitter: the pause stores paused, the
// reason and the first failure's time, a repeat failure keeps that time, and an
// ordinary UpdateStreamStatus (an operator's POST /status, or the key check's
// resume and disable) clears the marker.
func TestUpdateKeyUnavailablePause_PollTransmitter(t *testing.T) {
	h := newRetryHarness(t)
	ctx := context.Background()
	rec := newReceiverFixture(t, model.DeliveryPoll, model.RouteModePublish, "poll-transmitter")
	require.NoError(t, h.streamDAO.Create(ctx, rec))
	sid := rec.StreamConfiguration.Id
	first := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)

	h.svc.UpdateKeyUnavailablePause(ctx, sid, "POLL-SRV: no active signing key for issuer test-issuer (RS256)", first)

	stored, err := h.svc.GetStreamState(ctx, sid)
	require.NoError(t, err)
	assert.Equal(t, model.StreamStatePause, stored.Status)
	assert.Equal(t, "POLL-SRV: no active signing key for issuer test-issuer (RS256)", stored.ErrorMsg)
	require.NotNil(t, stored.KeyUnavailableSince, "the stored record carries the marker")
	assert.True(t, stored.KeyUnavailableSince.Equal(first))

	h.svc.UpdateKeyUnavailablePause(ctx, sid, "POLL-SRV: no active signing key for issuer test-issuer (RS256)", first.Add(time.Minute))
	stored, err = h.svc.GetStreamState(ctx, sid)
	require.NoError(t, err)
	assert.True(t, stored.KeyUnavailableSince.Equal(first), "a repeat failure does not move the marker")

	h.svc.UpdateStreamStatus(ctx, sid, model.StreamStatePause, "operator pause")
	stored, err = h.svc.GetStreamState(ctx, sid)
	require.NoError(t, err)
	assert.Nil(t, stored.KeyUnavailableSince, "an ordinary status write clears the marker")
}

// TestUpdateKeyUnavailablePause_SstpPair: on an SSTP pair the pause moves both
// halves and stores the marker on the pair record, whichever SID names it, and
// the receiver cache copy takes it too; an ordinary write clears it on both.
func TestUpdateKeyUnavailablePause_SstpPair(t *testing.T) {
	h := newRetryHarness(t)
	ctx := context.Background()
	id := model.NewRecordId()
	rxSid := model.NewRecordId().Hex()
	pair := &model.StreamStateRecord{
		Id:        id,
		ProjectId: "test-project",
		StreamConfiguration: model.StreamConfiguration{
			Id:        id.Hex(),
			Iss:       "test-issuer",
			RouteMode: model.RouteModePublish,
			Delivery:  &model.OneOfStreamConfigurationDelivery{},
		},
		SstpInbound: &model.StreamConfiguration{
			Id:        rxSid,
			Iss:       "peer-issuer",
			RouteMode: model.RouteModeImport,
			Delivery:  &model.OneOfStreamConfigurationDelivery{},
		},
		SstpMethod:    &model.SstpMethod{Role: model.SstpRoleInitiator},
		PairId:        id.Hex(),
		Status:        model.StreamStateEnabled,
		InboundStatus: model.StreamStateEnabled,
	}
	require.NoError(t, h.streamDAO.Create(ctx, pair))
	h.svc.LoadReceiverStreams(ctx)
	first := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)

	h.svc.UpdateKeyUnavailablePause(ctx, rxSid, "SSTP-CLIENT: no active signing key for issuer test-issuer (RS256)", first)

	stored, err := h.svc.GetStreamStateBySID(ctx, id.Hex())
	require.NoError(t, err)
	assert.Equal(t, model.StreamStatePause, stored.Status)
	assert.Equal(t, model.StreamStatePause, stored.InboundStatus, "both halves pause")
	require.NotNil(t, stored.KeyUnavailableSince)
	assert.True(t, stored.KeyUnavailableSince.Equal(first))

	h.svc.mu.Lock()
	entry, ok := h.svc.receiverStreams[rxSid]
	require.True(t, ok, "the pair is cached under its inbound SID")
	cached := entry.record.KeyUnavailableSince
	h.svc.mu.Unlock()
	assert.NotNil(t, cached, "the receiver cache copy carries the marker")

	h.svc.UpdateStreamStatus(ctx, id.Hex(), model.StreamStateEnabled, "")
	stored, err = h.svc.GetStreamStateBySID(ctx, id.Hex())
	require.NoError(t, err)
	assert.Nil(t, stored.KeyUnavailableSince, "an ordinary pair status write clears the marker")
	h.svc.mu.Lock()
	cached = h.svc.receiverStreams[rxSid].record.KeyUnavailableSince
	h.svc.mu.Unlock()
	assert.Nil(t, cached, "and on the receiver cache copy")
}
