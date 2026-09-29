package services

import (
	"context"
	"errors"
	"testing"

	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDurability_RoundTripsOnCreateAndUpdate(t *testing.T) {
	svc := newEventValidationTestService(model.EventValidationUnset)
	ctx := context.Background()

	req := pollReceiverRequest()
	req.Durability = model.DurabilityMode("LOCAL")
	created, err := svc.CreateStream(ctx, req, "test-project", nil)
	require.NoError(t, err)
	state, err := svc.GetStreamState(ctx, created.Id)
	require.NoError(t, err)
	assert.Equal(t, model.DurabilityLocal, state.Durability, "stored normalized")

	// An update that does not mention durability leaves it unchanged.
	_, err = svc.UpdateStream(ctx, created.Id, "test-project", model.StreamStateRecord{EventValidation: model.EventValidationStrict})
	require.NoError(t, err)
	state, err = svc.GetStreamState(ctx, created.Id)
	require.NoError(t, err)
	assert.Equal(t, model.DurabilityLocal, state.Durability)

	_, err = svc.UpdateStream(ctx, created.Id, "test-project", model.StreamStateRecord{Durability: model.DurabilityMajority})
	require.NoError(t, err)
	state, err = svc.GetStreamState(ctx, created.Id)
	require.NoError(t, err)
	assert.Equal(t, model.DurabilityMajority, state.Durability)
}

func TestDurability_InvalidValueIsInvalidRequest(t *testing.T) {
	svc := newEventValidationTestService(model.EventValidationUnset)
	ctx := context.Background()

	req := pollReceiverRequest()
	req.Durability = "eventual"
	_, err := svc.CreateStream(ctx, req, "test-project", nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidRequest))

	created, err := svc.CreateStream(ctx, pollReceiverRequest(), "test-project", nil)
	require.NoError(t, err)
	_, err = svc.UpdateStream(ctx, created.Id, "test-project", model.StreamStateRecord{Durability: "eventual"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidRequest))
}

func TestResolveDurabilityMode(t *testing.T) {
	local := &model.StreamStateRecord{Durability: model.DurabilityLocal}
	majority := &model.StreamStateRecord{Durability: model.DurabilityMajority}
	unset := &model.StreamStateRecord{}

	assert.Equal(t, model.DurabilityLocal, ResolveDurabilityMode(local, true))
	assert.Equal(t, model.DurabilityMajority, ResolveDurabilityMode(local, false), "local is ignored on a majority deployment")
	assert.Equal(t, model.DurabilityMajority, ResolveDurabilityMode(majority, true))
	assert.Equal(t, model.DurabilityMajority, ResolveDurabilityMode(unset, true), "unset means majority")
	assert.Equal(t, model.DurabilityMajority, ResolveDurabilityMode(nil, true))
}

func TestOverlayEffectiveDurability(t *testing.T) {
	svc := newEventValidationTestService(model.EventValidationUnset)
	rec := &model.StreamStateRecord{Durability: model.DurabilityLocal}
	svc.OverlayEffectiveDurability(rec)
	assert.Equal(t, model.DurabilityMajority, rec.EffectiveDurability)

	svc.SetDeploymentDurabilityLocal(true)
	svc.OverlayEffectiveDurability(rec)
	assert.Equal(t, model.DurabilityLocal, rec.EffectiveDurability)
	svc.OverlayEffectiveDurability(nil)
}
