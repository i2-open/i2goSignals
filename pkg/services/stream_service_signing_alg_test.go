package services

// Per-stream signing_alg validation and provisioning (i2goSignals#278).

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/dao/memory"
	"github.com/i2-open/i2goSignals/pkg/goSet/mldsa"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

func TestValidateSigningAlg_AcceptsOnlyWhatThisTransmitterCanProduce(t *testing.T) {
	for _, alg := range []string{"", "RS256", mldsa.Alg} {
		assert.NoError(t, validateSigningAlg(alg), "signing_alg %q must be accepted", alg)
	}
	for _, alg := range []string{"HS256", "none", "ML-DSA-44", "ES256", "rs256"} {
		err := validateSigningAlg(alg)
		require.Error(t, err, "signing_alg %q must be rejected at configuration time", alg)
		assert.Contains(t, err.Error(), "invalid signing_alg")
	}
}

// TestApplySigningAlg_ProvisionsTheIssuerKeyBeforeTheFirstSET is the reason the
// provisioning is at configuration time and not at first signing: a receiver
// caching the issuer's JWKS must be able to have fetched the new key already.
func TestApplySigningAlg_ProvisionsTheIssuerKeyBeforeTheFirstSET(t *testing.T) {
	ctx := context.Background()
	dao := memory.NewKeyDAO()
	keySvc := NewKeyService(dao, "DEFAULT", nil, nil)
	require.NoError(t, keySvc.InitializeTokenKey(ctx, rtIssuer))
	svc := NewStreamService(nil, keySvc, rtIssuer, StreamServiceConfig{})

	cfg := &model.StreamConfiguration{
		Id:         "stream-1",
		Iss:        rtIssuer,
		SigningAlg: mldsa.Alg,
		Delivery: &model.OneOfStreamConfigurationDelivery{
			PushTransmitMethod: &model.PushTransmitMethod{Method: model.DeliveryPush},
		},
	}
	require.NoError(t, svc.applySigningAlg(ctx, cfg, ""))

	_, _, err := keySvc.GetSigner(ctx, rtIssuer, mldsa.Alg)
	assert.NoError(t, err, "the transmitter stream's opt-in must leave a usable ML-DSA signer behind")
}

// TestApplySigningAlg_DoesNotMintForAReceiverStream: a receiver's `iss` names
// the REMOTE transmitter, so minting there would create signing material for an
// issuer this node does not speak for.
func TestApplySigningAlg_DoesNotMintForAReceiverStream(t *testing.T) {
	ctx := context.Background()
	dao := memory.NewKeyDAO()
	keySvc := NewKeyService(dao, "DEFAULT", nil, nil)
	require.NoError(t, keySvc.InitializeTokenKey(ctx, "DEFAULT"))
	svc := NewStreamService(nil, keySvc, "DEFAULT", StreamServiceConfig{})

	cfg := &model.StreamConfiguration{
		Id:         "stream-rx",
		Iss:        "https://someone-else.example.com",
		SigningAlg: mldsa.Alg,
		Delivery: &model.OneOfStreamConfigurationDelivery{
			PollReceiveMethod: &model.PollReceiveMethod{Method: model.ReceivePoll},
		},
	}
	require.NoError(t, svc.applySigningAlg(ctx, cfg, ""))

	_, _, err := keySvc.GetSigner(ctx, "https://someone-else.example.com", mldsa.Alg)
	assert.ErrorIs(t, err, interfaces.ErrKeyNotFound)
}

func TestApplySigningAlg_RejectsAnUnsupportedAlgBeforeTouchingTheKeyStore(t *testing.T) {
	ctx := context.Background()
	dao := memory.NewKeyDAO()
	keySvc := NewKeyService(dao, "DEFAULT", nil, nil)
	require.NoError(t, keySvc.InitializeTokenKey(ctx, rtIssuer))
	svc := NewStreamService(nil, keySvc, rtIssuer, StreamServiceConfig{})

	cfg := &model.StreamConfiguration{
		Id:         "stream-1",
		Iss:        rtIssuer,
		SigningAlg: "HS256",
		Delivery: &model.OneOfStreamConfigurationDelivery{
			PushTransmitMethod: &model.PushTransmitMethod{Method: model.DeliveryPush},
		},
	}
	assert.Error(t, svc.applySigningAlg(ctx, cfg, ""))
}
