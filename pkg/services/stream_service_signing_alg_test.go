package services

// Per-stream signing_alg validation (i2goSignals#278, and the ES256 opt-in of
// i2goSignals#284). A stream never creates a signing key (i2goSignals#314): the
// operator creates the key for the stream's iss and signing_alg first, and a
// signing transmitter without one is refused (#308).

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/i2-open/i2goSignals/pkg/goSet/mldsa"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

func TestValidateSigningAlg_AcceptsOnlyWhatThisTransmitterCanProduce(t *testing.T) {
	for _, alg := range []string{"", "RS256", "ES256", mldsa.Alg} {
		assert.NoError(t, validateSigningAlg(alg), "signing_alg %q must be accepted", alg)
	}
	for _, alg := range []string{"HS256", "none", "ML-DSA-44", "ES384", "es256", "rs256"} {
		err := validateSigningAlg(alg)
		require.Error(t, err, "signing_alg %q must be rejected at configuration time", alg)
		assert.Contains(t, err.Error(), "invalid signing_alg")
	}
}

// keyCountForAlg counts iss's stored key records of signing algorithm alg.
func keyCountForAlg(t *testing.T, svc *StreamService, iss, alg string) int {
	t.Helper()
	storedAlg, err := storedAlgFor(alg)
	require.NoError(t, err)
	recs, err := svc.keyService.keyDAO.FindByKeyName(context.Background(), iss)
	require.NoError(t, err)
	n := 0
	for _, rec := range recs {
		if rec.Alg == storedAlg {
			n++
		}
	}
	return n
}

// TestCreateStream_SigningAlgCreatesNoKey: a transmitter asking for a
// signing_alg its issuer has no key for is refused with #308's 400, and the
// refusal leaves no key behind. Once the operator creates the key, the same
// create succeeds and still no extra key appears.
func TestCreateStream_SigningAlgCreatesNoKey(t *testing.T) {
	for _, alg := range []string{"ES256", mldsa.Alg} {
		for _, method := range []string{model.DeliveryPush, model.DeliveryPoll} {
			t.Run(alg+" "+method, func(t *testing.T) {
				svc := signingKeyFixture(t) // keyedIssuer holds an RSA key only
				ctx := context.Background()
				req := pushSigningRequest(keyedIssuer, model.RouteModePublish)
				if method == model.DeliveryPoll {
					req = pollSigningRequest(keyedIssuer, model.RouteModePublish)
				}
				req.SigningAlg = alg

				_, err := svc.CreateStream(ctx, req, "test-project", nil)
				requireNoActiveKeyError(t, err, keyedIssuer, alg)
				assert.Zero(t, keyCountForAlg(t, svc, keyedIssuer, alg), "creating a stream must not create a key")
				assert.Empty(t, svc.ListStreams(ctx))

				_, _, err = svc.keyService.CreateKeyPairForAlg(ctx, keyedIssuer, alg, "sig", "test-project")
				require.NoError(t, err)
				_, err = svc.CreateStream(ctx, req, "test-project", nil)
				require.NoError(t, err)
				assert.Equal(t, 1, keyCountForAlg(t, svc, keyedIssuer, alg), "the operator's key is the only one")
			})
		}
	}
}

func TestUpdateStream_SigningAlgCreatesNoKey(t *testing.T) {
	for _, alg := range []string{"ES256", mldsa.Alg} {
		t.Run(alg, func(t *testing.T) {
			svc := signingKeyFixture(t)
			ctx := context.Background()
			created, err := svc.CreateStream(ctx, pushSigningRequest(keyedIssuer, model.RouteModePublish), "test-project", nil)
			require.NoError(t, err)
			update := model.StreamStateRecord{StreamConfiguration: model.StreamConfiguration{SigningAlg: alg}}

			_, err = svc.UpdateStream(ctx, created.Id, "test-project", update)
			requireNoActiveKeyError(t, err, keyedIssuer, alg)
			assert.Zero(t, keyCountForAlg(t, svc, keyedIssuer, alg), "updating a stream must not create a key")

			_, _, err = svc.keyService.CreateKeyPairForAlg(ctx, keyedIssuer, alg, "sig", "test-project")
			require.NoError(t, err)
			_, err = svc.UpdateStream(ctx, created.Id, "test-project", update)
			require.NoError(t, err)
			assert.Equal(t, 1, keyCountForAlg(t, svc, keyedIssuer, alg))
		})
	}
}

// TestCreateStream_ReceiverSigningAlgCreatesNoKey: a receiver's iss names the
// remote transmitter, which signs; nothing is created for it here either.
func TestCreateStream_ReceiverSigningAlgCreatesNoKey(t *testing.T) {
	svc := signingKeyFixture(t)
	ctx := context.Background()
	_, err := svc.CreateStream(ctx, model.StreamStateRecord{StreamConfiguration: model.StreamConfiguration{
		Iss:        keylessIssuer,
		Aud:        []string{"https://rx.example"},
		SigningAlg: mldsa.Alg,
		Delivery: &model.OneOfStreamConfigurationDelivery{
			PushReceiveMethod: &model.PushReceiveMethod{Method: model.ReceivePush},
		},
	}}, "test-project", nil)
	require.NoError(t, err)
	assert.Zero(t, keyCountForAlg(t, svc, keylessIssuer, mldsa.Alg))
}

func TestCreateStream_RejectsAnUnsupportedSigningAlgBeforeTouchingTheKeyStore(t *testing.T) {
	svc := signingKeyFixture(t)
	ctx := context.Background()
	req := pushSigningRequest(keyedIssuer, model.RouteModePublish)
	req.SigningAlg = "HS256"

	_, err := svc.CreateStream(ctx, req, "test-project", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid signing_alg")
	assert.Empty(t, svc.ListStreams(ctx))
}
