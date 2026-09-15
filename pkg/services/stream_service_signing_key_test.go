package services

import (
	"context"
	"errors"
	"net/url"
	"testing"

	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Issue #308: a signing transmitter (any transmitter not in Forward mode, an
// empty route mode counting as Publish) needs an active signing key for its iss
// and signing_alg. Create, every update, SSTP pair creation and a re-enable all
// check the stream as it would be after the change, and refuse with a 400-shaped
// ErrInvalidRequest naming the issuer and algorithm. Nothing is saved.

const (
	keyedIssuer   = "https://keyed.example"
	keylessIssuer = "https://keyless.example"
)

// signingKeyFixture is streamServiceFixture plus an RSA signing key for
// keyedIssuer.
func signingKeyFixture(t *testing.T) *StreamService {
	t.Helper()
	svc, _ := streamServiceFixture(t)
	baseUrl, err := url.Parse("https://local.example")
	require.NoError(t, err)
	svc.SetBaseUrl(baseUrl) // the SSTP responder derives its endpoint from it
	_, err = svc.keyService.CreateKeyPair(context.Background(), keyedIssuer, "sig", "test-project")
	require.NoError(t, err)
	return svc
}

func pushSigningRequest(iss, routeMode string) model.StreamStateRecord {
	return model.StreamStateRecord{StreamConfiguration: model.StreamConfiguration{
		Iss:       iss,
		Aud:       []string{"https://rx.example"},
		RouteMode: routeMode,
		Delivery: &model.OneOfStreamConfigurationDelivery{
			PushTransmitMethod: &model.PushTransmitMethod{Method: model.DeliveryPush, EndpointUrl: "https://rx.example/events"},
		},
	}}
}

func pollSigningRequest(iss, routeMode string) model.StreamStateRecord {
	return model.StreamStateRecord{StreamConfiguration: model.StreamConfiguration{
		Iss:       iss,
		Aud:       []string{"https://rx.example"},
		RouteMode: routeMode,
		Delivery: &model.OneOfStreamConfigurationDelivery{
			PollTransmitMethod: &model.PollTransmitMethod{Method: model.DeliveryPoll},
		},
	}}
}

func signingPairBootstrap(iss, mode string) model.SstpPairBootstrap {
	return model.SstpPairBootstrap{
		Role: model.SstpRoleResponder,
		Primary: model.SstpDirection{
			Iss:  iss,
			Aud:  []string{"https://peer.example"},
			Mode: mode,
		},
		Inbound: model.SstpDirection{
			Iss:  "https://peer.example",
			Aud:  []string{iss},
			Mode: model.SstpModeImport,
		},
	}
}

func requireNoActiveKeyError(t *testing.T, err error, iss, alg string) {
	t.Helper()
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidRequest), "a missing key must be a 400-shaped rejection: %v", err)
	assert.Contains(t, err.Error(), "no active signing key for issuer "+iss+" ("+alg+")")
}

func TestCreateStream_SigningTransmitterWithoutActiveKeyIsRefused(t *testing.T) {
	cases := []struct {
		name string
		req  model.StreamStateRecord
	}{
		{"push publish", pushSigningRequest(keylessIssuer, model.RouteModePublish)},
		{"push empty route mode", pushSigningRequest(keylessIssuer, "")},
		{"poll publish", pollSigningRequest(keylessIssuer, model.RouteModePublish)},
		{"poll empty route mode", pollSigningRequest(keylessIssuer, "")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := signingKeyFixture(t)
			ctx := context.Background()

			_, err := svc.CreateStream(ctx, tc.req, "test-project", nil)

			requireNoActiveKeyError(t, err, keylessIssuer, "RS256")
			assert.Empty(t, svc.ListStreams(ctx), "a refused create must save nothing")
		})
	}
}

func TestCreateStream_SuspendedOrRevokedKeyIsNotActive(t *testing.T) {
	for _, status := range []string{interfaces.KeyStatusSuspended, interfaces.KeyStatusRevoked} {
		t.Run(status, func(t *testing.T) {
			svc := signingKeyFixture(t)
			ctx := context.Background()
			_, _, err := svc.keyService.SetKeyStatus(ctx, keyedIssuer, "", status)
			require.NoError(t, err)

			for _, req := range []model.StreamStateRecord{
				pushSigningRequest(keyedIssuer, model.RouteModePublish),
				pollSigningRequest(keyedIssuer, ""),
			} {
				_, err = svc.CreateStream(ctx, req, "test-project", nil)
				requireNoActiveKeyError(t, err, keyedIssuer, "RS256")
			}
			_, err = svc.CreateSstpPair(ctx, signingPairBootstrap(keyedIssuer, model.SstpModePublish), "test-project", nil)
			requireNoActiveKeyError(t, err, keyedIssuer, "RS256")
			assert.Empty(t, svc.ListStreams(ctx))
		})
	}
}

func TestCreateStream_MessageNamesTheStreamsAlgorithm(t *testing.T) {
	svc := signingKeyFixture(t)
	ctx := context.Background()
	// The issuer's ES256 key exists but is suspended, so there is no active key
	// for the stream's algorithm.
	_, err := svc.keyService.EnsureSigningKeyForAlg(ctx, keyedIssuer, "ES256", "test-project")
	require.NoError(t, err)
	_, _, err = svc.keyService.SetKeyStatus(ctx, keyedIssuer, "", interfaces.KeyStatusSuspended)
	require.NoError(t, err)

	req := pushSigningRequest(keyedIssuer, model.RouteModePublish)
	req.SigningAlg = "ES256"
	_, err = svc.CreateStream(ctx, req, "test-project", nil)

	requireNoActiveKeyError(t, err, keyedIssuer, "ES256")
	assert.Empty(t, svc.ListStreams(ctx))
}

func TestCreateStream_ForwardAndReceiverStreamsNeedNoKey(t *testing.T) {
	svc := signingKeyFixture(t)
	ctx := context.Background()

	_, err := svc.CreateStream(ctx, pushSigningRequest(keylessIssuer, model.RouteModeForward), "test-project", nil)
	require.NoError(t, err, "a Forward push transmitter relays as is and needs no key")
	_, err = svc.CreateStream(ctx, pollSigningRequest(keylessIssuer, model.RouteModeForward), "test-project", nil)
	require.NoError(t, err, "a Forward poll transmitter relays as is and needs no key")
	_, err = svc.CreateSstpPair(ctx, signingPairBootstrap(keylessIssuer, model.SstpModeForward), "test-project", nil)
	require.NoError(t, err, "a Forward SSTP direction needs no key")

	_, err = svc.CreateStream(ctx, model.StreamStateRecord{StreamConfiguration: model.StreamConfiguration{
		Iss: keylessIssuer,
		Aud: []string{"https://rx.example"},
		Delivery: &model.OneOfStreamConfigurationDelivery{
			PushReceiveMethod: &model.PushReceiveMethod{Method: model.ReceivePush},
		},
	}}, "test-project", nil)
	require.NoError(t, err, "a receiver's iss names the remote transmitter; it signs nothing")
}

func TestCreateSstpPair_PublishDirectionWithoutActiveKeyIsRefused(t *testing.T) {
	svc := signingKeyFixture(t)
	ctx := context.Background()

	_, err := svc.CreateSstpPair(ctx, signingPairBootstrap(keylessIssuer, model.SstpModePublish), "test-project", nil)

	requireNoActiveKeyError(t, err, keylessIssuer, "RS256")
	assert.Empty(t, svc.ListStreams(ctx), "a refused pair create must save nothing")

	_, err = svc.CreateSstpPair(ctx, signingPairBootstrap(keyedIssuer, model.SstpModePublish), "test-project", nil)
	require.NoError(t, err)
}

func TestUpdateStream_LeavingASigningTransmitterWithoutActiveKeyIsRefused(t *testing.T) {
	svc := signingKeyFixture(t)
	ctx := context.Background()
	created, err := svc.CreateStream(ctx, pushSigningRequest(keyedIssuer, model.RouteModePublish), "test-project", nil)
	require.NoError(t, err)
	sid := created.Id

	_, err = svc.UpdateStream(ctx, sid, "test-project", model.StreamStateRecord{
		StreamConfiguration: model.StreamConfiguration{Iss: keylessIssuer},
	})
	requireNoActiveKeyError(t, err, keylessIssuer, "RS256")
	stored, err := svc.GetStreamState(ctx, sid)
	require.NoError(t, err)
	assert.Equal(t, keyedIssuer, stored.Iss, "a refused update must save nothing")

	// signing_alg: an ES256 key that exists but is suspended is not active, so
	// the check refuses.
	_, err = svc.keyService.EnsureSigningKeyForAlg(ctx, keyedIssuer, "ES256", "test-project")
	require.NoError(t, err)
	recs, err := svc.keyService.keyDAO.FindByKeyName(ctx, keyedIssuer)
	require.NoError(t, err)
	for _, rec := range recs {
		if rec.Alg == "ES256" {
			_, _, err = svc.keyService.SetKeyStatus(ctx, keyedIssuer, rec.Kid, interfaces.KeyStatusSuspended)
			require.NoError(t, err)
		}
	}
	_, err = svc.UpdateStream(ctx, sid, "test-project", model.StreamStateRecord{
		StreamConfiguration: model.StreamConfiguration{SigningAlg: "ES256"},
	})
	requireNoActiveKeyError(t, err, keyedIssuer, "ES256")
	stored, err = svc.GetStreamState(ctx, sid)
	require.NoError(t, err)
	assert.Empty(t, stored.SigningAlg, "a refused update must save nothing")

	_, err = svc.UpdateStream(ctx, sid, "test-project", model.StreamStateRecord{
		StreamConfiguration: model.StreamConfiguration{Description: "still RS256, key active"},
	})
	require.NoError(t, err, "the RS256 key is still active")
}

func TestUpdateStream_StreamWithMissingKeyOnlyAcceptsAFix(t *testing.T) {
	for _, method := range []string{model.DeliveryPush, model.DeliveryPoll} {
		t.Run(method, func(t *testing.T) {
			svc := signingKeyFixture(t)
			ctx := context.Background()
			req := pushSigningRequest(keyedIssuer, model.RouteModePublish)
			if method == model.DeliveryPoll {
				req = pollSigningRequest(keyedIssuer, model.RouteModePublish)
			}
			created, err := svc.CreateStream(ctx, req, "test-project", nil)
			require.NoError(t, err)
			sid := created.Id
			_, _, err = svc.keyService.SetKeyStatus(ctx, keyedIssuer, "", interfaces.KeyStatusSuspended)
			require.NoError(t, err)

			_, err = svc.UpdateStream(ctx, sid, "test-project", model.StreamStateRecord{
				StreamConfiguration: model.StreamConfiguration{Description: "unrelated edit"},
			})
			requireNoActiveKeyError(t, err, keyedIssuer, "RS256")
			stored, err := svc.GetStreamState(ctx, sid)
			require.NoError(t, err)
			assert.NotEqual(t, "unrelated edit", stored.Description, "a refused update must save nothing")

			_, err = svc.UpdateStream(ctx, sid, "test-project", model.StreamStateRecord{
				StreamConfiguration: model.StreamConfiguration{Iss: "http://receiver.com"},
			})
			require.NoError(t, err, "pointing the stream at an issuer that has a key always works")

			_, err = svc.UpdateStream(ctx, sid, "test-project", model.StreamStateRecord{
				StreamConfiguration: model.StreamConfiguration{Iss: keyedIssuer, RouteMode: model.RouteModeForward},
			})
			require.NoError(t, err, "switching to Forward always works")
			stored, err = svc.GetStreamState(ctx, sid)
			require.NoError(t, err)
			assert.Equal(t, model.RouteModeForward, stored.GetRouteMode())

			require.NoError(t, svc.DeleteStream(ctx, sid), "deleting always works")
		})
	}
}

func TestUpdateSstpPair_MissingPrimaryKeyOnlyAcceptsAFix(t *testing.T) {
	svc := signingKeyFixture(t)
	ctx := context.Background()
	rec, err := svc.CreateSstpPair(ctx, signingPairBootstrap(keyedIssuer, model.SstpModePublish), "test-project", nil)
	require.NoError(t, err)
	_, _, err = svc.keyService.SetKeyStatus(ctx, keyedIssuer, "", interfaces.KeyStatusSuspended)
	require.NoError(t, err)

	_, err = svc.UpdateStream(ctx, rec.PairId, "test-project", model.StreamStateRecord{
		StreamConfiguration: model.StreamConfiguration{Aud: []string{"https://other-peer.example"}},
	})
	requireNoActiveKeyError(t, err, keyedIssuer, "RS256")

	_, err = svc.UpdateStream(ctx, rec.PairId, "test-project", model.StreamStateRecord{
		StreamConfiguration: model.StreamConfiguration{RouteMode: model.RouteModeForward},
	})
	require.NoError(t, err, "switching the transmit direction to Forward always works")
}

func TestRequireActiveSigningKey_ReEnableCheck(t *testing.T) {
	svc := signingKeyFixture(t)
	ctx := context.Background()
	push, err := svc.CreateStream(ctx, pushSigningRequest(keyedIssuer, model.RouteModePublish), "test-project", nil)
	require.NoError(t, err)
	forward, err := svc.CreateStream(ctx, pushSigningRequest(keyedIssuer, model.RouteModeForward), "test-project", nil)
	require.NoError(t, err)
	pair, err := svc.CreateSstpPair(ctx, signingPairBootstrap(keyedIssuer, model.SstpModePublish), "test-project", nil)
	require.NoError(t, err)

	pushRec, err := svc.GetStreamState(ctx, push.Id)
	require.NoError(t, err)
	forwardRec, err := svc.GetStreamState(ctx, forward.Id)
	require.NoError(t, err)
	pairRec, err := svc.GetStreamStateBySID(ctx, pair.PairId)
	require.NoError(t, err)

	for _, rec := range []*model.StreamStateRecord{pushRec, forwardRec, pairRec} {
		require.NoError(t, svc.RequireActiveSigningKey(ctx, rec), "the key is active")
	}

	_, _, err = svc.keyService.SetKeyStatus(ctx, keyedIssuer, "", interfaces.KeyStatusSuspended)
	require.NoError(t, err)
	requireNoActiveKeyError(t, svc.RequireActiveSigningKey(ctx, pushRec), keyedIssuer, "RS256")
	requireNoActiveKeyError(t, svc.RequireActiveSigningKey(ctx, pairRec), keyedIssuer, "RS256")
	assert.NoError(t, svc.RequireActiveSigningKey(ctx, forwardRec), "a Forward transmitter needs no key")

	legacy := pushRec.DeepCopy()
	legacy.StreamConfiguration.RouteMode = ""
	requireNoActiveKeyError(t, svc.RequireActiveSigningKey(ctx, legacy), keyedIssuer, "RS256")

	_, _, err = svc.keyService.SetKeyStatus(ctx, keyedIssuer, "", interfaces.KeyStatusActive)
	require.NoError(t, err)
	assert.NoError(t, svc.RequireActiveSigningKey(ctx, pushRec), "a reactivated key passes again")
}
