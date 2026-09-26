package services

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// Business-stream TLS floor (#322, ADR-0066 §2 as amended by ADR 0076): a
// business stream whose endpoint this server dials must be https unless the
// stream carries tx_allow_plaintext: true. Receive-side / responder endpoints
// are never subject to the floor.

func TestTLSFloor_CreatePushTransmitterPlaintextRejected(t *testing.T) {
	svc := newSubjectFilterTestService()
	req := pushTransmitterRequest()
	req.Delivery.PushTransmitMethod.EndpointUrl = "http://rx.example/push"

	_, err := svc.CreateStream(context.Background(), req, "test-project", nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidRequest), "must wrap ErrInvalidRequest (HTTP 400): %v", err)
	assert.Contains(t, err.Error(), "tx_allow_plaintext")
}

func TestTLSFloor_CreatePushTransmitterPlaintextAcceptedWithOptOut(t *testing.T) {
	svc := newSubjectFilterTestService()
	ctx := context.Background()
	req := pushTransmitterRequest()
	req.Delivery.PushTransmitMethod.EndpointUrl = "http://rx.example/push"
	req.TxAllowPlaintext = true

	created, err := svc.CreateStream(ctx, req, "test-project", nil)
	require.NoError(t, err)
	assert.True(t, created.TxAllowPlaintext, "create response must echo the opt-out")

	state, err := svc.GetStreamState(ctx, created.Id)
	require.NoError(t, err)
	assert.True(t, state.TxAllowPlaintext, "opt-out must round-trip through the store")
}

func TestTLSFloor_CreatePollReceiverPlaintextRejectedThenAccepted(t *testing.T) {
	svc := newEventValidationTestService(model.EventValidationUnset)
	ctx := context.Background()

	req := pollReceiverRequest()
	req.Delivery.PollReceiveMethod.EndpointUrl = "http://tx.example/poll"
	_, err := svc.CreateStream(ctx, req, "test-project", nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidRequest), "%v", err)

	req.TxAllowPlaintext = true
	created, err := svc.CreateStream(ctx, req, "test-project", nil)
	require.NoError(t, err)
	assert.True(t, created.TxAllowPlaintext)
}

func TestTLSFloor_ReceiveSideEndpointsNeverRejected(t *testing.T) {
	// A push receiver (inbound) declares no endpoint this server dials; the
	// floor must not apply even though the stream has no opt-out. A receive
	// stream is issued a stream token, so the service needs its token key.
	svc := newSubjectFilterTestService()
	require.NoError(t, svc.keyService.InitializeTokenKey(context.Background(), "http://test"))
	req := model.StreamStateRecord{StreamConfiguration: model.StreamConfiguration{
		Iss: "test-issuer",
		Aud: []string{"http://test"},
		Delivery: &model.OneOfStreamConfigurationDelivery{
			PushReceiveMethod: &model.PushReceiveMethod{Method: model.ReceivePush, EndpointUrl: "http://test/events/x"},
		},
	}}
	created, err := svc.CreateStream(context.Background(), req, "test-project", nil)
	require.NoError(t, err)
	assert.False(t, created.TxAllowPlaintext)
}

func TestTLSFloor_TxAllowPlaintextOmittedFromJSONWhenFalse(t *testing.T) {
	svc := newSubjectFilterTestService()
	created, err := svc.CreateStream(context.Background(), pushTransmitterRequest(), "test-project", nil)
	require.NoError(t, err)

	raw, err := json.Marshal(created)
	require.NoError(t, err)
	assert.NotContains(t, string(raw), `"tx_allow_plaintext"`, "false must be omitted on the wire")

	optIn := created
	optIn.TxAllowPlaintext = true
	raw, err = json.Marshal(optIn)
	require.NoError(t, err)
	assert.Contains(t, string(raw), `"tx_allow_plaintext":true`)
}

func TestTLSFloor_UpdateToPlaintextEndpointRejectedWithoutOptOut(t *testing.T) {
	svc := newSubjectFilterTestService()
	ctx := context.Background()
	created, err := svc.CreateStream(ctx, pushTransmitterRequest(), "test-project", nil)
	require.NoError(t, err)

	patch := model.StreamStateRecord{StreamConfiguration: created.DeepCopy()}
	patch.Delivery.PushTransmitMethod.EndpointUrl = "http://rx.example/push"
	_, err = svc.UpdateStream(ctx, created.Id, "test-project", patch)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidRequest), "%v", err)

	// The stored stream must be untouched by the rejected update.
	state, err := svc.GetStreamState(ctx, created.Id)
	require.NoError(t, err)
	assert.Equal(t, "https://rx.example/push", state.Delivery.PushTransmitMethod.EndpointUrl)
}

func TestTLSFloor_UpdateToPlaintextEndpointAcceptedWithOptOut(t *testing.T) {
	svc := newSubjectFilterTestService()
	ctx := context.Background()
	created, err := svc.CreateStream(ctx, pushTransmitterRequest(), "test-project", nil)
	require.NoError(t, err)

	patch := model.StreamStateRecord{StreamConfiguration: created.DeepCopy()}
	patch.Delivery.PushTransmitMethod.EndpointUrl = "http://rx.example/push"
	patch.TxAllowPlaintext = true
	patch.TxTLSSkipVerify = true
	updated, err := svc.UpdateStream(ctx, created.Id, "test-project", patch)
	require.NoError(t, err)
	assert.True(t, updated.TxAllowPlaintext)
	assert.True(t, updated.TxTLSSkipVerify, "UpdateStream must carry TxTLSSkipVerify alongside TxAllowPlaintext")

	state, err := svc.GetStreamState(ctx, created.Id)
	require.NoError(t, err)
	assert.True(t, state.TxAllowPlaintext)
	assert.True(t, state.TxTLSSkipVerify)
	assert.Equal(t, "http://rx.example/push", state.Delivery.PushTransmitMethod.EndpointUrl)
}

func TestTLSFloor_PartialUpdateWithoutDeliveryPreservesOptOut(t *testing.T) {
	// A PUT that omits delivery (the usual SSF metadata patch) follows the
	// "absent means unchanged" rule: the stored opt-out survives, so the
	// stream's existing plaintext endpoint is not re-refused.
	svc := newSubjectFilterTestService()
	ctx := context.Background()
	req := pushTransmitterRequest()
	req.Delivery.PushTransmitMethod.EndpointUrl = "http://rx.example/push"
	req.TxAllowPlaintext = true
	created, err := svc.CreateStream(ctx, req, "test-project", nil)
	require.NoError(t, err)

	patch := model.StreamStateRecord{StreamConfiguration: model.StreamConfiguration{Description: "renamed"}}
	updated, err := svc.UpdateStream(ctx, created.Id, "test-project", patch)
	require.NoError(t, err)
	assert.True(t, updated.TxAllowPlaintext, "opt-out must survive a patch that omits delivery")
	assert.Equal(t, "http://rx.example/push", updated.Delivery.PushTransmitMethod.EndpointUrl)
}

func TestTLSFloor_UpdateGrantsOptOutThenEndpointInSequentialPuts(t *testing.T) {
	// The opt-out is grant-on-request on update: a PUT carrying only
	// tx_allow_plaintext (no delivery block) must not be dropped, so an
	// operator can grant the opt-out in one PUT and move the endpoint to
	// http:// in the next.
	svc := newSubjectFilterTestService()
	ctx := context.Background()
	created, err := svc.CreateStream(ctx, pushTransmitterRequest(), "test-project", nil)
	require.NoError(t, err)
	require.False(t, created.TxAllowPlaintext)

	first := model.StreamStateRecord{StreamConfiguration: model.StreamConfiguration{TxAllowPlaintext: true}}
	updated, err := svc.UpdateStream(ctx, created.Id, "test-project", first)
	require.NoError(t, err)
	assert.True(t, updated.TxAllowPlaintext, "a PUT carrying only tx_allow_plaintext must set it")

	second := model.StreamStateRecord{StreamConfiguration: created.DeepCopy()}
	second.Delivery.PushTransmitMethod.EndpointUrl = "http://rx.example/push"
	second.TxAllowPlaintext = false // omitted on the wire; must not revoke the grant
	updated, err = svc.UpdateStream(ctx, created.Id, "test-project", second)
	require.NoError(t, err, "endpoint move to http:// must succeed once the opt-out is stored")
	assert.True(t, updated.TxAllowPlaintext)

	state, err := svc.GetStreamState(ctx, created.Id)
	require.NoError(t, err)
	assert.True(t, state.TxAllowPlaintext, "GET must show the opt-out granted by the earlier PUT")
	assert.Equal(t, "http://rx.example/push", state.Delivery.PushTransmitMethod.EndpointUrl)
}

func TestTLSFloor_LegacyPlaintextStreamRemediedByOptOutOnlyPut(t *testing.T) {
	// A stream that pre-dates the floor (http:// endpoint, no opt-out) is
	// seeded straight into the store. Any update re-runs the floor, so a
	// description-only patch is refused; a PUT carrying tx_allow_plaintext
	// grants the opt-out and is the remedy.
	svc := newSubjectFilterTestService()
	ctx := context.Background()
	req := pushTransmitterRequest()
	req.Delivery.PushTransmitMethod.EndpointUrl = "http://rx.example/push"
	req.TxAllowPlaintext = true
	created, err := svc.CreateStream(ctx, req, "test-project", nil)
	require.NoError(t, err)
	legacy, err := svc.streamDAO.FindByID(ctx, created.Id)
	require.NoError(t, err)
	legacy.TxAllowPlaintext = false
	require.NoError(t, svc.streamDAO.Update(ctx, legacy))

	patch := model.StreamStateRecord{StreamConfiguration: model.StreamConfiguration{Description: "renamed"}}
	_, err = svc.UpdateStream(ctx, created.Id, "test-project", patch)
	require.Error(t, err, "a legacy plaintext stream fails the floor on any update")
	assert.True(t, errors.Is(err, ErrInvalidRequest), "%v", err)

	remedy := model.StreamStateRecord{StreamConfiguration: model.StreamConfiguration{TxAllowPlaintext: true}}
	updated, err := svc.UpdateStream(ctx, created.Id, "test-project", remedy)
	require.NoError(t, err, "a PUT carrying tx_allow_plaintext is the remedy")
	assert.True(t, updated.TxAllowPlaintext)

	updated, err = svc.UpdateStream(ctx, created.Id, "test-project", patch)
	require.NoError(t, err, "the description patch succeeds once the opt-out is stored")
	assert.Equal(t, "renamed", updated.Description)
	assert.True(t, updated.TxAllowPlaintext)
}

func TestTLSFloor_DeliveryPatchOmittingTxTLSSkipVerifyKeepsStoredValue(t *testing.T) {
	// A Delivery-carrying update that omits tx_tls_skip_verify must not
	// silently clear a stored true: the flag is grant-on-request like the
	// opt-out.
	svc := newSubjectFilterTestService()
	ctx := context.Background()
	req := pushTransmitterRequest()
	req.TxTLSSkipVerify = true
	created, err := svc.CreateStream(ctx, req, "test-project", nil)
	require.NoError(t, err)
	require.True(t, created.TxTLSSkipVerify)

	patch := model.StreamStateRecord{StreamConfiguration: created.DeepCopy()}
	patch.TxTLSSkipVerify = false // omitted on the wire
	patch.Delivery.PushTransmitMethod.EndpointUrl = "https://rx2.example/push"
	updated, err := svc.UpdateStream(ctx, created.Id, "test-project", patch)
	require.NoError(t, err)
	assert.True(t, updated.TxTLSSkipVerify, "stored tx_tls_skip_verify must survive a delivery patch that omits it")
	assert.Equal(t, "https://rx2.example/push", updated.Delivery.PushTransmitMethod.EndpointUrl)
}
