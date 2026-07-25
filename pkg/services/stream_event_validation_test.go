package services

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/i2-open/i2goSignals/pkg/dao/memory"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mustJSONEventValidation marshals v or fails the test.
func mustJSONEventValidation(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return b
}

// newEventValidationTestService builds a StreamService over the in-memory DAO
// with the supplied server-wide event-validation default.
func newEventValidationTestService(def model.EventValidationMode) *StreamService {
	streamDAO := memory.NewStreamDAO()
	keyDAO := memory.NewKeyDAO()
	keyService := NewKeyService(keyDAO, "http://test", nil, nil)
	return NewStreamService(streamDAO, keyService, "http://test",
		StreamServiceConfig{EventValidationDefault: def})
}

// pollReceiverRequest returns a minimal ReceivePoll (receive-side) stream
// creation request — the direction the event_validation knob applies to.
func pollReceiverRequest() model.StreamStateRecord {
	return model.StreamStateRecord{
		StreamConfiguration: model.StreamConfiguration{
			Iss: "test-issuer",
			Delivery: &model.OneOfStreamConfigurationDelivery{
				PollReceiveMethod: &model.PollReceiveMethod{
					Method:      model.ReceivePoll,
					EndpointUrl: "https://tx.example/poll",
				},
			},
		},
	}
}

// TestEventValidation_RoundTripsOnCreate verifies the knob is settable at create
// on a receive-side stream and is persisted and read back intact.
func TestEventValidation_RoundTripsOnCreate(t *testing.T) {
	svc := newEventValidationTestService(model.EventValidationUnset)
	ctx := context.Background()

	req := pollReceiverRequest()
	req.EventValidation = model.EventValidationEnforce

	created, err := svc.CreateStream(ctx, req, "test-project", nil)
	require.NoError(t, err)

	state, err := svc.GetStreamState(ctx, created.Id)
	require.NoError(t, err)
	assert.Equal(t, model.EventValidationEnforce, state.EventValidation,
		"event_validation must round-trip through CreateStream")
}

// TestEventValidation_PatchableThroughUpdate verifies the existing stream-update
// path patches the mode on a receive-side stream.
func TestEventValidation_PatchableThroughUpdate(t *testing.T) {
	svc := newEventValidationTestService(model.EventValidationUnset)
	ctx := context.Background()

	created, err := svc.CreateStream(ctx, pollReceiverRequest(), "test-project", nil)
	require.NoError(t, err)

	patch := model.StreamStateRecord{EventValidation: model.EventValidationStrict}
	_, err = svc.UpdateStream(ctx, created.Id, "test-project", patch)
	require.NoError(t, err)

	state, err := svc.GetStreamState(ctx, created.Id)
	require.NoError(t, err)
	assert.Equal(t, model.EventValidationStrict, state.EventValidation,
		"event_validation must be patchable through UpdateStream")
}

// TestEventValidation_MalformedRejectedAtCreateAndUpdate verifies a malformed
// mode is rejected on both paths with an error naming the accepted values.
func TestEventValidation_MalformedRejectedAtCreateAndUpdate(t *testing.T) {
	svc := newEventValidationTestService(model.EventValidationUnset)
	ctx := context.Background()

	bad := pollReceiverRequest()
	bad.EventValidation = model.EventValidationMode("PARANOID")
	_, err := svc.CreateStream(ctx, bad, "test-project", nil)
	require.Error(t, err, "a malformed event_validation must be rejected at create")
	for _, want := range []string{"NONE", "WARN", "ENFORCE", "STRICT"} {
		assert.Contains(t, err.Error(), want, "create error must name the accepted values")
	}

	created, err := svc.CreateStream(ctx, pollReceiverRequest(), "test-project", nil)
	require.NoError(t, err)

	_, err = svc.UpdateStream(ctx, created.Id, "test-project",
		model.StreamStateRecord{EventValidation: model.EventValidationMode("paranoid")})
	require.Error(t, err, "a malformed event_validation must be rejected at update")
	for _, want := range []string{"NONE", "WARN", "ENFORCE", "STRICT"} {
		assert.Contains(t, err.Error(), want, "update error must name the accepted values")
	}
}

// TestEventValidation_IgnoredOnTransmitOnlyStream verifies the receive-side-only
// direction rule: a mode set on a transmit-only stream is dropped (WARN-logged)
// while the stream still creates and updates successfully (story 13).
func TestEventValidation_IgnoredOnTransmitOnlyStream(t *testing.T) {
	svc := newEventValidationTestService(model.EventValidationUnset)
	ctx := context.Background()

	req := pushTransmitterRequest()
	req.EventValidation = model.EventValidationEnforce

	created, err := svc.CreateStream(ctx, req, "test-project", nil)
	require.NoError(t, err, "a transmit-only stream must still create successfully")

	state, err := svc.GetStreamState(ctx, created.Id)
	require.NoError(t, err)
	assert.Equal(t, model.EventValidationUnset, state.EventValidation,
		"event_validation must be dropped on a transmit-only stream")

	_, err = svc.UpdateStream(ctx, created.Id, "test-project",
		model.StreamStateRecord{EventValidation: model.EventValidationWarn})
	require.NoError(t, err, "a transmit-only stream must still update successfully")

	state, err = svc.GetStreamState(ctx, created.Id)
	require.NoError(t, err)
	assert.Equal(t, model.EventValidationUnset, state.EventValidation,
		"event_validation must stay dropped on a transmit-only stream after update")

	assert.Equal(t, model.EventValidationNone, svc.ResolveEventValidation(state),
		"a transmit-only stream has no inbound leg and always resolves to NONE")
}

// TestEventValidation_EmptyResolvesToServerDefault verifies the read-time
// resolution: an unset per-stream value inherits the server-wide default, and a
// set value wins over it.
func TestEventValidation_EmptyResolvesToServerDefault(t *testing.T) {
	svc := newEventValidationTestService(model.EventValidationWarn)
	ctx := context.Background()

	created, err := svc.CreateStream(ctx, pollReceiverRequest(), "test-project", nil)
	require.NoError(t, err)

	state, err := svc.GetStreamState(ctx, created.Id)
	require.NoError(t, err)
	require.Equal(t, model.EventValidationUnset, state.EventValidation,
		"no per-stream value was requested")
	assert.Equal(t, model.EventValidationWarn, svc.ResolveEventValidation(state),
		"an unset per-stream value must resolve to the server default")

	_, err = svc.UpdateStream(ctx, created.Id, "test-project",
		model.StreamStateRecord{EventValidation: model.EventValidationStrict})
	require.NoError(t, err)
	state, err = svc.GetStreamState(ctx, created.Id)
	require.NoError(t, err)
	assert.Equal(t, model.EventValidationStrict, svc.ResolveEventValidation(state),
		"a per-stream value must win over the server default")
}

// TestNewStreamService_EventValidationDefaultFallsBackToNone verifies an unset
// or unrecognized configured default resolves to NONE.
func TestNewStreamService_EventValidationDefaultFallsBackToNone(t *testing.T) {
	for _, configured := range []model.EventValidationMode{
		model.EventValidationUnset, model.EventValidationMode("bogus"),
	} {
		svc := newEventValidationTestService(configured)
		assert.Equal(t, model.EventValidationNone, svc.EventValidationDefault(),
			"configured default %q must fall back to NONE", configured)
	}

	svc := newEventValidationTestService(model.EventValidationEnforce)
	assert.Equal(t, model.EventValidationEnforce, svc.EventValidationDefault(),
		"a recognized configured default must be kept")
}

// TestEventValidation_SstpPairBindsToInboundLeg verifies that on a bidirectional
// SSTP pair record the single event_validation field governs the INBOUND leg
// (ADR COM-0018, story 12): the pair has an inbound leg so the mode is honored
// rather than dropped as wrong-direction, and the resolver reports it as the
// inbound mode.
func TestEventValidation_SstpPairBindsToInboundLeg(t *testing.T) {
	svc, _ := sstpFixture(t)
	ctx := context.Background()

	rec, err := svc.CreateSstpPair(ctx, responderBootstrap(), "proj-1", nil)
	require.NoError(t, err)
	require.NotNil(t, rec.SstpInbound, "pair record must carry an inbound leg")
	require.Equal(t, model.DeliverySstpPair, rec.GetType())

	_, err = svc.UpdateStream(ctx, rec.PairId, "proj-1",
		model.StreamStateRecord{EventValidation: model.EventValidationEnforce})
	require.NoError(t, err)

	stored, err := svc.GetStreamState(ctx, rec.PairId)
	require.NoError(t, err)
	require.NotNil(t, stored.SstpInbound)
	assert.Equal(t, model.EventValidationEnforce, stored.EventValidation,
		"event_validation must be honored on a pair record (it has an inbound leg)")
	assert.Equal(t, model.EventValidationEnforce, svc.ResolveEventValidation(stored),
		"the pair's single field governs the inbound leg")

	// The mode is off the SSF wire format on both legs of the pair.
	assert.NotContains(t, string(mustJSONEventValidation(t, stored.SstpInbound)), "event_validation",
		"the inbound leg's wire-format StreamConfiguration must not carry the knob")
	assert.NotContains(t, string(mustJSONEventValidation(t, stored.StreamConfiguration)), "event_validation",
		"the tx leg's wire-format StreamConfiguration must not carry the knob")
}

// TestEventValidation_SstpPairPatchViaInboundSid verifies the pair's single field
// is reached when the patch targets the inbound SID rather than the PairId.
func TestEventValidation_SstpPairPatchViaInboundSid(t *testing.T) {
	svc, _ := sstpFixture(t)
	ctx := context.Background()

	rec, err := svc.CreateSstpPair(ctx, responderBootstrap(), "proj-1", nil)
	require.NoError(t, err)
	require.NotNil(t, rec.SstpInbound)

	_, err = svc.UpdateStream(ctx, rec.SstpInbound.Id, "proj-1",
		model.StreamStateRecord{EventValidation: model.EventValidationStrict})
	require.NoError(t, err)

	stored, err := svc.GetStreamState(ctx, rec.PairId)
	require.NoError(t, err)
	assert.Equal(t, model.EventValidationStrict, stored.EventValidation,
		"patching via the inbound SID must set the pair's inbound event_validation")
}

// TestResolveEventValidationMode_NilRecord guards the pure resolver's nil case.
func TestResolveEventValidationMode_NilRecord(t *testing.T) {
	assert.Equal(t, model.EventValidationNone,
		ResolveEventValidationMode(nil, model.EventValidationStrict))
}
