package services

// ADR-0066 §D2 — "None + unverified" is not a configurable state.
//
// These tests pin the invariant that i2goSignals#235 introduced:
//   - Business-stream config validation rejects L2=None (SigningOnly=true)
//     combined with no configured trust root (IssuerJWKSUrl / Iss) — on
//     CREATE and UPDATE, across push, poll, and SSTP-business shapes.
//   - The "NONE" sentinel is normalized to empty and then rejected under
//     signing-only, on both create and update paths.
//   - LoadReceiverStreams fail-closes any persisted stream that violates
//     the invariant (disables it, records the reason on the record), so
//     an older validator that let None+unverified through cannot silently
//     surface a live unauthenticated event-injection endpoint at restart.
//
// If any of these tests fail, planning#48 has regressed on the ADR-0066 §D2
// posture and the injection hole has reopened.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/i2-open/i2goSignals/pkg/dao/memory"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// noneUnverifiedPollReceive constructs a receive-side poll-mode stream request
// that is L2=None (SigningOnly=true) with NO configured trust root. Under the
// old guard this was rejected only because the guard exists; the point of
// these tests is to prove that (a) the invariant is stated as such and (b)
// the "NONE" sentinel is also caught.
func noneUnverifiedPollReceive(iss, jwksUrl string) model.StreamStateRecord {
	return model.StreamStateRecord{StreamConfiguration: model.StreamConfiguration{
		Iss:             iss,
		IssuerJWKSUrl:   jwksUrl,
		SigningOnly:     true,
		EventsRequested: []string{"urn:ietf:params:sse:event-type:risc:account-enabled"},
		Delivery: &model.OneOfStreamConfigurationDelivery{
			PollReceiveMethod: &model.PollReceiveMethod{Method: model.ReceivePoll},
		},
	}}
}

// noneUnverifiedPushReceive is the push shape of the same scenario. The
// invariant is delivery-shape-agnostic: the L2=None posture on any receive
// method requires a trust root.
func noneUnverifiedPushReceive(iss, jwksUrl string) model.StreamStateRecord {
	return model.StreamStateRecord{StreamConfiguration: model.StreamConfiguration{
		Iss:             iss,
		IssuerJWKSUrl:   jwksUrl,
		SigningOnly:     true,
		EventsRequested: []string{"urn:ietf:params:sse:event-type:risc:account-enabled"},
		Delivery: &model.OneOfStreamConfigurationDelivery{
			PushReceiveMethod: &model.PushReceiveMethod{Method: model.ReceivePush},
		},
	}}
}

// TestADR0066_Invariant_Helper_PositivelyStated pins the shape of the
// invariant helper's decision table so a refactor cannot accidentally flip
// the polarity of the guard.
func TestADR0066_Invariant_Helper_PositivelyStated(t *testing.T) {
	cases := []struct {
		name    string
		cfg     model.StreamConfiguration
		wantErr bool
		errHint string
	}{
		{
			name:    "L2=bearer (SigningOnly=false) with no trust root — invariant satisfied by L2",
			cfg:     model.StreamConfiguration{SigningOnly: false},
			wantErr: false,
		},
		{
			name:    "L2=bearer with a trust root — allowed (belt-and-suspenders)",
			cfg:     model.StreamConfiguration{SigningOnly: false, Iss: "https://iss.example", IssuerJWKSUrl: "https://jwks.example"},
			wantErr: false,
		},
		{
			name:    "L2=None + no iss + no jwks — REJECTED (None + unverified)",
			cfg:     model.StreamConfiguration{SigningOnly: true},
			wantErr: true,
			errHint: "None + unverified",
		},
		{
			name:    "L2=None + iss only, missing jwks — REJECTED",
			cfg:     model.StreamConfiguration{SigningOnly: true, Iss: "https://iss.example"},
			wantErr: true,
			errHint: "None + unverified",
		},
		{
			name:    "L2=None + jwks only, missing iss — REJECTED",
			cfg:     model.StreamConfiguration{SigningOnly: true, IssuerJWKSUrl: "https://jwks.example"},
			wantErr: true,
			errHint: "None + unverified",
		},
		{
			name:    "L2=None + iss + jwks='NONE' (un-normalized sentinel) — REJECTED",
			cfg:     model.StreamConfiguration{SigningOnly: true, Iss: "https://iss.example", IssuerJWKSUrl: "NONE"},
			wantErr: true,
			errHint: "IssuerJWKSUrl 'NONE' is not a trust root",
		},
		{
			name:    "L2=None + full trust root — invariant satisfied by L3",
			cfg:     model.StreamConfiguration{SigningOnly: true, Iss: "https://iss.example", IssuerJWKSUrl: "https://jwks.example"},
			wantErr: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateBusinessStreamSecurity(tc.cfg)
			if tc.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.errHint)
				assert.Contains(t, err.Error(), "ADR-0066")
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestADR0066_Create_PollReceive_NoTrustRoot_Rejected — the poll-receive
// business-stream shape rejects None+unverified at create time.
func TestADR0066_Create_PollReceive_NoTrustRoot_Rejected(t *testing.T) {
	svc := newStrictTestStreamService(t)
	ctx := context.Background()

	_, err := svc.CreateStream(ctx, noneUnverifiedPollReceive("", ""), "test-project", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "None + unverified")
	assert.Contains(t, err.Error(), "ADR-0066")
}

// TestADR0066_Create_PushReceive_NoTrustRoot_Rejected — the push-receive
// business-stream shape rejects the same misconfiguration.
func TestADR0066_Create_PushReceive_NoTrustRoot_Rejected(t *testing.T) {
	svc := newStrictTestStreamService(t)
	ctx := context.Background()

	_, err := svc.CreateStream(ctx, noneUnverifiedPushReceive("", ""), "test-project", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "None + unverified")
}

// TestADR0066_Create_NoneSentinelRejected proves that the "NONE" sentinel
// (case-insensitive) is normalized THEN caught by the invariant validator.
// A signing-only stream cannot smuggle an unverified posture past validation
// by writing "NONE" for IssuerJWKSUrl.
func TestADR0066_Create_NoneSentinelRejected(t *testing.T) {
	svc := newStrictTestStreamService(t)
	ctx := context.Background()

	for _, sentinel := range []string{"NONE", "None", "none"} {
		t.Run(sentinel, func(t *testing.T) {
			_, err := svc.CreateStream(ctx, noneUnverifiedPollReceive("https://iss.example", sentinel), "test-project", nil)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "None + unverified")
		})
	}
}

// TestADR0066_Update_RejectsFlipToNoneUnverified proves the update path also
// enforces the invariant: flipping a bare receiver stream (no trust root) to
// SigningOnly=true is rejected with the ADR-0066 wording. This complements
// TestUpdateStream_SigningOnlyGuardrail which exercises the same code path
// but does not assert the ADR-0066 wording — the wording is what future
// reviewers grep for when auditing the invariant.
func TestADR0066_Update_RejectsFlipToNoneUnverified(t *testing.T) {
	svc := newStrictTestStreamService(t)
	ctx := context.Background()

	// Create a plain receiver with no trust root and SigningOnly=false —
	// invariant satisfied by L2 (bearer).
	plain := model.StreamStateRecord{StreamConfiguration: model.StreamConfiguration{
		EventsRequested: []string{"urn:ietf:params:sse:event-type:risc:account-enabled"},
		Delivery: &model.OneOfStreamConfigurationDelivery{
			PollReceiveMethod: &model.PollReceiveMethod{Method: model.ReceivePoll},
		},
	}}
	created, err := svc.CreateStream(ctx, plain, "test-project", nil)
	require.NoError(t, err)
	require.False(t, created.SigningOnly)

	// Flip SigningOnly on without adding a trust root — should be rejected.
	flip := model.StreamStateRecord{StreamConfiguration: model.StreamConfiguration{
		SigningOnly: true,
		Delivery: &model.OneOfStreamConfigurationDelivery{
			PollReceiveMethod: &model.PollReceiveMethod{Method: model.ReceivePoll},
		},
	}}
	_, err = svc.UpdateStream(ctx, created.Id, "test-project", flip)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "None + unverified")
	assert.Contains(t, err.Error(), "ADR-0066")
}

// TestADR0066_LoadReceiverStreams_FailClosedOnPersistedViolation proves the
// startup fail-closed guard: a stream persisted directly through the DAO
// (bypassing CreateStream, mimicking an older release's validator letting
// None+unverified through) is disabled when LoadReceiverStreams runs, with
// the reason recorded on the record. Operator remediation is then obvious.
func TestADR0066_LoadReceiverStreams_FailClosedOnPersistedViolation(t *testing.T) {
	svc := newStrictTestStreamService(t)
	ctx := context.Background()

	// Persist a signing-only stream with NO trust root, bypassing the
	// validator (as an older release would have allowed).
	bad := &model.StreamStateRecord{
		StreamConfiguration: model.StreamConfiguration{
			Id:              "bad-none-unverified-sid",
			Iss:             "", // no iss
			IssuerJWKSUrl:   "", // no jwks
			SigningOnly:     true,
			EventsRequested: []string{"urn:ietf:params:sse:event-type:risc:account-enabled"},
			Delivery: &model.OneOfStreamConfigurationDelivery{
				PollReceiveMethod: &model.PollReceiveMethod{Method: model.ReceivePoll},
			},
		},
		Status: model.StreamStateEnabled, // was live under the old validator
	}
	require.NoError(t, svc.streamDAO.Create(ctx, bad))

	// Simulate a restart: LoadReceiverStreams should re-validate and
	// fail-closed the offending record.
	_ = svc.LoadReceiverStreams(ctx)

	reloaded, err := svc.GetStreamState(ctx, "bad-none-unverified-sid")
	require.NoError(t, err)
	require.NotNil(t, reloaded)
	assert.Equal(t, model.StreamStateDisable, reloaded.Status,
		"a persisted None+unverified stream must be disabled at startup (ADR-0066 §D2)")
	assert.Contains(t, reloaded.ErrorMsg, "ADR-0066 §D2 invariant violation")
	assert.Contains(t, reloaded.ErrorMsg, "primary")
}

// TestADR0066_LoadReceiverStreams_PermitsValidStreams proves the fail-closed
// startup guard does NOT touch streams that satisfy the invariant.
func TestADR0066_LoadReceiverStreams_PermitsValidStreams(t *testing.T) {
	svc := newStrictTestStreamService(t)
	ctx := context.Background()
	jwks := emptyJwksServer(t)

	// A signing-only stream WITH a real trust root — invariant satisfied.
	good := &model.StreamStateRecord{
		StreamConfiguration: model.StreamConfiguration{
			Id:              "good-signing-only-sid",
			Iss:             "https://issuer.example.com",
			IssuerJWKSUrl:   jwks.URL,
			SigningOnly:     true,
			EventsRequested: []string{"urn:ietf:params:sse:event-type:risc:account-enabled"},
			Delivery: &model.OneOfStreamConfigurationDelivery{
				PollReceiveMethod: &model.PollReceiveMethod{Method: model.ReceivePoll},
			},
		},
		Status: model.StreamStateEnabled,
	}
	require.NoError(t, svc.streamDAO.Create(ctx, good))

	_ = svc.LoadReceiverStreams(ctx)

	reloaded, err := svc.GetStreamState(ctx, "good-signing-only-sid")
	require.NoError(t, err)
	require.NotNil(t, reloaded)
	assert.Equal(t, model.StreamStateEnabled, reloaded.Status,
		"a compliant stream must remain enabled after startup fail-closed scan")
	assert.Empty(t, reloaded.ErrorMsg)
}

// TestADR0066_LoadReceiverStreams_FailClosedOnSstpInboundViolation exercises
// the SSTP-business shape: an SSTP pair whose rx-side (SstpInbound) leg is
// signing-only without a trust root must also be disabled at startup. A
// partially-invariant pair cannot safely accept inbound events.
func TestADR0066_LoadReceiverStreams_FailClosedOnSstpInboundViolation(t *testing.T) {
	svc := newStrictTestStreamService(t)
	ctx := context.Background()

	pair := &model.StreamStateRecord{
		PairId: "sstp-pair-id",
		StreamConfiguration: model.StreamConfiguration{
			Id:  "sstp-pair-sid",
			Iss: "https://tx.example",
			Delivery: &model.OneOfStreamConfigurationDelivery{
				SstpTransmitMarker: &model.SstpTransmitMarker{Method: model.DeliverySstp},
			},
		},
		// SstpMethod being non-nil is what makes GetType() report
		// DeliverySstpPair, which in turn makes HasInbound() report true and
		// puts the record on the ListReceiverStreams path.
		SstpMethod: &model.SstpMethod{
			Role:        model.SstpRoleInitiator,
			EndpointUrl: "https://peer.example/sstp/pair-peer",
			PeerPairId:  "pair-peer",
		},
		// Rx-side (inbound) leg violates the invariant: signing-only with no
		// trust root. The pair MUST be disabled even though the primary leg
		// (tx side) is fine — a partially-invariant pair cannot safely accept
		// inbound events.
		SstpInbound: &model.StreamConfiguration{
			Id:            "sstp-pair-inbound-sid",
			Iss:           "",
			IssuerJWKSUrl: "",
			SigningOnly:   true,
			Delivery: &model.OneOfStreamConfigurationDelivery{
				SstpReceiveMarker: &model.SstpReceiveMarker{Method: model.ReceiveSstp},
			},
		},
		Status: model.StreamStateEnabled,
		// Both directions start live, the way a pair created through the normal
		// SSTP path does. Inbound ingest is gated on InboundStatus alone, so a
		// pair disabled on the transmit leg only keeps accepting inbound events.
		InboundStatus: model.StreamStateEnabled,
	}
	require.NoError(t, svc.streamDAO.Create(ctx, pair))

	_ = svc.LoadReceiverStreams(ctx)

	reloaded, err := svc.GetStreamState(ctx, "sstp-pair-sid")
	require.NoError(t, err)
	require.NotNil(t, reloaded)
	assert.Equal(t, model.StreamStateDisable, reloaded.Status,
		"an SSTP pair whose inbound leg violates the invariant must be disabled at startup")
	assert.Contains(t, reloaded.ErrorMsg, "sstp-inbound",
		"the disable reason must name the offending leg for operator remediation")
	assert.Equal(t, model.StreamStateDisable, reloaded.InboundStatus,
		"the inbound leg is the one that violates the invariant, and it is the only status "+
			"inbound ingest consults — leaving it enabled is what lets the pair keep accepting events")
	assert.Contains(t, reloaded.InboundErrorMsg, "sstp-inbound",
		"the inbound leg must carry the reason too, not just the transmit leg")
}

// (guard against unused imports if the memory package alias flips)
var _ = memory.NewStreamDAO
