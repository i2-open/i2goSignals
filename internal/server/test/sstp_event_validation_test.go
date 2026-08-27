package test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/i2-open/i2goSignals/pkg/dao/ids"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/goSetPush"
	"github.com/i2-open/i2goSignals/pkg/goSetSstp"
	"github.com/i2-open/i2goSignals/pkg/goSetValidate"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// TestSstpAcceptorEventValidationModeMatrix is the thin per-path integration
// pass over the #247 mode matrix on the SSTP acceptor: exactly the wire
// outcomes, with the combinatorial claim coverage left in pkg/goSetValidate and
// the policy coverage in internal/server's unit seam.
//
// It is the SSTP counterpart of TestPushEventValidationModeMatrix, and the ACs
// it exists to pin are the two that only a real request can show: an ENFORCE
// rejection is a per-JTI setErr (the rest of the message still lands) and the
// rejected SET is never persisted.
func TestSstpAcceptorEventValidationModeMatrix(t *testing.T) {
	instance, err := createServer(t, "sstp-event-validation", true)
	require.NoError(t, err)
	defer func() {
		if instance.ts != nil {
			instance.ts.Close()
		}
		instance.app.Shutdown()
	}()

	cases := []struct {
		name       string
		mode       model.EventValidationMode
		payload    func(*goSet.SecurityEventToken)
		wantReject bool
	}{
		{"NONE forwards a malformed payload", model.EventValidationNone, sstpEvMalformedPayload, false},
		{"WARN is wire-invisible", model.EventValidationWarn, sstpEvMalformedPayload, false},
		{"ENFORCE rejects a malformed payload", model.EventValidationEnforce, sstpEvMalformedPayload, true},
		{"ENFORCE forwards an out-of-contract URI", model.EventValidationEnforce, sstpEvUnsupportedPayload, false},
		{"STRICT rejects an out-of-contract URI", model.EventValidationStrict, sstpEvUnsupportedPayload, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pair := newSstpEventValidationPair(t, instance, tc.mode)

			badJti, badSet := sstpEvSignedSet(t, instance, tc.payload)
			// A second, unimpeachable SET in the SAME message: a rejection must
			// be scoped to its own JTI.
			goodJti, goodSet := sstpEvSignedSet(t, instance, sstpEvValidPayload)

			resp := pair.postSets(t, instance, map[string]string{badJti: badSet, goodJti: goodSet})
			require.Equal(t, http.StatusOK, resp.StatusCode)
			var msg goSetSstp.Message
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			require.NoError(t, json.Unmarshal(raw, &msg))

			assert.NotContains(t, msg.SetErrs, goodJti,
				"a valid SET in the same message must be unaffected")

			if !tc.wantReject {
				assert.NotContains(t, msg.SetErrs, badJti, "mode %s must be wire-invisible", tc.mode)
				return
			}
			require.Contains(t, msg.SetErrs, badJti,
				"mode %s must reject with a per-JTI setErr", tc.mode)
			assert.Equal(t, goSetPush.ErrInvalidRequest, msg.SetErrs[badJti].Err,
				"a validation rejection is invalid_request (RFC8935 §2.4 registry, shared by RFC8936 §7.1.2)")
			assert.NotEmpty(t, msg.SetErrs[badJti].Description)
			assert.Nil(t, instance.GetEvent(badJti),
				"a rejected SET must never be persisted")
		})
	}
}

// newSstpEventValidationPair provisions an enabled SSTP pair carrying mode on
// its (single, bidirectional) record. The inbound issuer is the local DEFAULT
// key so its JWKS resolves internally and the SETs below verify.
//
// The mode is written straight onto the StreamStateRecord because
// event_validation is a goSignals operator knob and is deliberately absent from
// the SSF wire-format StreamConfiguration.
func newSstpEventValidationPair(t *testing.T, instance *ssfInstance, mode model.EventValidationMode) *sstpTestPair {
	t.Helper()
	txSid := ids.NewObjectID()
	rxSid := ids.NewObjectID()
	pairId := ids.NewObjectID()

	rec := &model.StreamStateRecord{
		StreamConfiguration: model.StreamConfiguration{
			Id:  txSid,
			Iss: "peer.example.com",
			Aud: []string{"DEFAULT"},
		},
		SstpInbound: &model.StreamConfiguration{
			Id:  rxSid,
			Iss: "DEFAULT",
			Aud: []string{"peer.example.com"},
		},
		SstpMethod:      &model.SstpMethod{Role: "responder"},
		PairId:          pairId,
		ProjectId:       instance.projectId,
		Status:          model.StreamStateEnabled,
		InboundStatus:   model.StreamStateEnabled,
		EventValidation: mode,
	}
	require.NoError(t, instance.streamSvc().PersistStreamStateRecord(context.Background(), rec))

	state, err := instance.GetStreamState(rxSid)
	if err == nil && state != nil {
		require.Equal(t, mode, state.EventValidation,
			"the mode must bind to the pair's inbound leg (ADR COM-0018)")
	}

	bearer, err := instance.GetAuthIssuer().IssueSstpPairToken(txSid, rxSid, instance.projectId, false, nil)
	require.NoError(t, err)
	return &sstpTestPair{pairId: pairId, txSid: txSid, rxSid: rxSid, bearer: bearer}
}

// sstpEvSignedSet signs one inbound SET with the local DEFAULT key (the pair's
// inbound issuer) and returns its JTI + compact JWS.
func sstpEvSignedSet(t *testing.T, instance *ssfInstance, addPayload func(*goSet.SecurityEventToken)) (string, string) {
	t.Helper()
	set := goSet.CreateSet(nil, "DEFAULT", []string{"peer.example.com"})
	set.SubjectId = &goSet.SubjectIdentifier{
		Format:           "opaque",
		OpaqueIdentifier: goSet.OpaqueIdentifier{Id: fmt.Sprintf("sstp-ev-%s", set.ID)},
	}
	addPayload(&set)
	key, err := instance.GetPrivateKey("DEFAULT")
	require.NoError(t, err)
	signed, err := set.JWS(jwt.SigningMethodRS256, key)
	require.NoError(t, err)
	return set.ID, signed
}

// The three SET shapes this matrix needs. The engaged validators are the two SSF
// stream-management ones NewValidatorSet always engages, so the pair needs no
// negotiated event list for the malformed row to bite.
func sstpEvValidPayload(s *goSet.SecurityEventToken) {
	s.AddEventPayload(goSetValidate.SsfVerificationEventUri, map[string]any{"state": "sstp-ev-state"})
}

func sstpEvMalformedPayload(s *goSet.SecurityEventToken) {
	// "status" is REQUIRED and must be one of the SSF §8.1.2 values.
	s.AddEventPayload(goSetValidate.SsfStreamUpdatedEventUri, map[string]any{"status": "not-a-status"})
}

func sstpEvUnsupportedPayload(s *goSet.SecurityEventToken) {
	// An out-of-tree vendor URI: neither in the pair's contract nor covered by
	// any built-in validator pack.
	s.AddEventPayload("https://vendor.example.com/secevent/event-type/no-validator",
		map[string]any{"reason": "sstp event-validation matrix"})
}
