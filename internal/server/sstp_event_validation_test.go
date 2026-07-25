package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/MicahParks/keyfunc/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/goSetPush"
	"github.com/i2-open/i2goSignals/pkg/goSetSstp"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// Spec #247 issue #254: event_validation enforcement on the two SSTP receive
// paths — the acceptor (internal/server/api_sstp.go) and the dialer's inbound
// half (internal/server/sstp_dialer.go). Both consume the SAME policy inputs
// (mode resolved for the pair's inbound leg, engagement from that leg's
// negotiated events_delivered), which is what makes an operator's policy
// independent of which side dialed.

const (
	sstpValidationIssuer  = "https://peer.issuer.example"
	sstpValidationAud     = "https://us.example"
	sstpRiscDisabledUri   = "https://schemas.openid.net/secevent/risc/event-type/account-disabled"
	sstpVendorEventUri    = "https://vendor.example.com/secevent/event-type/no-validator"
	sstpValidationRxSid   = "rx-sid-validation"
	sstpValidationPairId  = "pair-validation"
	sstpValidationTxSid   = "tx-sid-validation"
	sstpValidationBadJti  = "jti-malformed"
	sstpValidationGoodJti = "jti-good"
)

// signSstpEventSet signs one SET carrying the given event payload, with an
// iss_sub subject the RISC pack accepts, and returns the compact JWS plus a
// JWKS that verifies it.
func signSstpEventSet(t *testing.T, jti, eventUri string, payload map[string]any) (string, *keyfunc.JWKS) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	signed, kid := signSstpEventSetWithKey(t, priv, jti, eventUri, payload)
	given := keyfunc.NewGivenRSA(&priv.PublicKey, keyfunc.GivenKeyOptions{Algorithm: "RS256"})
	return signed, keyfunc.NewGiven(map[string]keyfunc.GivenKey{kid: given})
}

// signSstpEventSetWithKey signs against a caller-supplied key so a test can put
// several SETs in one message under one JWKS, returning the compact JWS and the
// kid it was signed with.
func signSstpEventSetWithKey(t *testing.T, priv *rsa.PrivateKey, jti, eventUri string, payload map[string]any) (string, string) {
	t.Helper()
	set := goSet.SecurityEventToken{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:       jti,
			Issuer:   sstpValidationIssuer,
			Audience: jwt.ClaimStrings{sstpValidationAud},
		},
		SubjectId: &goSet.SubjectIdentifier{
			Format:                  "iss_sub",
			IssuerSubjectIdentifier: goSet.IssuerSubjectIdentifier{Issuer: "https://idp.example.com", Sub: "user-42"},
		},
		Events: map[string]any{eventUri: payload},
	}
	set.Kid = "kid-shared"

	signed, err := set.JWS(jwt.SigningMethodRS256, priv)
	require.NoError(t, err)
	return signed, set.Kid
}

// sstpValidationPair builds an SSTP pair record whose INBOUND leg negotiated
// inboundDelivered. The transmit leg deliberately negotiates a DIFFERENT event
// set, so any test that passes only because engagement was read off the wrong
// leg fails here (ADR COM-0018: one record, two legs).
func sstpValidationPair(mode model.EventValidationMode, inboundDelivered []string) *model.StreamStateRecord {
	return &model.StreamStateRecord{
		StreamConfiguration: model.StreamConfiguration{
			Id:              sstpValidationTxSid,
			Iss:             sstpValidationAud,
			Aud:             []string{sstpValidationIssuer},
			EventsDelivered: []string{sstpVendorEventUri},
			EventsSupported: []string{sstpVendorEventUri},
		},
		SstpInbound: &model.StreamConfiguration{
			Id:              sstpValidationRxSid,
			Iss:             sstpValidationIssuer,
			Aud:             []string{sstpValidationAud},
			EventsDelivered: inboundDelivered,
			EventsSupported: inboundDelivered,
		},
		SstpMethod:      &model.SstpMethod{Role: model.SstpRoleInitiator},
		PairId:          sstpValidationPairId,
		Status:          model.StreamStateEnabled,
		InboundStatus:   model.StreamStateEnabled,
		EventValidation: mode,
	}
}

// acceptorVerify drives the acceptor's verify+policy helper exactly as
// ReceiveSstpEventHandler does: resolve the pair's inbound mode, build the
// validator set from the inbound leg, verify, then apply the mode.
func acceptorVerify(t *testing.T, rec *model.StreamStateRecord, jwks *keyfunc.JWKS, sets map[string]string) ([]string, map[string]goSetSstp.SetErr) {
	t.Helper()
	policy, validators := sstpInboundValidationPolicy(rec, rec.EventValidation, nil)
	cfg := goSetSstp.VerifyConfig{
		JWKS:              jwks,
		ExpectedIssuer:    rec.SstpInbound.Iss,
		ExpectedAudiences: rec.SstpInbound.Aud,
		RequireSignature:  true,
		Validators:        validators,
	}
	parsed, setErrs := verifySstpInboundSets(goSetSstp.Message{Sets: sets}, cfg, policy)
	jtis := make([]string, 0, len(parsed))
	for _, p := range parsed {
		jtis = append(jtis, p.Jti)
	}
	return jtis, setErrs
}

// TestSstpAcceptor_EventValidationModeMatrix is the acceptor half of the #254
// mode matrix: NONE/WARN forward everything, ENFORCE rejects a malformed
// payload, and STRICT additionally rejects an out-of-contract URI that ENFORCE
// forwards.
func TestSstpAcceptor_EventValidationModeMatrix(t *testing.T) {
	malformed, malformedJwks := signSstpEventSet(t, sstpValidationBadJti, sstpRiscDisabledUri,
		map[string]any{"reason": "   "})
	outOfContract, outOfContractJwks := signSstpEventSet(t, sstpValidationBadJti, sstpVendorEventUri,
		map[string]any{"anything": "goes"})

	cases := []struct {
		name       string
		mode       model.EventValidationMode
		token      string
		jwks       *keyfunc.JWKS
		wantReject bool
	}{
		{"NONE forwards a malformed payload", model.EventValidationNone, malformed, malformedJwks, false},
		{"unset inherits NONE", model.EventValidationUnset, malformed, malformedJwks, false},
		{"WARN is wire-invisible", model.EventValidationWarn, malformed, malformedJwks, false},
		{"ENFORCE rejects a malformed payload", model.EventValidationEnforce, malformed, malformedJwks, true},
		{"STRICT rejects a malformed payload", model.EventValidationStrict, malformed, malformedJwks, true},
		{"ENFORCE forwards an out-of-contract URI", model.EventValidationEnforce, outOfContract, outOfContractJwks, false},
		{"STRICT rejects an out-of-contract URI", model.EventValidationStrict, outOfContract, outOfContractJwks, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := sstpValidationPair(tc.mode, []string{sstpRiscDisabledUri})
			parsed, setErrs := acceptorVerify(t, rec, tc.jwks,
				map[string]string{sstpValidationBadJti: tc.token})

			if !tc.wantReject {
				assert.Empty(t, setErrs, "mode %s must not produce a per-JTI setErr", tc.mode)
				assert.Equal(t, []string{sstpValidationBadJti}, parsed, "the SET must reach the router")
				return
			}
			assert.Empty(t, parsed, "a rejected SET must never reach the event router")
			require.Contains(t, setErrs, sstpValidationBadJti)
			se := setErrs[sstpValidationBadJti]
			assert.Equal(t, goSetPush.ErrInvalidRequest, se.Err,
				"a validation rejection is invalid_request on every transport (RFC8935 §2.4 / RFC8936 §7.1.2 registry)")
			assert.NotEmpty(t, se.Description, "a rejection must always carry a diagnostic")
		})
	}
}

// TestSstpAcceptor_EnforceNamesUriAndClaimAndSparesOtherJtis pins the two
// properties a per-JTI surface exists for: the error text is actionable (it
// names the event URI and the failing claim) and a rejection is scoped to its
// own JTI — valid SETs in the same message are unaffected.
func TestSstpAcceptor_EnforceNamesUriAndClaimAndSparesOtherJtis(t *testing.T) {
	// Both SETs are signed with ONE key so a single JWKS covers the message,
	// keeping the assertion on validation rather than on trust plumbing.
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	bad, kid := signSstpEventSetWithKey(t, priv, sstpValidationBadJti, sstpRiscDisabledUri,
		map[string]any{"reason": "   "})
	good, _ := signSstpEventSetWithKey(t, priv, sstpValidationGoodJti, sstpRiscDisabledUri,
		map[string]any{"reason": "hijacking"})
	given := keyfunc.NewGivenRSA(&priv.PublicKey, keyfunc.GivenKeyOptions{Algorithm: "RS256"})
	merged := keyfunc.NewGiven(map[string]keyfunc.GivenKey{kid: given})

	rec := sstpValidationPair(model.EventValidationEnforce, []string{sstpRiscDisabledUri})
	parsed, setErrs := acceptorVerify(t, rec, merged, map[string]string{
		sstpValidationBadJti:  bad,
		sstpValidationGoodJti: good,
	})

	require.Contains(t, setErrs, sstpValidationBadJti)
	assert.NotContains(t, setErrs, sstpValidationGoodJti,
		"a valid JTI in the same message must be unaffected")
	assert.Equal(t, []string{sstpValidationGoodJti}, parsed)

	desc := setErrs[sstpValidationBadJti].Description
	assert.Contains(t, desc, sstpRiscDisabledUri, "the setErr must name the offending event URI")
	assert.Contains(t, desc, "reason", "the setErr must name the failing claim")
}

// TestSstpEventValidation_EngagementBindsToInboundLeg proves the ADR COM-0018
// binding: engagement is computed from the pair's INBOUND leg. The transmit leg
// of the fixture negotiates the vendor URI, so reading engagement off the wrong
// leg would flip both assertions below.
func TestSstpEventValidation_EngagementBindsToInboundLeg(t *testing.T) {
	// Inbound leg negotiated the RISC URI ⇒ the RISC validator is engaged ⇒
	// the bad payload is Malformed ⇒ ENFORCE rejects.
	engaged := sstpValidationPair(model.EventValidationEnforce, []string{sstpRiscDisabledUri})
	bad, jwks := signSstpEventSet(t, sstpValidationBadJti, sstpRiscDisabledUri,
		map[string]any{"reason": "   "})
	_, setErrs := acceptorVerify(t, engaged, jwks, map[string]string{sstpValidationBadJti: bad})
	require.Contains(t, setErrs, sstpValidationBadJti,
		"the RISC validator must be engaged from SstpInbound.EventsDelivered")

	// Inbound leg negotiated something else ⇒ the RISC URI is out of contract
	// ⇒ Unsupported ⇒ ENFORCE forwards it (only STRICT would reject).
	notEngaged := sstpValidationPair(model.EventValidationEnforce, []string{sstpVendorEventUri})
	parsed, setErrs2 := acceptorVerify(t, notEngaged, jwks, map[string]string{sstpValidationBadJti: bad})
	assert.Empty(t, setErrs2, "an un-engaged URI is Unsupported, which ENFORCE forwards")
	assert.Equal(t, []string{sstpValidationBadJti}, parsed)
}

// TestSstpEventValidation_NoneBuildsNoValidatorSet pins the NONE posture as the
// pre-#247 receive path rather than "validate and discard the answer": a NONE
// pair hands VerifySET a nil validator set, so no validation work happens at all.
func TestSstpEventValidation_NoneBuildsNoValidatorSet(t *testing.T) {
	for _, mode := range []model.EventValidationMode{model.EventValidationNone, model.EventValidationUnset} {
		_, validators := sstpInboundValidationPolicy(
			sstpValidationPair(mode, []string{sstpRiscDisabledUri}), mode, nil)
		assert.Nil(t, validators, "mode %q must build no validator set", mode)
	}
	policy, validators := sstpInboundValidationPolicy(
		sstpValidationPair(model.EventValidationWarn, []string{sstpRiscDisabledUri}),
		model.EventValidationWarn, nil)
	assert.NotNil(t, validators, "WARN must engage validators — it reports without rejecting")
	assert.Equal(t, sstpValidationRxSid, policy.Sid,
		"logs must be attributed to the receiving (inbound) SID")
}

// TestSstpDialer_InboundHalfEventValidationModeMatrix is the dialer half of the
// #254 mode matrix, driven through runInboundHalf — the dialer's single
// response-SET ingest point. It mirrors the acceptor matrix above claim for
// claim, which is the point: one policy, two paths.
func TestSstpDialer_InboundHalfEventValidationModeMatrix(t *testing.T) {
	malformed, malformedJwks := signSstpEventSet(t, sstpValidationBadJti, sstpRiscDisabledUri,
		map[string]any{"reason": "   "})
	outOfContract, outOfContractJwks := signSstpEventSet(t, sstpValidationBadJti, sstpVendorEventUri,
		map[string]any{"anything": "goes"})

	cases := []struct {
		name       string
		mode       model.EventValidationMode
		token      string
		jwks       *keyfunc.JWKS
		wantReject bool
	}{
		{"NONE forwards a malformed payload", model.EventValidationNone, malformed, malformedJwks, false},
		{"unset inherits NONE", model.EventValidationUnset, malformed, malformedJwks, false},
		{"WARN is wire-invisible", model.EventValidationWarn, malformed, malformedJwks, false},
		{"ENFORCE rejects a malformed payload", model.EventValidationEnforce, malformed, malformedJwks, true},
		{"ENFORCE forwards an out-of-contract URI", model.EventValidationEnforce, outOfContract, outOfContractJwks, false},
		{"STRICT rejects an out-of-contract URI", model.EventValidationStrict, outOfContract, outOfContractJwks, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := sstpValidationPair(tc.mode, []string{sstpRiscDisabledUri})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			fake := newFakeSstpOutbound(ctx, *rec)
			fake.verifyCfg = goSetSstp.VerifyConfig{
				JWKS:              tc.jwks,
				ExpectedIssuer:    sstpValidationIssuer,
				ExpectedAudiences: []string{sstpValidationAud},
				RequireSignature:  true,
			}
			d := NewSstpDialer(&oneShotCoordinator{}, "node-validation", nil, SstpDialerConfig{})
			d.Bind(fake)

			feedback := d.runInboundHalf(rec, map[string]string{sstpValidationBadJti: tc.token})

			if !tc.wantReject {
				assert.Empty(t, feedback.SetErrs, "mode %s must not report a setErr", tc.mode)
				assert.Equal(t, []string{sstpValidationBadJti}, feedback.Acks,
					"an accepted SET is ingested and acked")
				assert.Len(t, fake.ingestedCopy(), 1)
				return
			}
			assert.Empty(t, feedback.Acks, "a rejected SET must not be acked")
			assert.Empty(t, fake.ingestedCopy(), "a rejected SET must never reach the event router")
			require.Contains(t, feedback.SetErrs, sstpValidationBadJti)
			assert.Equal(t, goSetPush.ErrInvalidRequest, feedback.SetErrs[sstpValidationBadJti].Err,
				"the dialer reports the same code as the acceptor")
		})
	}
}

// TestSstpDialer_InboundHalfEnforceNamesUriAndClaim pins the dialer's rejection
// text: like the acceptor's, it must name the event URI and the failing claim so
// the peer operator can act on it without a log dive on our side.
func TestSstpDialer_InboundHalfEnforceNamesUriAndClaim(t *testing.T) {
	bad, jwks := signSstpEventSet(t, sstpValidationBadJti, sstpRiscDisabledUri,
		map[string]any{"reason": "   "})
	rec := sstpValidationPair(model.EventValidationEnforce, []string{sstpRiscDisabledUri})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fake := newFakeSstpOutbound(ctx, *rec)
	fake.verifyCfg = goSetSstp.VerifyConfig{
		JWKS:              jwks,
		ExpectedIssuer:    sstpValidationIssuer,
		ExpectedAudiences: []string{sstpValidationAud},
		RequireSignature:  true,
	}
	d := NewSstpDialer(&oneShotCoordinator{}, "node-validation", nil, SstpDialerConfig{})
	d.Bind(fake)

	feedback := d.runInboundHalf(rec, map[string]string{sstpValidationBadJti: bad})

	require.Contains(t, feedback.SetErrs, sstpValidationBadJti)
	desc := feedback.SetErrs[sstpValidationBadJti].Description
	assert.Contains(t, desc, sstpRiscDisabledUri, "the setErr must name the offending event URI")
	assert.Contains(t, desc, "reason", "the setErr must name the failing claim")
}

// TestSstpEventValidation_CounterCarriesSstpTransportLabel covers the
// observability AC end-to-end on both paths: the shared counter records the
// SSTP transport label, and it does so under WARN — where the wire response is
// unchanged and the counter is the ONLY machine-readable signal.
func TestSstpEventValidation_CounterCarriesSstpTransportLabel(t *testing.T) {
	stats := newValidationStats()
	malformed, jwks := signSstpEventSet(t, sstpValidationBadJti, sstpRiscDisabledUri,
		map[string]any{"reason": "   "})
	rec := sstpValidationPair(model.EventValidationWarn, []string{sstpRiscDisabledUri})

	// Acceptor path.
	policy, validators := sstpInboundValidationPolicy(rec, rec.EventValidation, stats)
	_, setErrs := verifySstpInboundSets(
		goSetSstp.Message{Sets: map[string]string{sstpValidationBadJti: malformed}},
		goSetSstp.VerifyConfig{
			JWKS:              jwks,
			ExpectedIssuer:    sstpValidationIssuer,
			ExpectedAudiences: []string{sstpValidationAud},
			RequireSignature:  true,
			Validators:        validators,
		}, policy)
	require.Empty(t, setErrs, "WARN must stay wire-invisible on the acceptor path")

	// Dialer inbound half, through the same counter.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fake := newFakeSstpOutbound(ctx, *rec)
	fake.verifyCfg = goSetSstp.VerifyConfig{
		JWKS:              jwks,
		ExpectedIssuer:    sstpValidationIssuer,
		ExpectedAudiences: []string{sstpValidationAud},
		RequireSignature:  true,
	}
	d := NewSstpDialer(&oneShotCoordinator{}, "node-validation", stats, SstpDialerConfig{})
	d.Bind(fake)
	feedback := d.runInboundHalf(rec, map[string]string{sstpValidationBadJti: malformed})
	require.Empty(t, feedback.SetErrs, "WARN must stay wire-invisible on the dialer path")

	assert.Equal(t, 2.0, testutil.ToFloat64(
		stats.EventValidations.WithLabelValues("malformed", "WARN", validationTransportSstp)),
		"both SSTP paths must count under one transport label")
}

// TestSstpDialer_EnforceReportsSetErrOnNextRequest is the dialer path's thin
// integration pass: a full dial cycle against a live peer, proving the ENFORCE
// rejection actually reaches the wire. The dialer is the CLIENT here, so its
// only channel for a per-JTI error is the next request's setErrs — without that
// carriage a validation rejection would look to the peer like a missing ack and
// be resent forever.
func TestSstpDialer_EnforceReportsSetErrOnNextRequest(t *testing.T) {
	malformed, jwks := signSstpEventSet(t, sstpValidationBadJti, sstpRiscDisabledUri,
		map[string]any{"reason": "   "})

	var mu sync.Mutex
	var lastSetErrs map[string]goSetSstp.SetErr
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var msg goSetSstp.Message
		require.NoError(t, json.Unmarshal(raw, &msg))
		mu.Lock()
		if len(msg.SetErrs) > 0 {
			lastSetErrs = msg.SetErrs
		}
		mu.Unlock()
		// Every response re-offers the same malformed SET, so the dialer keeps
		// exercising its inbound half until the assertion below is satisfied.
		w.Header().Set("Content-Type", goSetSstp.ContentType)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(goSetSstp.Message{
			Sets: map[string]string{sstpValidationBadJti: malformed},
		})
	}))
	defer peer.Close()

	rec := sstpValidationPair(model.EventValidationEnforce, []string{sstpRiscDisabledUri})
	rec.StreamConfiguration.RouteMode = model.RouteModeForward
	rec.SstpMethod = &model.SstpMethod{
		Role:                model.SstpRoleInitiator,
		EndpointUrl:         peer.URL,
		AuthorizationHeader: "Bearer test-token",
	}
	// One outbound event so the primary cycle actually POSTs.
	ev := &model.EventRecord{Jti: "sstp-outbound-ev", Original: `{"jti":"sstp-outbound-ev"}`}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fake := newFakeSstpOutbound(ctx, *rec, ev)
	fake.verifyCfg = goSetSstp.VerifyConfig{
		JWKS:              jwks,
		ExpectedIssuer:    sstpValidationIssuer,
		ExpectedAudiences: []string{sstpValidationAud},
		RequireSignature:  true,
	}

	dialer := NewSstpDialer(&oneShotCoordinator{}, "node-ev-e2e", nil, SstpDialerConfig{
		BaseDelay:           5 * time.Millisecond,
		MaxDelay:            50 * time.Millisecond,
		BackoffFactor:       2.0,
		LeaseDuration:       500 * time.Millisecond,
		HeartbeatInterval:   200 * time.Millisecond,
		HeartbeatRetryDelay: 10 * time.Millisecond,
		Jitter:              func() time.Duration { return 0 },
		HTTPClient:          &http.Client{Timeout: 2 * time.Second},
		BackfillBatch:       10,
	})
	dialer.Bind(fake)
	dialer.RegisterPair(sstpValidationPairId)
	t.Cleanup(func() { dialer.UnregisterPair(sstpValidationPairId) })

	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		_, ok := lastSetErrs[sstpValidationBadJti]
		return ok
	}, 3*time.Second, 20*time.Millisecond,
		"the rejection must ride the next request's setErrs so the peer stops resending")

	mu.Lock()
	se := lastSetErrs[sstpValidationBadJti]
	mu.Unlock()
	assert.Equal(t, goSetPush.ErrInvalidRequest, se.Err)
	assert.Contains(t, se.Description, sstpRiscDisabledUri)
	assert.Empty(t, fake.ingestedCopy(), "a rejected SET must never reach the event router")
}

// TestSstpDialer_InboundServerDefaultAppliesWhenPairIsUnset proves the dialer
// inherits the server-wide default (I2SIG_STREAM_EVENT_VALIDATION) the same way
// the acceptor does through the StreamService: a pair with no per-stream mode
// still enforces when the deployment default says ENFORCE.
func TestSstpDialer_InboundServerDefaultAppliesWhenPairIsUnset(t *testing.T) {
	bad, jwks := signSstpEventSet(t, sstpValidationBadJti, sstpRiscDisabledUri,
		map[string]any{"reason": "   "})
	rec := sstpValidationPair(model.EventValidationUnset, []string{sstpRiscDisabledUri})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fake := newFakeSstpOutbound(ctx, *rec)
	fake.verifyCfg = goSetSstp.VerifyConfig{
		JWKS:              jwks,
		ExpectedIssuer:    sstpValidationIssuer,
		ExpectedAudiences: []string{sstpValidationAud},
		RequireSignature:  true,
	}
	d := NewSstpDialer(&oneShotCoordinator{}, "node-validation", nil, SstpDialerConfig{
		EventValidationDefault: model.EventValidationEnforce,
	})
	d.Bind(fake)

	feedback := d.runInboundHalf(rec, map[string]string{sstpValidationBadJti: bad})
	require.Contains(t, feedback.SetErrs, sstpValidationBadJti,
		"an unset pair must inherit the server default on the dialer path too")
}
