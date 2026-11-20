package model

import "testing"

func pollConfigWithBearer(bearer string) *StreamConfiguration {
	return &StreamConfiguration{
		Id: "sid-1",
		Delivery: &OneOfStreamConfigurationDelivery{
			PollTransmitMethod: &PollTransmitMethod{
				Method:              DeliveryPoll,
				EndpointUrl:         "https://example/poll/sid-1",
				AuthorizationHeader: bearer,
			},
		},
	}
}

// TestMaskCredentialsPoll covers ADR 0022 §3: a poll delivery bearer reads as
// the sentinel *** on every read surface, and the original record is never
// mutated (masking applies to a deep copy).
func TestMaskCredentialsPoll(t *testing.T) {
	live := "Bearer live-token"
	cfg := pollConfigWithBearer(live)

	masked := cfg.MaskCredentials()

	if got := masked.Delivery.PollTransmitMethod.AuthorizationHeader; got != MaskedCredentialValue {
		t.Errorf("masked poll bearer = %q, want %q", got, MaskedCredentialValue)
	}
	if got := cfg.Delivery.PollTransmitMethod.AuthorizationHeader; got != live {
		t.Errorf("original poll bearer mutated: got %q, want %q", got, live)
	}
}

// TestMaskCredentialsPush covers the RFC8935 (push) read surface.
func TestMaskCredentialsPush(t *testing.T) {
	cfg := &StreamConfiguration{
		Id: "sid-2",
		Delivery: &OneOfStreamConfigurationDelivery{
			PushReceiveMethod: &PushReceiveMethod{
				Method:              ReceivePush,
				EndpointUrl:         "https://example/events/sid-2",
				AuthorizationHeader: "Bearer push-live",
			},
		},
	}
	masked := cfg.MaskCredentials()
	if got := masked.Delivery.PushReceiveMethod.AuthorizationHeader; got != MaskedCredentialValue {
		t.Errorf("masked push bearer = %q, want %q", got, MaskedCredentialValue)
	}
}

// TestMaskCredentialsTxToken covers the tx_token field (outbound peer credential).
func TestMaskCredentialsTxToken(t *testing.T) {
	tok := "tx-live-secret"
	cfg := &StreamConfiguration{Id: "sid-3", TxToken: &tok}
	masked := cfg.MaskCredentials()
	if masked.TxToken == nil || *masked.TxToken != MaskedCredentialValue {
		t.Errorf("masked tx_token = %v, want %q", masked.TxToken, MaskedCredentialValue)
	}
	if *cfg.TxToken != tok {
		t.Errorf("original tx_token mutated: %q", *cfg.TxToken)
	}
}

// TestMaskCredentialsEmptyUnchanged confirms an empty (no bearer configured)
// field is not turned into ***; the sentinel must not be ambiguous with "no
// credential" — masking only redacts a present value.
func TestMaskCredentialsEmptyUnchanged(t *testing.T) {
	cfg := pollConfigWithBearer("")
	masked := cfg.MaskCredentials()
	if got := masked.Delivery.PollTransmitMethod.AuthorizationHeader; got != "" {
		t.Errorf("empty bearer became %q; masking must not redact an absent credential", got)
	}
}

// TestMaskCredentialsSstp covers the SSTP responder bearer carried in
// StreamStateRecord.SstpMethod (ADR 0022 §3).
func TestMaskCredentialsSstp(t *testing.T) {
	rec := &StreamStateRecord{
		SstpMethod: &SstpMethod{
			Role:                SstpRoleResponder,
			EndpointUrl:         "https://example/sstp/pair-1",
			AuthorizationHeader: "Bearer sstp-live",
		},
	}
	masked := rec.MaskCredentials()
	if got := masked.SstpMethod.AuthorizationHeader; got != MaskedCredentialValue {
		t.Errorf("masked sstp bearer = %q, want %q", got, MaskedCredentialValue)
	}
	if rec.SstpMethod.AuthorizationHeader != "Bearer sstp-live" {
		t.Error("original sstp bearer mutated")
	}
}

// TestMergeUnchangedCredentialsLeaveAlone covers ADR 0022 §3: an UPDATE body
// carrying the sentinel *** for a credential means "leave the stored value
// unchanged" — a read-edit-write round trip must not clobber the live bearer.
func TestMergeUnchangedCredentialsLeaveAlone(t *testing.T) {
	stored := pollConfigWithBearer("Bearer stored-live")
	incoming := pollConfigWithBearer(MaskedCredentialValue)

	incoming.MergeUnchangedCredentials(stored)

	if got := incoming.Delivery.PollTransmitMethod.AuthorizationHeader; got != "Bearer stored-live" {
		t.Errorf("after merge, bearer = %q, want the stored live value", got)
	}
}

// TestMergeUnchangedCredentialsRealUpdate confirms a genuine new credential in
// the update body replaces the stored one (only the sentinel is special).
func TestMergeUnchangedCredentialsRealUpdate(t *testing.T) {
	stored := pollConfigWithBearer("Bearer stored-live")
	incoming := pollConfigWithBearer("Bearer brand-new")

	incoming.MergeUnchangedCredentials(stored)

	if got := incoming.Delivery.PollTransmitMethod.AuthorizationHeader; got != "Bearer brand-new" {
		t.Errorf("after merge, bearer = %q, want the new value", got)
	}
}
