package model

// StripTransmitterSupplied returns a wire copy of a StreamConfiguration ready
// to POST to a registration target. It is the single, pure, table-testable
// implementation shared by the goSignals CLI (executeCreateRequest) and the
// server-side receiver create-stream handler that resolves a TxAlias.
//
// It always clears fields that are transmitter-assigned / Read-Only (SSF 1.0
// §7.1.1) and must not be echoed on a CREATE body: Id (stream_id),
// EventsSupported, EventsDelivered, MinVerificationInterval, and
// InactivityTimeout. Strict transmitters (the OpenID conformance suite, etc.)
// reject create bodies that carry these.
//
// When strict is true the wire body is additionally stripped of the
// transmitter-owned identity fields Iss, Aud, and IssuerJWKSUrl on
// transmitter-side (publisher-leg) registrations, to satisfy SSF §8.1.1.1 which
// forbids the receiver from supplying these on a publisher-leg POST. A strict
// transmitter returns HTTP 400 otherwise. Receiver-side bodies (Delivery.method
// == Receive*) are NEVER additionally stripped: there Iss/Aud/IssuerJWKSUrl are
// the foreign transmitter's hints the local SUT needs to validate inbound SETs
// (RFC 8417 §2.2) and discover SSF endpoints, so they are preserved regardless
// of strict. When strict is false everything passes through unchanged (apart
// from the always-cleared Read-Only fields above), preserving the operator's
// --iss / --aud / --iss-jwks-url intent for goSignals-to-goSignals federation.
func StripTransmitterSupplied(reg StreamConfiguration, strict bool) StreamConfiguration {
	wire := reg.DeepCopy()
	wire.Id = ""
	wire.EventsSupported = nil
	wire.EventsDelivered = nil
	wire.MinVerificationInterval = 0
	wire.InactivityTimeout = 0
	if strict {
		method := ""
		if reg.Delivery != nil {
			method = reg.Delivery.GetMethod()
		}
		isReceiverSide := method == ReceivePush || method == ReceivePoll || method == ReceiveSstp
		if !isReceiverSide {
			wire.Aud = nil
			wire.Iss = ""
			wire.IssuerJWKSUrl = ""
		}
	}
	return wire
}
