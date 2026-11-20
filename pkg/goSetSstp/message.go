// Package goSetSstp implements the wire-protocol shape of the Synchronous SET Transfer
// Protocol (SSTP, draft-hunt-secevent-sstp-00) as a third SET delivery method alongside
// RFC8935 push (pkg/goSetPush) and RFC8936 poll (pkg/goSetPoll).
//
// Inside an SSTP message each SET is byte-identical to an RFC8935 SET: the "sets" object
// maps a SET's "jti" to its compact-serialized JWS string, exactly as carried on the
// RFC8935 push wire.
//
// This package depends only on pkg/goSet and the standard library — it imports nothing
// under internal/, matching the boundary rule of its sibling protocol libraries.
package goSetSstp

// Message is the body of an SSTP request or response, carried with Content-Type
// application/sstp+json (draft-hunt-secevent-sstp-00 §2.1). The same shape is used in
// both directions of the single HTTP cycle.
type Message struct {
	// ReturnEvents indicates whether the peer SHOULD return SETs in its upcoming response.
	// Nil means "unspecified"; use ReturnEventsResolved for the effective value (default true).
	ReturnEvents *bool `json:"returnEvents,omitempty"`

	// ReturnImmediately, when true, declines HTTP long-polling. Nil means "unspecified";
	// use ReturnImmediatelyResolved for the effective value (default false).
	ReturnImmediately *bool `json:"returnImmediately,omitempty"`

	// Sets maps each SET's "jti" to its encoded (compact JWS) SET string. Omitted when empty.
	Sets map[string]string `json:"sets,omitempty"`

	// Ack lists the "jti" of each SET the sender has successfully received. Omitted when empty.
	Ack []string `json:"ack,omitempty"`

	// SetErrs maps the "jti" of each invalid received SET to its per-JTI error. Omitted when empty.
	SetErrs map[string]SetErr `json:"setErrs,omitempty"`
}

// BoolPtr returns a pointer to b. It is the canonical way to set Message.ReturnEvents or
// Message.ReturnImmediately to an explicit true/false (as opposed to leaving them nil to mean
// "unspecified / use the default").
func BoolPtr(b bool) *bool {
	return &b
}

// ReturnEventsResolved returns the effective value of ReturnEvents, applying the §2.1 default
// of true when the field is nil (unspecified). This is the single place the returnEvents default
// is documented.
func (m Message) ReturnEventsResolved() bool {
	if m.ReturnEvents == nil {
		return true
	}
	return *m.ReturnEvents
}

// ReturnImmediatelyResolved returns the effective value of ReturnImmediately, applying the §2.1
// default of false when the field is nil (unspecified). This is the single place the
// returnImmediately default is documented.
func (m Message) ReturnImmediatelyResolved() bool {
	if m.ReturnImmediately == nil {
		return false
	}
	return *m.ReturnImmediately
}

// SetErr is the per-JTI error object carried under SSTP "setErrs" (§2.3). It mirrors the
// {err, description} shape of RFC8935's DeliveryErr but uses the SSTP error vocabulary.
type SetErr struct {
	// Err is one of the ErrCode keywords from §2.3 Table 1.
	Err string `json:"err"`

	// Description is human-readable diagnostic text.
	Description string `json:"description"`
}
