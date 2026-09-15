package model

import "encoding/json"

// IsSstpBootstrapBody discriminates a POST /stream request body as an
// SstpPairBootstrap rather than an SSF StreamConfiguration (ADR 0019). The
// distinguishing shape is a top-level "role" of initiator/responder together
// with at least one of the per-direction "primary"/"inbound" objects, none of
// which appear on a StreamConfiguration. A malformed body returns false so the
// caller falls through to the StreamConfiguration path and reports its error.
func IsSstpBootstrapBody(body []byte) bool {
	var probe struct {
		Role    string          `json:"role"`
		Primary json.RawMessage `json:"primary"`
		Inbound json.RawMessage `json:"inbound"`
	}
	if err := json.Unmarshal(body, &probe); err != nil {
		return false
	}
	if probe.Role != SstpRoleInitiator && probe.Role != SstpRoleResponder {
		return false
	}
	return len(probe.Primary) > 0 || len(probe.Inbound) > 0
}

// SstpPairBootstrap is the discriminated body shape accepted by POST /stream
// to provision one node's half of an SSTP pair (PRD #154 Q44, ADR 0019). It is
// NOT an SSF wire-format StreamConfiguration: it carries pair-level connectivity
// plus per-direction business-plane inputs, which the service expands into a
// bidirectional StreamStateRecord (one transmit-side StreamConfiguration as the
// primary, one receive-side StreamConfiguration as SstpInbound).
//
// iss/aud are business-plane inputs supplied per direction — they are NOT
// derived from goSignals' own identity (Q27, Q29). No reciprocity is enforced
// between the two halves so that asymmetric multi-hop pairs are legitimate.
type SstpPairBootstrap struct {
	// Role declares which side of the pair this node plays: SstpRoleInitiator
	// (HTTP client) or SstpRoleResponder (HTTP server). Required, no default.
	Role string `json:"role,omitempty"`

	// EndpointUrl is the SSTP endpoint for the pair. On the responder it is
	// server-derived and MUST NOT be supplied by the operator. On the initiator
	// it is operator-supplied (or learned via the auto-reg response).
	EndpointUrl string `json:"endpoint_url,omitempty"`

	// AuthorizationHeader is the per-pair bearer. On the initiator it MUST be
	// operator-supplied (the peer responder minted it). On the responder it is
	// server-minted and MUST NOT be supplied by the operator.
	AuthorizationHeader string `json:"authorization_header,omitempty"`

	// PeerServerAlias names a stored Server whose credentials are used to cascade
	// the mirrored bootstrap to the peer. Optional: when omitted, only the local
	// half is provisioned and peer connectivity is patched later (Q31).
	PeerServerAlias string `json:"peer_server_alias,omitempty"`

	// PeerPairId is the PairId held by the peer for this same pair. Learned via
	// the cascade response; settable directly when bootstrapping the mirror.
	PeerPairId string `json:"peer_pair_id,omitempty"`

	// Description is a human-facing label for the pair, copied onto both halves.
	Description string `json:"description,omitempty"`

	// Primary is the transmit (outbound) direction's business-plane inputs.
	Primary SstpDirection `json:"primary"`

	// Inbound is the receive (inbound) direction's business-plane inputs.
	Inbound SstpDirection `json:"inbound"`
}

// SstpDirection holds the per-direction business-plane inputs of an SSTP pair
// bootstrap. iss/aud ride the business plane (Q27, Q29); events are accepted
// loosely per half (no URI-registry check, empty allowed); mode maps to the
// existing RouteMode semantics via SstpModeToRouteMode; receive_mode optionally
// gives the receiving end its own choice (issue #306); event_source answers the
// other ADR 0004 axis for this half alone (issue #296).
type SstpDirection struct {
	// Iss is the issuer asserted for this direction. Non-empty. A JWT
	// StringOrURI (RFC 7519 s4.1.1), so a URI by convention but not by rule —
	// validateSstpDirection warns about a non-URI value rather than refusing it.
	Iss string `json:"iss,omitempty"`

	// IssJwksUrl is the issuer's JWKS URL for SET validation on this direction.
	IssJwksUrl string `json:"iss_jwks_url,omitempty"`

	// Aud is the audience for this direction. Non-empty. StringOrURI per
	// RFC 7519 s4.1.3, with the same convention-not-rule caveat as Iss.
	Aud []string `json:"aud,omitempty"`

	// Events is the requested event-type set for this direction (loose, may be
	// empty).
	Events []string `json:"events,omitempty"`

	// Mode is one of SstpModeForward, SstpModePublish, SstpModeImport, mapped to
	// the existing RouteMode by SstpModeToRouteMode. It is the TRANSMITTING end's
	// choice for this direction, and also the receiving end's unless ReceiveMode
	// says otherwise.
	Mode string `json:"mode,omitempty"`

	// ReceiveMode is the RECEIVING end's choice for this direction: SstpModeImport
	// (keep what arrives) or SstpModeForward (route it on). Optional (issue #306).
	//
	// A direction has two ends that read its route mode differently: the
	// transmitter tests == FW (relay verbatim, or re-sign), the receiver tests
	// == IM (import only, or route on), and PUBLISH is indistinguishable from
	// FORWARD on receipt (ADR 0031 D2). With Mode alone both ends are written from
	// one word, so "relay verbatim, import only" cannot be said. When ReceiveMode
	// is set the receiving end's RouteMode comes from it (see ReceiveRouteMode);
	// when it is empty the receiving end mirrors Mode exactly as it did before the
	// field existed, and the direction marshals without the key.
	//
	// Which end is which follows the bootstrap: on this node the primary is the
	// transmitting end, so the primary's ReceiveMode is the PEER's choice and
	// reaches it through mirrorSstpBootstrap's swap; the inbound's ReceiveMode is
	// this node's own. Each is echoed on the record — StreamStateRecord.ReceiveMode
	// and InboundReceiveMode.
	ReceiveMode string `json:"receive_mode,omitempty"`

	// EventSource says where THIS direction's events come from — the second of
	// the two orthogonal axes ADR 0004 defines, Mode above being the first. Mode
	// answers whether the direction re-signs; EventSource answers what it
	// carries. The two halves of a pair are independent logical streams, so each
	// one answers both questions for itself (issue #296).
	//
	// Nil preserves the behaviour from before the field existed: the leg falls
	// through effectiveEventSourceType to the DIRECT default.
	//
	// Where a direction's descriptor lands on the record: the primary's becomes
	// StreamStateRecord.EventSource, which is the one MatchesStream consults when
	// deciding what this pair transmits; the inbound's becomes
	// StreamStateRecord.InboundEventSource. See buildSstpRecord.
	EventSource *EventSource `json:"event_source,omitempty"`
}

const (
	// SstpModeForward preserves the upstream iss (maps to RouteModeForward).
	SstpModeForward = "FORWARD"
	// SstpModePublish re-signs with goSignals' iss (maps to RouteModePublish).
	SstpModePublish = "PUBLISH"
	// SstpModeImport keeps events local without further propagation (maps to
	// RouteModeImport).
	SstpModeImport = "IMPORT"
)

// SstpModeToRouteMode maps a bootstrap direction mode to the existing RouteMode
// constant. An empty mode resolves to RouteModePublish (the create-time default
// used by push/poll). An unknown value returns ("", false) so callers can
// reject it.
func SstpModeToRouteMode(mode string) (string, bool) {
	switch mode {
	case "", SstpModePublish:
		return RouteModePublish, true
	case SstpModeForward:
		return RouteModeForward, true
	case SstpModeImport:
		return RouteModeImport, true
	default:
		return "", false
	}
}

// SstpReceiveModeToRouteMode maps a direction's receive_mode to the RouteMode the
// receiving end stores. Only the two receive-side choices are valid:
// SstpModeImport and SstpModeForward. SstpModePublish is refused because a
// receiver cannot act on it differently from FORWARD (ADR 0031 D2), and the empty
// string is refused because an absent receive_mode is not a value — the direction
// falls back to its mode instead (SstpDirection.ReceiveRouteMode). Any other
// value returns ("", false) so callers can reject it.
func SstpReceiveModeToRouteMode(receiveMode string) (string, bool) {
	switch receiveMode {
	case SstpModeImport:
		return RouteModeImport, true
	case SstpModeForward:
		return RouteModeForward, true
	default:
		return "", false
	}
}

// ReceiveRouteMode is the RouteMode the RECEIVING end of this direction stores:
// the mapped ReceiveMode when it is present and valid, otherwise the mapped Mode,
// which is what the receiving end stored before ReceiveMode existed. Validation
// (validateSstpDirection) refuses an invalid value of either field before a
// record is built, so the fallback is never reached with a bad ReceiveMode on
// the create path.
func (d SstpDirection) ReceiveRouteMode() string {
	if mode, ok := SstpReceiveModeToRouteMode(d.ReceiveMode); ok {
		return mode
	}
	mode, _ := SstpModeToRouteMode(d.Mode)
	return mode
}
