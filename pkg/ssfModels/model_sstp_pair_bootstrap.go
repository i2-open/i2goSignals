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
// existing RouteMode semantics via SstpModeToRouteMode.
type SstpDirection struct {
	// Iss is the issuer asserted for this direction. Non-empty, URI-shaped.
	Iss string `json:"iss,omitempty"`

	// IssJwksUrl is the issuer's JWKS URL for SET validation on this direction.
	IssJwksUrl string `json:"iss_jwks_url,omitempty"`

	// Aud is the audience for this direction. Non-empty, URI-shaped.
	Aud []string `json:"aud,omitempty"`

	// Events is the requested event-type set for this direction (loose, may be
	// empty).
	Events []string `json:"events,omitempty"`

	// Mode is one of SstpModeForward, SstpModePublish, SstpModeImport, mapped to
	// the existing RouteMode by SstpModeToRouteMode.
	Mode string `json:"mode,omitempty"`
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
