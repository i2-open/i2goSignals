package model

// SstpTransmitMarker is the SSF wire-format delivery marker for the transmit
// (outbound) side of an SSTP pair. Per ADR 0018, the per-direction Delivery
// field carries ONLY the method URN — pair-scoped connectivity (Role,
// EndpointUrl, AuthorizationHeader, PeerPairId) lives in SstpMethod on the
// record, never on the SSF wire shape. This keeps bearer tokens and endpoints
// out of any SSF wire response.
type SstpTransmitMarker struct {
	Method string `json:"method" bson:"method"` // urn:i2-open:secevent:delivery:sstp
}

// SstpReceiveMarker is the SSF wire-format delivery marker for the receive
// (inbound) side of an SSTP pair. Marker-only, like SstpTransmitMarker.
type SstpReceiveMarker struct {
	Method string `json:"method" bson:"method"` // urn:i2-open:secevent:delivery:sstp:receive
}

// SstpMethod carries the pair-scoped connectivity for an SSTP StreamStateRecord.
// Per ADR 0018 / PRD #154 Q23, secrets and endpoints live here — on the record,
// not duplicated across the two per-direction Delivery fields — so redaction in
// SSF wire responses is trivial and the pair-scoped semantics match the data
// model.
type SstpMethod struct {
	// Role declares which side of the pair this node plays: SstpRoleInitiator
	// (HTTP client) or SstpRoleResponder (HTTP server). Required at create.
	Role string `json:"role,omitempty" bson:"role,omitempty"`
	// EndpointUrl is the SSTP endpoint for the pair (POST /sstp/{PairId}).
	EndpointUrl string `json:"endpoint_url,omitempty" bson:"endpoint_url,omitempty"`
	// AuthorizationHeader is the per-pair bearer credential.
	AuthorizationHeader string `json:"authorization_header,omitempty" bson:"authorization_header,omitempty"`
	// PeerPairId is the PairId held by the peer node for this same pair.
	PeerPairId string `json:"peer_pair_id,omitempty" bson:"peer_pair_id,omitempty"`
}

// DeepCopy returns an independent copy of the SstpMethod, or nil when m is nil.
func (m *SstpMethod) DeepCopy() *SstpMethod {
	if m == nil {
		return nil
	}
	res := *m
	return &res
}

const (
	// SstpRoleInitiator marks the node that owns the SSTP-client HTTP connection.
	SstpRoleInitiator = "initiator"
	// SstpRoleResponder marks the node that answers POST /sstp/{id} (SSTP server).
	SstpRoleResponder = "responder"
)
