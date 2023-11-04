package model

type PollTransmitMethod struct {
	Method              string `json:"method"`                 // urn:ietf:rfc:8936
	EndpointUrl         string `json:"endpoint_url,omitempty"` // The URL where events can be retrieved from. This is specified by the Transmitter.
	AuthorizationHeader string `json:"authorization_header,omitempty"`
}

type PollReceiveMethod struct {
	Method string `json:"method"` // urn:ietf:rfc:8936:receive
	//	RouteMode           string          `json:"route_mode,omitempty"` // Is one of RouteModeImport, RouteModeForward or RouteModePublish
	EndpointUrl         string          `json:"endpoint_url"`
	AuthorizationHeader string          `json:"authorization_header,omitempty"`
	PollConfig          *PollParameters `json:"poll_config,omitempty"`
}
