package model

type PushTransmitMethod struct {
	Method              string `json:"method"`                         // urn:ietf:rfc:8935
	EndpointUrl         string `json:"endpoint_url"`                   // The URL where events are pushed through HTTP POST. This is set by the Receiver.
	AuthorizationHeader string `json:"authorization_header,omitempty"` // The HTTP Authorization header that the Transmitter MUST set with each event delivery. The value is optional and it is set by the Receiver.
}

type PushReceiveMethod struct {
	Method string `json:"method"` // urn:ietf:rfc:8935:receive
	//	RouteMode           string // Is one of RouteModeImport, RouteModeForward or RouteModePublish
	EndpointUrl         string `json:"endpoint_url"`
	AuthorizationHeader string `json:"authorization_header,omitempty"` // token generated on response

}
