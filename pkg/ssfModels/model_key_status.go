package model

// SetKeyStatusRequest is the body of POST /key/{keyName}/status. Status is one
// of "active" | "suspended" | "revoked" (see pkg/dao KeyStatus* constants).
// An empty Kid applies the transition to all records under the keyName; a
// supplied Kid must belong to that keyName. See community ADR 0028.
type SetKeyStatusRequest struct {
	Status string `json:"status"`
	Kid    string `json:"kid,omitempty"`
}
