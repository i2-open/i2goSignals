package operations

import "encoding/json"

type patchOp struct {
	Op    string
	Path  string
	Value []json.RawMessage
}

type PatchRequest struct {
	Schemas    []string `json:"schemas" default:"urn:ietf:params:scim:api:messages:2.0:PatchOp"`
	Operations []patchOp
}
