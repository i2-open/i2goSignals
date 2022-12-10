package i2scim

import (
	"encoding/json"
)

const METHOD_CREATE = "POST"
const METHOD_REPLACE = "PUT"
const METHOD_PATCH = "PATCH"
const METHOD_DELETE = "DELETE"

type ScimOperation struct {
	Method     string          `json:"method"`
	Path       string          `json:"path"`
	SeqNum     int             `json:"seq"`
	Data       json.RawMessage `json:"data"`
	AcceptDate string          `json:"accptd"`
	TransId    string          `json:"tid"`
}

/*
func (so *ScimOperation) mapSetEvents() []*jwt.Token {
	var events []*jwt.Token

	if so.Method == METHOD_CREATE {

	}
}

*/
