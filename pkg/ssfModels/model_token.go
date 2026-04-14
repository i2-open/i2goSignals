package model

import (
	"time"
)

// TokenRecord tracks issued tokens without storing the actual token string.
type TokenRecord struct {
	JTI       string    `bson:"_id" json:"jti"`
	ClientID  string    `bson:"client_id,omitzero" json:"client_id,omitzero"`
	Subject   string    `bson:"subject" json:"subject,omitempty"`
	ProjectID string    `bson:"project_id" json:"project_id"`
	Type      string    `bson:"type" json:"type"`     // one of TokenTypeIAT or TokenTypeStream
	Scopes    []string  `bson:"scopes" json:"scopes"` // scopes issued with the token
	IssuedAt  time.Time `bson:"iat" json:"iat"`
	ExpiresAt time.Time `bson:"exp" json:"exp"`
	RevokedAt time.Time `bson:"revoked_at,omitzero" json:"revoked_at,omitzero"`
	Parent    string    `bson:"parent" json:"parent,omitempty"`
}

// IntrospectionResponse implements RFC7662 response format.
type IntrospectionResponse struct {
	Active    bool   `json:"active"`
	Type      string `json:"type"` // one of TokenTypeIAT or TokenTypeStream
	ProjectID string `json:"project_id,omitzero"`
	ClientID  string `json:"client_id,omitzero"`
	Subject   string `json:"subject,omitzero"`
	Scope     string `json:"scope,omitzero"`
	Exp       int64  `json:"exp,omitzero"`
	Iat       int64  `json:"iat,omitzero"`
	Jti       string `json:"jti"`
}

const (
	TokenTypeIAT    = "IAT"
	TokenTypeStream = "STREAM"
)
