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

	// Provenance: redemption tracking (ADR 0007 — track redemption, not
	// issuance). LastRedemptionIP/At record where and when the token was last
	// used (a /register call for an IAT); RedemptionCount is the running tally.
	LastRedemptionIP string    `bson:"last_redemption_ip,omitzero" json:"last_redemption_ip,omitempty"`
	LastRedemptionAt time.Time `bson:"last_redemption_at,omitzero" json:"last_redemption_at,omitzero"`
	RedemptionCount  int64     `bson:"redemption_count,omitzero" json:"redemption_count,omitempty"`
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

	// Provenance (ADR 0007) surfaced for audit display.
	Parent           string `json:"parent,omitempty"`
	LastRedemptionIP string `json:"last_redemption_ip,omitempty"`
	LastRedemptionAt int64  `json:"last_redemption_at,omitzero"`
	RedemptionCount  int64  `json:"redemption_count,omitzero"`
}

const (
	TokenTypeIAT    = "IAT"
	TokenTypeStream = "STREAM"
)
