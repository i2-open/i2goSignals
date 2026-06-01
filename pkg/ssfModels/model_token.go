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

	// StreamID links a STREAM-typed token to the stream it authorizes (the
	// stream's hex id). It is a join key only — the last-seen IP is NOT copied
	// here; it is read live from the stream's RemoteAddress when listing.
	StreamID string `bson:"stream_id,omitzero" json:"stream_id,omitempty"`

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
	Type      string `json:"token_type,omitzero"` // RFC 7662 token_type; one of TokenTypeIAT or TokenTypeStream
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

// TokenListEntry is an enriched, caller-scoped row returned by GET /token. It
// embeds the stored TokenRecord (provenance + lineage included) and adds the
// live last-seen IP joined from the stream's RemoteAddress for STREAM-typed
// tokens (never stored a second time on the token).
type TokenListEntry struct {
	*TokenRecord `bson:",inline"`

	// LastSeenIP is the stream's most recent RemoteAddress, joined at list time
	// for STREAM-typed rows. Empty for IAT tokens or when no address is known.
	LastSeenIP string `json:"last_seen_ip,omitempty"`
}

// IsActive reports whether the token is currently live: neither revoked nor
// expired. This is the single source of truth for token liveness, shared by
// introspection, the list filter, and the CLI, so the three cannot diverge.
func (r TokenRecord) IsActive() bool {
	return r.RevokedAt.IsZero() && (r.ExpiresAt.IsZero() || r.ExpiresAt.After(time.Now()))
}

// State returns the human-readable lifecycle state of the token: "revoked"
// (RevokedAt set, taking precedence), "expired" (ExpiresAt in the past), else
// "active". Consistent with IsActive.
func (r TokenRecord) State() string {
	if !r.RevokedAt.IsZero() {
		return "revoked"
	}
	if !r.ExpiresAt.IsZero() && r.ExpiresAt.Before(time.Now()) {
		return "expired"
	}
	return "active"
}

const (
	TokenTypeIAT    = "IAT"
	TokenTypeStream = "STREAM"
)
