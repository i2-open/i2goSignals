package model

import (
	"go.mongodb.org/mongo-driver/v2/bson"
)

// SsfClient describes a client entity that may manage one or more streams within one or more projects.
//
// AllowedScopes records the capabilities the client was granted, which is not the
// same as the roles minted into its stream-client (management) token. In
// particular, event_delivery may appear here as a granted capability while the
// management token never carries it as a role: event delivery is authorized by a
// separate per-stream delivery token (see authUtil.IssueStreamToken), not by the
// management token. This divergence is intentional (#140) — do not "reconcile" it
// by minting event_delivery into the management token.
type SsfClient struct {
	Id            bson.ObjectID `bson:"_id" json:"client_id"`  // The Client identifier or client_id
	ProjectIds    []string      `json:"project_ids"`           // Project ids that the client is allowed to access
	AllowedScopes []string      `json:"allowed_scopes"`        // Capabilities granted to the client; see note below
	Email         string        `json:"email,omitempty"`       // The contact email address
	Description   string        `json:"description,omitempty"` // A description of the client
}
