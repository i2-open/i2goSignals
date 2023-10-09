package model

import "go.mongodb.org/mongo-driver/bson/primitive"

// SsfClient describes a client entity that may manage one or more streams within one or more projects
type SsfClient struct {
	Id            primitive.ObjectID `bson:"_id" json:"client_id"`  // The Client identifier or client_id
	ProjectIds    []string           `json:"project_ids"`           // Project ids that the client is allowed to access
	AllowedScopes []string           `json:"allowed_scopes"`        // What scopes the client may be issued
	Email         string             `json:"email,omitempty"`       // The contact email address
	Description   string             `json:"description,omitempty"` // A description of the client
}
