package model

type RegisterParameters struct {
	Scopes      []string `json:"scopes,omitempty"` // The scopes requested (usually stream and/or event)
	Email       string   `json:"email,omitempty"`
	Description string   `json:"description,omitempty"`
}
