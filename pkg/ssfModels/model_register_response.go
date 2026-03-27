package model

type RegisterResponse struct {
	// The issued Bearer Token that the client will use for all Stream Management API calls that require authorization.
	Token string `json:"token"`
}
