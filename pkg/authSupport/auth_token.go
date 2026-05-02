package authSupport

import (
	"context"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// TokenTracker is an interface for tracking and checking token revocation.
type TokenTracker interface {
	TrackToken(ctx context.Context, claims *EventAuthToken, tokenPurpose string) error
	IsRevoked(ctx context.Context, jti string) (bool, error)
}

const (
	ScopeStreamMgmt    = "stream"
	ScopeEventDelivery = "event"
	ScopeStreamAdmin   = "admin"
	ScopeRegister      = "reg"
	ScopeRoot          = "root"
	StreamAny          = "any"
)

// EventAuthToken is a token used for stream management and event delivery.
type EventAuthToken struct {
	StreamIds []string `json:"streams,omitempty"`
	ProjectId string   `json:"project_id"`
	Roles     []string `json:"roles,omitempty"`
	ClientId  string   `json:"client_id,omitempty"`
	jwt.RegisteredClaims
	Scope string `json:"scope,omitempty"`
}

// IsScopeMatch checks both Event token roles array and oauth style space-delimited scope claim.
func (t *EventAuthToken) IsScopeMatch(scopesAccepted []string) bool {
	if t == nil {
		return false
	}
	for _, acceptedScope := range scopesAccepted {
		// Check Roles (roles claim)
		for _, role := range t.Roles {
			if strings.EqualFold(role, ScopeRoot) {
				return true
			}
			if strings.EqualFold(role, acceptedScope) {
				return true
			}
		}
		// Check Scope (scope claim)
		if t.Scope != "" {
			scopes := strings.Fields(t.Scope)
			for _, scope := range scopes {
				if strings.EqualFold(scope, ScopeRoot) {
					return true
				}
				if strings.EqualFold(scope, acceptedScope) {
					return true
				}
			}
		}
	}
	return false
}

// IsAuthorized checks if the token is authorized for a specific stream and scopes.
func (t *EventAuthToken) IsAuthorized(streamId string, scopesAccepted []string) bool {
	if t == nil {
		return false
	}

	scopeMatch := t.IsScopeMatch(scopesAccepted)
	if streamId == "" {
		// Cases where streamId is not needed
		return scopeMatch
	}
	// if no value for streamId is in the token, assume any stream is ok
	if len(t.StreamIds) == 0 {
		return scopeMatch
	}

	// Auth restricts stream Id. Check for a match
	for _, v := range t.StreamIds {
		if strings.EqualFold(v, streamId) || strings.EqualFold(v, StreamAny) {
			return scopeMatch
		}
	}

	return false
}
