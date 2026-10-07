package services

import (
	"context"

	"github.com/i2-open/i2goSignals/pkg/authSupport"
)

type authIssuerCtxKey struct{}

// WithAuthIssuer returns ctx carrying issuer as the request's bearer-token
// issuer. A surface whose configured Auth differs from KeyService's issuer
// (#376) binds it per request so service-side minting and jti checks use the
// same issuer its handlers validate with. A nil issuer leaves ctx unchanged.
func WithAuthIssuer(ctx context.Context, issuer *authSupport.AuthIssuer) context.Context {
	if issuer == nil {
		return ctx
	}
	return context.WithValue(ctx, authIssuerCtxKey{}, issuer)
}

// authIssuerFor returns the issuer bound to ctx by WithAuthIssuer, falling back
// to the KeyService issuer when none is bound.
func (s *KeyService) authIssuerFor(ctx context.Context) *authSupport.AuthIssuer {
	if issuer, ok := ctx.Value(authIssuerCtxKey{}).(*authSupport.AuthIssuer); ok {
		return issuer
	}
	return s.GetAuthIssuer()
}
