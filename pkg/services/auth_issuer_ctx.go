package services

import (
	"context"

	"github.com/i2-open/i2goSignals/pkg/authSupport"
)

type authIssuerCtxKey struct{}

// WithAuthIssuer returns ctx carrying issuer as the request's bearer-token
// issuer. A surface's configured Auth may come from a different key store than
// KeyService (#376); the surface routes bind it per request so service-side
// minting and jti checks use the same issuer its handlers validate with. An
// embedder calling StreamService or ClientService directly, outside the
// surface routes, binds its Auth the same way, or those services mint with
// KeyService's issuer. A nil issuer leaves ctx unchanged.
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
