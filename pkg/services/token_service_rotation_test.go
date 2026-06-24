package services

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/i2-open/i2goSignals/pkg/authSupport"
	"github.com/i2-open/i2goSignals/pkg/dao/memory"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
)

func trackTestToken(t *testing.T, svc *TokenService, jti string) {
	t.Helper()
	claims := &authSupport.EventAuthToken{
		ProjectId: "proj",
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jti,
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
		},
	}
	if err := svc.TrackToken(context.Background(), claims, "", model.TokenTypeStream); err != nil {
		t.Fatalf("TrackToken: %v", err)
	}
}

// TestRevokeTokenAtDeferred covers the deferred-revocation path of rotate-on-GET
// (ADR 0022 §2): a future-dated revocation leaves the token valid until the
// grace instant elapses; an immediate (now-or-past) revocation is revoked at
// once, exactly like admin revocation.
func TestRevokeTokenAtDeferred(t *testing.T) {
	ctx := context.Background()
	svc := NewTokenService(memory.NewTokenDAO())

	trackTestToken(t, svc, "grace-jti")
	if err := svc.RevokeTokenAt(ctx, "grace-jti", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("RevokeTokenAt(future): %v", err)
	}
	revoked, err := svc.IsRevoked(ctx, "grace-jti")
	if err != nil {
		t.Fatalf("IsRevoked: %v", err)
	}
	if revoked {
		t.Error("future-dated revocation must leave the token valid during the grace window")
	}

	trackTestToken(t, svc, "immediate-jti")
	if err := svc.RevokeTokenAt(ctx, "immediate-jti", time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("RevokeTokenAt(past): %v", err)
	}
	revoked, err = svc.IsRevoked(ctx, "immediate-jti")
	if err != nil {
		t.Fatalf("IsRevoked: %v", err)
	}
	if !revoked {
		t.Error("past-dated revocation must be revoked immediately")
	}
}

// TestAdminRevokeStillImmediate confirms the pre-existing admin RevokeToken
// (revoked_at = now) is unchanged by the deferred-revocation rule.
func TestAdminRevokeStillImmediate(t *testing.T) {
	ctx := context.Background()
	svc := NewTokenService(memory.NewTokenDAO())
	trackTestToken(t, svc, "admin-jti")
	if err := svc.RevokeToken(ctx, "admin-jti"); err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}
	revoked, err := svc.IsRevoked(ctx, "admin-jti")
	if err != nil {
		t.Fatalf("IsRevoked: %v", err)
	}
	if !revoked {
		t.Error("admin RevokeToken must revoke immediately")
	}
}
