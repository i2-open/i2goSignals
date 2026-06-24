package model

import (
	"testing"
	"time"
)

// TestTokenRecordIsRevoked covers the deferred-revocation semantics introduced
// for rotate-on-GET (ADR 0022 §2): a token is revoked only when revoked_at is
// SET and IN THE PAST. A future-dated revoked_at (the rotation grace window) is
// not yet revoked, so the old bearer keeps validating during the grace window.
func TestTokenRecordIsRevoked(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name      string
		revokedAt time.Time
		want      bool
	}{
		{"zero revoked_at is not revoked", time.Time{}, false},
		{"admin revoke (now) is revoked", now.Add(-time.Millisecond), true},
		{"past revoked_at is revoked", now.Add(-time.Hour), true},
		{"future-dated revoked_at is not yet revoked (grace window)", now.Add(time.Hour), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := TokenRecord{RevokedAt: tt.revokedAt}
			if got := rec.IsRevoked(); got != tt.want {
				t.Errorf("IsRevoked() = %v, want %v (revoked_at=%v)", got, tt.want, tt.revokedAt)
			}
		})
	}
}

// TestTokenRecordIsActiveWithGrace confirms IsActive tracks the deferred-revocation
// rule: a future-dated revoked_at still reads as active until the grace elapses.
func TestTokenRecordIsActiveWithGrace(t *testing.T) {
	future := TokenRecord{RevokedAt: time.Now().Add(time.Hour), ExpiresAt: time.Now().Add(24 * time.Hour)}
	if !future.IsActive() {
		t.Error("token with future-dated revoked_at should still be active during grace window")
	}
	past := TokenRecord{RevokedAt: time.Now().Add(-time.Hour), ExpiresAt: time.Now().Add(24 * time.Hour)}
	if past.IsActive() {
		t.Error("token revoked in the past should not be active")
	}
}
