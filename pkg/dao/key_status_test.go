package dao

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestJwkKeyRec_DerivedStatus verifies the derived-status ladder: revoked wins
// over suspended, suspended over active, and an untouched record is active. The
// status is derived from the two nullable timestamps, never stored (ADR 0028,
// mirroring the TokenRecord timestamp pattern of ADR 0022).
func TestJwkKeyRec_DerivedStatus(t *testing.T) {
	now := time.Now()

	active := JwkKeyRec{KeyName: "k", Kid: "k"}
	assert.Equal(t, KeyStatusActive, active.Status())
	assert.True(t, active.IsActive())
	assert.False(t, active.IsRevoked())

	suspended := JwkKeyRec{KeyName: "k", Kid: "k", SuspendedAt: now}
	assert.Equal(t, KeyStatusSuspended, suspended.Status())
	assert.False(t, suspended.IsActive())
	assert.False(t, suspended.IsRevoked())

	revoked := JwkKeyRec{KeyName: "k", Kid: "k", RevokedAt: now}
	assert.Equal(t, KeyStatusRevoked, revoked.Status())
	assert.False(t, revoked.IsActive())
	assert.True(t, revoked.IsRevoked())

	// Revocation wins over suspension.
	both := JwkKeyRec{KeyName: "k", Kid: "k", SuspendedAt: now, RevokedAt: now}
	assert.Equal(t, KeyStatusRevoked, both.Status())
	assert.False(t, both.IsActive())
	assert.True(t, both.IsRevoked())
}

// TestJwkKeyRec_ToKeyState verifies the per-kid state projection used by
// KeySummary carries the derived status and both timestamps.
func TestJwkKeyRec_ToKeyState(t *testing.T) {
	now := time.Now()
	rec := JwkKeyRec{KeyName: "k", Kid: "k-2", SuspendedAt: now}
	st := rec.ToKeyState()
	assert.Equal(t, "k-2", st.Kid)
	assert.Equal(t, KeyStatusSuspended, st.Status)
	assert.Equal(t, now, st.SuspendedAt)
	assert.True(t, st.RevokedAt.IsZero())
}
