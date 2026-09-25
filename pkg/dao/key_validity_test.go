package dao

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestJwkKeyRec_ValidityWindow: a record is valid from NotBefore (inclusive)
// until NotAfter (exclusive); a zero bound is open, so a record with neither
// never expires (i2goSignals#318).
func TestJwkKeyRec_ValidityWindow(t *testing.T) {
	t0 := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	rec := JwkKeyRec{Kid: "k", NotBefore: t0, NotAfter: t0.Add(24 * time.Hour)}

	assert.False(t, rec.ValidAt(t0.Add(-time.Second)))
	assert.True(t, rec.ValidAt(t0))
	assert.True(t, rec.ValidAt(t0.Add(24*time.Hour-time.Second)))
	assert.False(t, rec.ValidAt(t0.Add(24*time.Hour)))

	open := JwkKeyRec{Kid: "k"}
	assert.True(t, open.ValidAt(time.Time{}))
	assert.True(t, open.ValidAt(t0.AddDate(100, 0, 0)))
}

// TestJwkKeyRec_StatusAt: the derived status at an instant. Revoked and
// suspended outrank the validity window; outside it an otherwise active record
// is expired or not-yet-valid. A record with no validity reads exactly as
// Status() does.
func TestJwkKeyRec_StatusAt(t *testing.T) {
	t0 := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	rec := JwkKeyRec{Kid: "k", NotBefore: t0, NotAfter: t0.Add(time.Hour)}

	assert.Equal(t, KeyStatusNotYetValid, rec.StatusAt(t0.Add(-time.Minute)))
	assert.Equal(t, KeyStatusActive, rec.StatusAt(t0))
	assert.Equal(t, KeyStatusExpired, rec.StatusAt(t0.Add(time.Hour)))

	suspended := rec
	suspended.SuspendedAt = t0
	assert.Equal(t, KeyStatusSuspended, suspended.StatusAt(t0.Add(2*time.Hour)))
	revoked := rec
	revoked.RevokedAt = t0
	assert.Equal(t, KeyStatusRevoked, revoked.StatusAt(t0.Add(2*time.Hour)))

	legacy := JwkKeyRec{Kid: "k"}
	assert.Equal(t, legacy.Status(), legacy.StatusAt(t0))
}

// TestJwkKeyRec_ToKeyStateCarriesValidity: the per-kid state reports the
// window as not_before/not_after.
func TestJwkKeyRec_ToKeyStateCarriesValidity(t *testing.T) {
	t0 := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	rec := JwkKeyRec{Kid: "k", NotBefore: t0, NotAfter: t0.Add(time.Hour)}
	st := rec.ToKeyStateAt(t0.Add(2 * time.Hour))
	assert.Equal(t, KeyStatusExpired, st.Status)
	assert.Equal(t, t0, st.NotBefore)
	assert.Equal(t, t0.Add(time.Hour), st.NotAfter)
}
