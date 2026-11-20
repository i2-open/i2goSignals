package dao

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestJwkKeyRec_ValidityWindow: a record is valid from NotBefore through
// NotAfter, both inclusive (RFC 5280); a zero bound is open, so a record with neither
// never expires (i2goSignals#318).
func TestJwkKeyRec_ValidityWindow(t *testing.T) {
	t0 := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	rec := JwkKeyRec{Kid: "k", NotBefore: t0, NotAfter: t0.Add(24 * time.Hour)}

	assert.False(t, rec.ValidAt(t0.Add(-time.Second)))
	assert.True(t, rec.ValidAt(t0))
	assert.True(t, rec.ValidAt(t0.Add(24*time.Hour-time.Second)))
	assert.True(t, rec.ValidAt(t0.Add(24*time.Hour)), "still valid at exactly NotAfter")
	assert.False(t, rec.ValidAt(t0.Add(24*time.Hour+time.Nanosecond)))

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
	assert.Equal(t, KeyStatusActive, rec.StatusAt(t0.Add(time.Hour)), "NotAfter is inclusive")
	assert.Equal(t, KeyStatusExpired, rec.StatusAt(t0.Add(time.Hour+time.Nanosecond)))

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
// window as notBefore/notAfter.
func TestJwkKeyRec_ToKeyStateCarriesValidity(t *testing.T) {
	t0 := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	rec := JwkKeyRec{Kid: "k", NotBefore: t0, NotAfter: t0.Add(time.Hour)}
	st := rec.ToKeyStateAt(t0.Add(2 * time.Hour))
	assert.Equal(t, KeyStatusExpired, st.Status)
	assert.Equal(t, t0, st.NotBefore)
	assert.Equal(t, t0.Add(time.Hour), st.NotAfter)
}

// TestJwkKeyRec_ToKeyStateIsRawLifecycleState: the DAO projection consults no
// clock — its status is the lifecycle status alone, and the reader derives the
// validity status against its own clock (#318 review).
func TestJwkKeyRec_ToKeyStateIsRawLifecycleState(t *testing.T) {
	t0 := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	rec := JwkKeyRec{Kid: "k", NotBefore: t0, NotAfter: t0.Add(time.Hour)}
	st := rec.ToKeyState()
	assert.Equal(t, KeyStatusActive, st.Status, "long expired, but no clock is read")
	assert.Equal(t, KeyStatusExpired, st.StatusAt(t0.Add(2*time.Hour)))

	raw, err := json.Marshal(st)
	assert.NoError(t, err)
	assert.Contains(t, string(raw), `"not_before"`)
	assert.Contains(t, string(raw), `"not_after"`)
}

func TestValidityPeriod(t *testing.T) {
	t0 := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	p := ValidityPeriod{NotBefore: t0, NotAfter: t0.Add(time.Hour)}
	tests := []struct {
		name       string
		p          ValidityPeriod
		at         time.Time
		valid, nyv bool
	}{
		{"open period", ValidityPeriod{}, t0, true, false},
		{"before NotBefore", p, t0.Add(-time.Second), false, true},
		{"at NotBefore", p, t0, true, false},
		{"inside", p, t0.Add(time.Minute), true, false},
		{"at NotAfter (inclusive)", p, t0.Add(time.Hour), true, false},
		{"just after NotAfter", p, t0.Add(time.Hour + time.Nanosecond), false, false},
		{"after NotAfter", p, t0.Add(2 * time.Hour), false, false},
		{"open start", ValidityPeriod{NotAfter: t0}, t0.Add(-time.Hour), true, false},
		{"open end", ValidityPeriod{NotBefore: t0}, t0.AddDate(100, 0, 0), true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.valid, tt.p.ValidAt(tt.at))
			assert.Equal(t, tt.nyv, tt.p.NotYetValidAt(tt.at))
		})
	}
	rec := JwkKeyRec{NotBefore: p.NotBefore, NotAfter: p.NotAfter}
	assert.Equal(t, p, rec.Validity())
	assert.Equal(t, p, rec.ToKeyState().Validity())
}
