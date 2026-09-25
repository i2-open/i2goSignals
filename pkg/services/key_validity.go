package services

// Signing-key validity periods (i2goSignals#318, ADR 0042). A key signs only
// inside [NotBefore, NotAfter). Validity is derived against the KeyService clock
// on every read, never stored as a status, so an expired key leaves signing
// selection the moment its NotAfter passes, and a newer key that is not yet
// valid takes over at its NotBefore, with no operator action and no job.

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
)

const (
	// DefaultKeyLifetime is how long a generated or cert-less uploaded signing
	// key stays valid when neither I2SIG_ISSUER_KEY_LIFETIME nor the request says
	// otherwise.
	DefaultKeyLifetime = 180 * 24 * time.Hour
	// DefaultKeyExpiryWarning is how far ahead of a signing key's NotAfter the
	// expiry WARN starts.
	DefaultKeyExpiryWarning = 30 * 24 * time.Hour

	keyLifetimeEnvVar      = "I2SIG_ISSUER_KEY_LIFETIME"
	keyExpiryWarningEnvVar = "I2SIG_ISSUER_KEY_EXPIRY_WARNING"

	// expiryWarnEvery is the most often one key's expiry WARN repeats from the
	// background pass.
	expiryWarnEvery = 24 * time.Hour
	// expiryScanEvery is the most often the background pass reads the key store
	// looking for keys inside the warning window.
	expiryScanEvery = time.Hour
)

// ParseKeyLifetime parses a key lifetime or warning window: a whole or decimal
// number of days with a "d" suffix ("180d"), or a Go duration ("12h"). "0" and
// "never" (any case) mean no expiry and return 0. Empty and negative values are
// errors.
func ParseKeyLifetime(raw string) (time.Duration, error) {
	v := strings.ToLower(strings.TrimSpace(raw))
	switch v {
	case "":
		return 0, errors.New("empty key lifetime")
	case "0", "never":
		return 0, nil
	}
	var d time.Duration
	if days, ok := strings.CutSuffix(v, "d"); ok {
		n, err := strconv.ParseFloat(days, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid key lifetime %q: want a number of days (180d), a duration (12h), 0 or never", raw)
		}
		d = time.Duration(n * float64(24*time.Hour))
	} else {
		var err error
		if d, err = time.ParseDuration(v); err != nil {
			return 0, fmt.Errorf("invalid key lifetime %q: want a number of days (180d), a duration (12h), 0 or never", raw)
		}
	}
	if d < 0 {
		return 0, fmt.Errorf("invalid key lifetime %q: must not be negative", raw)
	}
	return d, nil
}

// durationFromEnv reads a lifetime-style setting, falling back to def (with a
// WARN) when it is set but unparseable.
func durationFromEnv(name string, def time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return def
	}
	d, err := ParseKeyLifetime(raw)
	if err != nil {
		ksLog.Warn("Invalid key validity setting; using the default", "setting", name, "value", raw, "default", def, "error", err)
		return def
	}
	return d
}

// KeyOption adjusts how a key is minted.
type KeyOption func(*keyOptions)

type keyOptions struct {
	lifetime    time.Duration
	hasLifetime bool
}

// WithLifetime overrides the global key lifetime for one key. 0 means the key
// never expires.
func WithLifetime(d time.Duration) KeyOption {
	return func(o *keyOptions) {
		o.lifetime = d
		o.hasLifetime = true
	}
}

// keyValidity is the validity period stamped on a minted record. The zero value
// is the open period of a key that never expires.
type keyValidity struct {
	notBefore time.Time
	notAfter  time.Time
}

// SetClock replaces the clock validity is derived against. Tests inject one; a
// nil now restores time.Now.
func (s *KeyService) SetClock(now func() time.Time) {
	s.validityMu.Lock()
	defer s.validityMu.Unlock()
	s.nowFn = now
}

// SetKeyLifetime sets the global lifetime of generated and cert-less uploaded
// signing keys. 0 means they never expire.
func (s *KeyService) SetKeyLifetime(d time.Duration) {
	s.validityMu.Lock()
	defer s.validityMu.Unlock()
	s.keyLifetime = d
}

// SetExpiryWarningWindow sets how far ahead of NotAfter the expiry WARN starts.
func (s *KeyService) SetExpiryWarningWindow(d time.Duration) {
	s.validityMu.Lock()
	defer s.validityMu.Unlock()
	s.expiryWarnWindow = d
	s.lastExpiryScan = time.Time{} // a new window is looked at on the next pass
}

func (s *KeyService) clock() time.Time {
	s.validityMu.Lock()
	now := s.nowFn
	s.validityMu.Unlock()
	if now == nil {
		return time.Now()
	}
	return now()
}

// mintedAt is the CreatedAt stamped on a record this service mints
// (i2goSignals#316): stamped here rather than in each KeyDAO so every store
// carries it, and truncated to the millisecond Mongo stores so it reads back
// unchanged.
func (s *KeyService) mintedAt() time.Time {
	return s.clock().UTC().Truncate(time.Millisecond)
}

// generatedValidity is the period of a key minted at createdAt without a
// certificate: createdAt plus the request's lifetime, or the global one. The
// token issuer's key never expires: it signs the server's own auth tokens, and
// an expiry there would lock administrators out.
func (s *KeyService) generatedValidity(keyName string, createdAt time.Time, opts []KeyOption) keyValidity {
	if keyName == s.tokenIssuer {
		return keyValidity{}
	}
	var o keyOptions
	for _, opt := range opts {
		opt(&o)
	}
	s.validityMu.Lock()
	lifetime := s.keyLifetime
	s.validityMu.Unlock()
	if o.hasLifetime {
		lifetime = o.lifetime
	}
	if lifetime <= 0 {
		return keyValidity{}
	}
	return keyValidity{notAfter: createdAt.Add(lifetime)}
}

// GetSignerUntil is GetSigner plus the instant its answer stops holding: the
// selected key's NotAfter, or a newer key's NotBefore when that comes first. It
// is the zero time when no validity bound can change the selection. The event
// router caches a signer no longer than that, so a cached key converges on the
// same answer a fresh lookup gives.
func (s *KeyService) GetSignerUntil(ctx context.Context, issuer string, alg string) (crypto.Signer, string, time.Time, error) {
	rec, until, err := s.signingRecFor(ctx, issuer, alg)
	if err != nil {
		return nil, "", time.Time{}, err
	}
	key, kid, err := parseSigningRec(rec)
	if err != nil {
		return nil, "", time.Time{}, err
	}
	return key, kid, until, nil
}

// signingRecFor resolves issuer's active signing record for signature algorithm
// alg at the service clock, with the instant the selection stops holding.
func (s *KeyService) signingRecFor(ctx context.Context, issuer string, alg string) (*interfaces.JwkKeyRec, time.Time, error) {
	storedAlg, err := storedAlgFor(alg)
	if err != nil {
		return nil, time.Time{}, err
	}
	recs, err := s.keyDAO.FindByKeyName(ctx, issuer)
	if err != nil {
		return nil, time.Time{}, err
	}
	now := s.clock()
	latest, sawInactive := latestActiveSigningRec(recs, storedAlg, now)
	if latest == nil {
		if sawInactive {
			// WARN, not ERROR (deliberately demoted): this runs on every key read,
			// and a paused stream's push retries and background key check read
			// the key once per retry. The router logs the one ERROR per
			// key-unavailable pause (#312) and again when the stream is disabled.
			ksLog.Warn("No active signing key for issuer; all signing keys are suspended, revoked, expired or not yet valid",
				"issuer", issuer, "alg", algLabel(storedAlg),
				"remedy", "rotate a new key or reactivate a suspended key")
		}
		return nil, time.Time{}, interfaces.ErrKeyNotFound
	}
	return latest, selectionUntil(recs, latest, storedAlg, now), nil
}

// selectionUntil is the first instant after now at which a validity bound
// changes which record of storedAlg is selected: the selected record's NotAfter,
// or the NotBefore of a record that would then be newer and active.
func selectionUntil(recs []*interfaces.JwkKeyRec, selected *interfaces.JwkKeyRec, storedAlg string, now time.Time) time.Time {
	until := selected.NotAfter
	for _, rec := range recs {
		if len(rec.KeyBytes) == 0 || rec.Alg != storedAlg || !rec.IsActive() {
			continue
		}
		if rec.NotBefore.After(now) && rec.NewerThan(selected) && (until.IsZero() || rec.NotBefore.Before(until)) {
			until = rec.NotBefore
		}
	}
	return until
}

// signingKeyUnavailableDetail says why issuer has no signing key of alg when a
// validity period is the reason: "expired at <time>" or "not valid until
// <time>" for the newest otherwise-active key, "" when there is none.
func (s *KeyService) signingKeyUnavailableDetail(ctx context.Context, issuer string, alg string) string {
	storedAlg, err := storedAlgFor(alg)
	if err != nil {
		return ""
	}
	recs, err := s.keyDAO.FindByKeyName(ctx, issuer)
	if err != nil {
		return ""
	}
	now := s.clock()
	var newest *interfaces.JwkKeyRec
	for _, rec := range recs {
		if len(rec.KeyBytes) == 0 || rec.Alg != storedAlg || !rec.IsActive() || rec.ValidAt(now) {
			continue
		}
		if rec.NewerThan(newest) {
			newest = rec
		}
	}
	switch {
	case newest == nil:
		return ""
	case !newest.NotBefore.IsZero() && now.Before(newest.NotBefore):
		return "the signing key is not valid until " + newest.NotBefore.UTC().Format(time.RFC3339)
	default:
		return "the signing key expired at " + newest.NotAfter.UTC().Format(time.RFC3339)
	}
}

// warnIfExpiringSoon logs the expiry WARN for rec when its NotAfter falls inside
// the warning window, and reports whether it did.
func (s *KeyService) warnIfExpiringSoon(rec *interfaces.JwkKeyRec, now time.Time) bool {
	if rec == nil || rec.NotAfter.IsZero() || !rec.ValidAt(now) {
		return false
	}
	s.validityMu.Lock()
	window := s.expiryWarnWindow
	s.validityMu.Unlock()
	left := rec.NotAfter.Sub(now)
	if window <= 0 || left > window {
		return false
	}
	ksLog.Warn("Signing key expires soon",
		"issuer", rec.KeyName, "alg", algLabel(rec.Alg), "kid", recKid(rec),
		"notAfter", rec.NotAfter.UTC().Format(time.RFC3339),
		"daysRemaining", int(left/(24*time.Hour)),
		"remedy", "rotate a new key for this issuer and algorithm before it expires")
	return true
}

// WarnExpiringSigningKeys is the background expiry check: it WARNs for every
// signing key inside the warning window, at most once a day per key, and reads
// the key store at most once an hour. The event router's background key check
// calls it on every pass.
func (s *KeyService) WarnExpiringSigningKeys(ctx context.Context) {
	now := s.clock()
	s.validityMu.Lock()
	if !s.lastExpiryScan.IsZero() && now.Sub(s.lastExpiryScan) < expiryScanEvery {
		s.validityMu.Unlock()
		return
	}
	s.lastExpiryScan = now
	s.validityMu.Unlock()

	names, err := s.keyDAO.ListKeyNames(ctx)
	if err != nil {
		ksLog.Debug("Expiry check could not list key names", "error", err)
		return
	}
	for _, name := range names {
		recs, err := s.keyDAO.FindByKeyName(ctx, name)
		if err != nil {
			continue
		}
		for _, rec := range recs {
			if len(rec.KeyBytes) == 0 || !rec.IsActive() {
				continue
			}
			kid := recKid(rec)
			s.validityMu.Lock()
			last, seen := s.expiryWarnedAt[kid]
			s.validityMu.Unlock()
			if seen && now.Sub(last) < expiryWarnEvery {
				continue
			}
			if s.warnIfExpiringSoon(rec, now) {
				s.validityMu.Lock()
				s.expiryWarnedAt[kid] = now
				s.validityMu.Unlock()
			}
		}
	}
}

// statesAt re-derives each KeyState's status at now. Suspended and revoked
// stand; otherwise the validity period decides between active, expired and
// not-yet-valid.
func statesAt(states []interfaces.KeyState, now time.Time) {
	for i := range states {
		st := &states[i]
		rec := interfaces.JwkKeyRec{SuspendedAt: st.SuspendedAt, RevokedAt: st.RevokedAt, NotBefore: st.NotBefore, NotAfter: st.NotAfter}
		st.Status = rec.StatusAt(now)
	}
}
