package services

// Signing keys carry a validity period (i2goSignals#318, ADR 0042). A key
// signs only inside [NotBefore, NotAfter); validity is derived against the
// KeyService clock on every read, so these tests drive time with an injected
// clock and never sleep.

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/dao/memory"
	"github.com/i2-open/i2goSignals/pkg/goSet/mldsa"
)

const validityIssuer = "https://validity.example"

// testClock is a settable clock for KeyService.SetClock.
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func newTestClock(t time.Time) *testClock { return &testClock{t: t} }

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) Set(t time.Time) {
	c.mu.Lock()
	c.t = t
	c.mu.Unlock()
}

var validityT0 = time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

func validityKeyService(t *testing.T) (*KeyService, *testClock) {
	t.Helper()
	clk := newTestClock(validityT0)
	svc := NewKeyService(memory.NewKeyDAO(), "DEFAULT", nil, nil)
	svc.SetClock(clk.Now)
	return svc, clk
}

// seedSigningRec stores a signing record of alg for keyName with the given
// validity period and creation time, and returns its kid.
func seedSigningRec(t *testing.T, svc *KeyService, keyName, alg, kid string, created, notBefore, notAfter time.Time) string {
	t.Helper()
	storedAlg, err := storedAlgFor(alg)
	require.NoError(t, err)
	key, err := generateSigningKey(storedAlg)
	require.NoError(t, err)
	encAlg, priv, pub, err := encodeSigningKey(key)
	require.NoError(t, err)
	require.NoError(t, svc.keyDAO.Insert(context.Background(), &interfaces.JwkKeyRec{
		KeyName: keyName, Kid: kid, Use: "sig", Alg: encAlg,
		KeyBytes: priv, PubKeyBytes: pub,
		CreatedAt: created, NotBefore: notBefore, NotAfter: notAfter,
	}))
	return kid
}

// A record with no validity period behaves exactly as before: it signs at any
// instant, however far the clock moves.
func TestKeyValidity_ARecordWithNoValiditySignsAtAnyTime(t *testing.T) {
	svc, clk := validityKeyService(t)
	kid := seedSigningRec(t, svc, validityIssuer, "RS256", "legacy", validityT0, time.Time{}, time.Time{})
	for _, at := range []time.Time{validityT0, validityT0.AddDate(50, 0, 0)} {
		clk.Set(at)
		_, got, err := svc.GetSigner(context.Background(), validityIssuer, "RS256")
		require.NoError(t, err)
		assert.Equal(t, kid, got)
	}
}

// A key valid at T0 signs at T0 and still at exactly NotAfter (inclusive, RFC
// 5280); once the clock passes NotAfter it is not active, so GetSigner reports
// no active key.
func TestKeyValidity_AnExpiredKeyIsNotActive(t *testing.T) {
	for _, alg := range []string{"RS256", "ES256", mldsa.Alg} {
		t.Run(alg, func(t *testing.T) {
			svc, clk := validityKeyService(t)
			notAfter := validityT0.Add(time.Hour)
			kid := seedSigningRec(t, svc, validityIssuer, alg, "k1", validityT0, validityT0, notAfter)

			_, got, err := svc.GetSigner(context.Background(), validityIssuer, alg)
			require.NoError(t, err)
			assert.Equal(t, kid, got)

			clk.Set(notAfter)
			_, got, err = svc.GetSigner(context.Background(), validityIssuer, alg)
			require.NoError(t, err, "still valid at exactly NotAfter")
			assert.Equal(t, kid, got)

			clk.Set(notAfter.Add(time.Nanosecond))
			_, _, err = svc.GetSigner(context.Background(), validityIssuer, alg)
			assert.ErrorIs(t, err, interfaces.ErrKeyNotFound)
		})
	}
}

// A newer key that is not yet valid is skipped until its NotBefore, then takes
// over without any operator action.
func TestKeyValidity_ANewerNotYetValidKeyTakesOverAtNotBefore(t *testing.T) {
	svc, clk := validityKeyService(t)
	ctx := context.Background()
	start := validityT0.Add(time.Hour)
	older := seedSigningRec(t, svc, validityIssuer, "ES256", "older", validityT0.Add(-time.Hour), time.Time{}, time.Time{})
	newer := seedSigningRec(t, svc, validityIssuer, "ES256", "newer", validityT0, start, time.Time{})

	_, kid, until, err := svc.GetSignerUntil(ctx, validityIssuer, "ES256")
	require.NoError(t, err)
	assert.Equal(t, older, kid, "the not-yet-valid key is skipped")
	assert.Equal(t, start, until, "the selection must be re-made at the newer key's NotBefore")

	clk.Set(start)
	_, kid, err = svc.GetSigner(ctx, validityIssuer, "ES256")
	require.NoError(t, err)
	assert.Equal(t, newer, kid)
}

// GetSignerUntil reports the instant just past the selected key's (inclusive)
// NotAfter as when the answer stops holding, and the zero time for a key with
// no period.
func TestKeyValidity_GetSignerUntilReportsTheSelectedKeysNotAfter(t *testing.T) {
	svc, _ := validityKeyService(t)
	notAfter := validityT0.Add(time.Hour)
	seedSigningRec(t, svc, validityIssuer, "RS256", "k1", validityT0, time.Time{}, notAfter)
	_, _, until, err := svc.GetSignerUntil(context.Background(), validityIssuer, "RS256")
	require.NoError(t, err)
	assert.Equal(t, notAfter.Add(time.Nanosecond), until)

	svc2, _ := validityKeyService(t)
	seedSigningRec(t, svc2, validityIssuer, "RS256", "k1", validityT0, time.Time{}, time.Time{})
	_, _, until, err = svc2.GetSignerUntil(context.Background(), validityIssuer, "RS256")
	require.NoError(t, err)
	assert.True(t, until.IsZero())
}

func keyRec(t *testing.T, svc *KeyService, kid string) *interfaces.JwkKeyRec {
	t.Helper()
	rec, err := svc.keyDAO.FindByKid(context.Background(), kid)
	require.NoError(t, err)
	return rec
}

// A generated key expires DefaultKeyLifetime (180d) after creation unless the
// global setting or the request says otherwise.
func TestKeyValidity_GeneratedKeyLifetime(t *testing.T) {
	ctx := context.Background()
	assert.Equal(t, 180*24*time.Hour, DefaultKeyLifetime)

	t.Run("default 180d", func(t *testing.T) {
		svc, _ := validityKeyService(t)
		_, kid, err := svc.CreateKeyPairForAlg(ctx, validityIssuer, "ES256", "sig", "")
		require.NoError(t, err)
		rec := keyRec(t, svc, kid)
		assert.Equal(t, validityT0.AddDate(0, 0, 180), rec.NotAfter)
		assert.Equal(t, validityT0, rec.CreatedAt)
	})
	t.Run("global never", func(t *testing.T) {
		svc, _ := validityKeyService(t)
		svc.SetKeyLifetime(0)
		_, kid, err := svc.CreateKeyPairForAlg(ctx, validityIssuer, "RS256", "sig", "")
		require.NoError(t, err)
		assert.True(t, keyRec(t, svc, kid).NotAfter.IsZero())
	})
	t.Run("per-request never", func(t *testing.T) {
		svc, _ := validityKeyService(t)
		_, kid, err := svc.RotateKey(ctx, validityIssuer, "RS256", "", WithLifetime(0))
		require.NoError(t, err)
		assert.True(t, keyRec(t, svc, kid).NotAfter.IsZero())
	})
	t.Run("per-request duration overrides the setting", func(t *testing.T) {
		svc, _ := validityKeyService(t)
		svc.SetKeyLifetime(0)
		_, kid, err := svc.CreateKeyPairForAlg(ctx, validityIssuer, mldsa.Alg, "sig", "", WithLifetime(10*24*time.Hour))
		require.NoError(t, err)
		assert.Equal(t, validityT0.AddDate(0, 0, 10), keyRec(t, svc, kid).NotAfter)
	})
	t.Run("the token issuer key never expires", func(t *testing.T) {
		svc, _ := validityKeyService(t)
		require.NoError(t, svc.InitializeTokenKey(ctx, "DEFAULT"))
		rec := keyRec(t, svc, "DEFAULT")
		assert.True(t, rec.NotAfter.IsZero())
		assert.Equal(t, validityT0, rec.NotBefore)
	})
	// Server-generated keys expire (#318): CreateKeyPair and
	// EnsureSigningKeyForAlg stamp NotBefore = creation, NotAfter = creation
	// plus the configured lifetime; a zero lifetime leaves NotAfter empty.
	t.Run("CreateKeyPair and EnsureSigningKeyForAlg take the lifetime", func(t *testing.T) {
		svc, _ := validityKeyService(t)
		svc.SetKeyLifetime(30 * 24 * time.Hour)
		_, err := svc.CreateKeyPair(ctx, validityIssuer, "sig", "")
		require.NoError(t, err)
		rec := keyRec(t, svc, validityIssuer)
		assert.Equal(t, validityT0, rec.NotBefore)
		assert.Equal(t, validityT0.AddDate(0, 0, 30), rec.NotAfter)

		minted, err := svc.EnsureSigningKeyForAlg(ctx, validityIssuer, "ES256", "")
		require.NoError(t, err)
		require.True(t, minted)
		recs, err := svc.keyDAO.FindByKeyName(ctx, validityIssuer)
		require.NoError(t, err)
		for _, r := range recs {
			assert.Equal(t, validityT0, r.NotBefore, r.Kid)
			assert.Equal(t, validityT0.AddDate(0, 0, 30), r.NotAfter, r.Kid)
		}
	})
	t.Run("a zero lifetime leaves NotAfter empty on generated keys", func(t *testing.T) {
		svc, _ := validityKeyService(t)
		svc.SetKeyLifetime(0)
		_, err := svc.CreateKeyPair(ctx, validityIssuer, "sig", "")
		require.NoError(t, err)
		_, err = svc.EnsureSigningKeyForAlg(ctx, validityIssuer, "ES256", "")
		require.NoError(t, err)
		recs, err := svc.keyDAO.FindByKeyName(ctx, validityIssuer)
		require.NoError(t, err)
		require.Len(t, recs, 2)
		for _, r := range recs {
			assert.Equal(t, validityT0, r.NotBefore, r.Kid)
			assert.True(t, r.NotAfter.IsZero(), r.Kid)
		}
	})
}

func TestParseKeyLifetime(t *testing.T) {
	cases := map[string]time.Duration{
		"180d":  180 * 24 * time.Hour,
		"30d":   30 * 24 * time.Hour,
		"1.5d":  36 * time.Hour,
		"12h":   12 * time.Hour,
		"0":     0,
		"never": 0,
		"NEVER": 0,
	}
	for in, want := range cases {
		got, err := ParseKeyLifetime(in)
		require.NoError(t, err, in)
		assert.Equal(t, want, got, in)
	}
	for _, bad := range []string{"", "soon", "-1d", "-5h", "d", "nand", "NaNd", "infd", "+Infd", "1e12d"} {
		_, err := ParseKeyLifetime(bad)
		assert.Error(t, err, bad)
	}
}

// Saving a signing transmitter whose only key is expired, or not yet valid, is
// refused with a 400 naming the issuer, the algorithm and the time.
func TestKeyValidity_SaveIsRefusedWithOnlyAnExpiredOrNotYetValidKey(t *testing.T) {
	ctx := context.Background()
	t.Run("expired", func(t *testing.T) {
		svc, _ := streamServiceFixture(t)
		clk := newTestClock(validityT0)
		svc.keyService.SetClock(clk.Now)
		notAfter := validityT0.Add(-time.Hour)
		seedSigningRec(t, svc.keyService, keyedIssuer, "ES256", "k-exp", validityT0.AddDate(0, 0, -1), time.Time{}, notAfter)
		req := pollSigningRequest(keyedIssuer, "")
		req.StreamConfiguration.SigningAlg = "ES256"
		err := svc.RequireActiveSigningKey(ctx, &req)
		require.ErrorIs(t, err, ErrInvalidRequest)
		assert.Contains(t, err.Error(), keyedIssuer)
		assert.Contains(t, err.Error(), "ES256")
		assert.Contains(t, err.Error(), "expired at "+notAfter.Format(time.RFC3339))
	})
	t.Run("not yet valid", func(t *testing.T) {
		svc, _ := streamServiceFixture(t)
		clk := newTestClock(validityT0)
		svc.keyService.SetClock(clk.Now)
		start := validityT0.Add(time.Hour)
		seedSigningRec(t, svc.keyService, keyedIssuer, "RS256", "k-nyv", validityT0, start, time.Time{})
		req := pollSigningRequest(keyedIssuer, "")
		err := svc.RequireActiveSigningKey(ctx, &req)
		require.ErrorIs(t, err, ErrInvalidRequest)
		assert.Contains(t, err.Error(), keyedIssuer)
		assert.Contains(t, err.Error(), "RS256")
		assert.Contains(t, err.Error(), "not valid until "+start.Format(time.RFC3339))
	})
}

// Saving a stream whose key is inside the expiry-warning window succeeds and
// logs the expiry WARN.
func TestKeyValidity_SaveWithAKeyInsideTheWarningWindowSucceedsAndWarns(t *testing.T) {
	svc, _ := streamServiceFixture(t)
	clk := newTestClock(validityT0)
	svc.keyService.SetClock(clk.Now)
	notAfter := validityT0.AddDate(0, 0, 10)
	seedSigningRec(t, svc.keyService, keyedIssuer, "RS256", "k-soon", validityT0, time.Time{}, notAfter)
	logs := captureLogs(t)
	req := pollSigningRequest(keyedIssuer, "")
	require.NoError(t, svc.RequireActiveSigningKey(context.Background(), &req))
	assert.Contains(t, logs.String(), "level=WARN")
	assert.Contains(t, logs.String(), "Signing key expires soon")
	assert.Contains(t, logs.String(), "daysRemaining=10")
}

// The stranding guard counts expired keys as unavailable: suspending the only
// valid key when the rest are expired strands the stream.
func TestKeyValidity_StrandingGuardCountsExpiredKeysAsUnavailable(t *testing.T) {
	svc, _ := streamServiceFixture(t)
	ctx := context.Background()
	clk := newTestClock(validityT0)
	svc.keyService.SetClock(clk.Now)
	seedSigningRec(t, svc.keyService, keyedIssuer, "RS256", "k-expired", validityT0.Add(-2*time.Hour), time.Time{}, validityT0.Add(-time.Hour))
	seedSigningRec(t, svc.keyService, keyedIssuer, "RS256", "k-valid", validityT0.Add(-time.Hour), time.Time{}, time.Time{})
	seedSigningRec(t, svc.keyService, keyedIssuer, "RS256", "k-future", validityT0, validityT0.Add(time.Hour), time.Time{})
	rec := pollTransmitterRecord("rs-1", "")
	require.NoError(t, svc.PersistStreamStateRecord(ctx, &rec))

	algs, stranded, err := svc.StrandedByKeyChange(ctx, keyedIssuer, KeyChange{Retires: RetireKid("k-valid")})
	require.NoError(t, err)
	assert.Equal(t, []string{"RS256"}, algs)
	require.Len(t, stranded, 1)
	assert.Equal(t, "rs-1", stranded[0].StreamId)
}

// The listing reports the derived status and the validity period.
func TestKeyValidity_ListingReportsDerivedStatusAndPeriod(t *testing.T) {
	svc, clk := validityKeyService(t)
	ctx := context.Background()
	notAfter := validityT0.Add(time.Hour)
	seedSigningRec(t, svc, validityIssuer, "RS256", "k1", validityT0, validityT0, notAfter)
	seedSigningRec(t, svc, validityIssuer, "RS256", "k2", validityT0, notAfter.Add(time.Hour), time.Time{})
	clk.Set(notAfter.Add(time.Second))

	stateOf := func(states []interfaces.KeyState, kid string) interfaces.KeyState {
		for _, st := range states {
			if st.Kid == kid {
				return st
			}
		}
		t.Fatalf("no state for %s", kid)
		return interfaces.KeyState{}
	}
	summary, err := svc.GetKeySummary(ctx, validityIssuer)
	require.NoError(t, err)
	k1 := stateOf(summary.KeyStates, "k1")
	assert.Equal(t, interfaces.KeyStatusExpired, k1.Status)
	assert.Equal(t, validityT0, k1.NotBefore)
	assert.Equal(t, notAfter, k1.NotAfter)
	assert.Equal(t, interfaces.KeyStatusNotYetValid, stateOf(summary.KeyStates, "k2").Status)

	summaries, err := svc.ListSummaries(ctx)
	require.NoError(t, err)
	require.Len(t, summaries, 1)
	assert.Equal(t, interfaces.KeyStatusExpired, stateOf(summaries[0].KeyStates, "k1").Status)

	raw, err := json.Marshal(k1)
	require.NoError(t, err)
	assert.Contains(t, string(raw), `"not_before"`)
	assert.Contains(t, string(raw), `"not_after"`)
	assert.Contains(t, string(raw), `"status":"expired"`)
}

// An expired public key stays in the JWKS until revoked, deleted or replaced.
func TestKeyValidity_AnExpiredKeyStaysInTheJWKS(t *testing.T) {
	svc, clk := validityKeyService(t)
	notAfter := validityT0.Add(time.Hour)
	seedSigningRec(t, svc, validityIssuer, "ES256", "k-exp", validityT0, time.Time{}, notAfter)
	clk.Set(notAfter.AddDate(1, 0, 0))
	raw := svc.GetPublicJWKS(context.Background(), validityIssuer)
	require.NotNil(t, raw)
	assert.Contains(t, string(*raw), `"kid":"k-exp"`)
}

// The expiry WARN fires from the background pass at most once per day per key,
// only inside the window, and the window is configurable.
func TestKeyValidity_ExpiryWarningFiresOncePerDayInsideTheWindow(t *testing.T) {
	svc, clk := validityKeyService(t)
	ctx := context.Background()
	notAfter := validityT0.AddDate(0, 0, 40)
	seedSigningRec(t, svc, validityIssuer, "ES256", "k1", validityT0, time.Time{}, notAfter)

	logs := captureLogs(t)
	svc.WarnExpiringSigningKeys(ctx)
	assert.NotContains(t, logs.String(), "Signing key expires soon", "40 days out is outside the default 30d window")

	svc.SetExpiryWarningWindow(45 * 24 * time.Hour)
	svc.WarnExpiringSigningKeys(ctx)
	svc.WarnExpiringSigningKeys(ctx)
	clk.Set(validityT0.Add(23 * time.Hour))
	svc.WarnExpiringSigningKeys(ctx)
	out := logs.String()
	assert.Equal(t, 1, countOf(out, "Signing key expires soon"), "once per day, not per pass: %s", out)
	assert.Contains(t, out, "issuer="+validityIssuer)
	assert.Contains(t, out, "alg=ES256")
	assert.Contains(t, out, "daysRemaining=40")
	assert.Contains(t, out, "notAfter="+notAfter.Format(time.RFC3339))

	clk.Set(validityT0.Add(24 * time.Hour))
	svc.WarnExpiringSigningKeys(ctx)
	assert.Equal(t, 2, countOf(logs.String(), "Signing key expires soon"), "the next day warns again")
}

func countOf(s, sub string) int {
	n := 0
	for i := 0; ; {
		j := indexFrom(s, sub, i)
		if j < 0 {
			return n
		}
		n++
		i = j + len(sub)
	}
}

func indexFrom(s, sub string, from int) int {
	if from > len(s) {
		return -1
	}
	for i := from; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
