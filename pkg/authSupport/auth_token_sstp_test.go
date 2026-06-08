package authSupport

import (
    "testing"
    "time"

    "github.com/golang-jwt/jwt/v5"
    "github.com/i2-open/i2goSignals/pkg/goSet"
    "github.com/stretchr/testify/assert"
)

// TestIssueSstpPairToken_StreamIds locks the register-tokens extension for SSTP
// pair create (issue #160, PRD #154 Q9.1/Q42): a single management bearer covers
// BOTH directions of an SSTP pair via EventAuthToken.StreamIds=[txSid, rxSid]. The
// minted token must parse, carry exactly the two pair SIDs, and authorize each SID
// for the read scope (event).
func TestIssueSstpPairToken_StreamIds(t *testing.T) {
    const txSid = "tx-sid-1"
    const rxSid = "rx-sid-1"

    signed, err := auth.IssueSstpPairToken(txSid, rxSid, "proj-sstp", false, nil)
    assert.NoError(t, err, "pair token should be issued")

    eat, err := auth.ParseAuthToken(signed)
    assert.NoError(t, err, "pair token should parse and validate")
    assert.ElementsMatch(t, []string{txSid, rxSid}, eat.StreamIds, "pair bearer carries both pair SIDs")

    // scope=event is sufficient for read-status / verify on either direction (Q42).
    assert.True(t, eat.IsAuthorized(txSid, []string{ScopeEventDelivery}), "tx side authorized for event")
    assert.True(t, eat.IsAuthorized(rxSid, []string{ScopeEventDelivery}), "rx side authorized for event")
}

// sstpPairEat builds an EventAuthToken shaped exactly like a minted SSTP pair
// bearer (StreamIds=[txSid, rxSid]) with the given roles, for asserting the
// scope-driven authorization paths without going through signing.
func sstpPairEat(txSid, rxSid string, roles ...string) *EventAuthToken {
    return &EventAuthToken{
        StreamIds: []string{txSid, rxSid},
        ProjectId: "proj-sstp",
        Roles:     roles,
        RegisteredClaims: jwt.RegisteredClaims{
            IssuedAt:  jwt.NewNumericDate(time.Now()),
            ExpiresAt: jwt.NewNumericDate(time.Now().AddDate(0, 0, 90)),
            ID:        goSet.GenerateJti(),
        },
    }
}

// TestSstpPairToken_WriteRequiresStreamScope locks the read/write scope asymmetry
// for an SSTP pair bearer (issue #160; PRD #154 Q42): scope=stream is required for
// UpdateStatus / config writes, and a bearer holding only scope=event is rejected
// for those writes while still passing the event-scoped reads on either side.
func TestSstpPairToken_WriteRequiresStreamScope(t *testing.T) {
    const txSid = "tx-sid-2"
    const rxSid = "rx-sid-2"

    // The production (non-admin) pair bearer holds both stream and event, so writes
    // are authorized on either direction.
    signed, err := auth.IssueSstpPairToken(txSid, rxSid, "proj-sstp", false, nil)
    assert.NoError(t, err)
    full, err := auth.ParseAuthToken(signed)
    assert.NoError(t, err)
    assert.True(t, full.IsAuthorized(txSid, []string{ScopeStreamMgmt}), "stream-scope write authorized on tx side")
    assert.True(t, full.IsAuthorized(rxSid, []string{ScopeStreamMgmt}), "stream-scope write authorized on rx side")

    // A bearer holding only event scope may read but not write.
    eventOnly := sstpPairEat(txSid, rxSid, ScopeEventDelivery)
    assert.True(t, eventOnly.IsAuthorized(txSid, []string{ScopeEventDelivery}), "event-only reads tx side")
    assert.True(t, eventOnly.IsAuthorized(rxSid, []string{ScopeEventDelivery}), "event-only reads rx side")
    assert.False(t, eventOnly.IsAuthorized(txSid, []string{ScopeStreamMgmt}), "event-only rejected for stream-scope write on tx side")
    assert.False(t, eventOnly.IsAuthorized(rxSid, []string{ScopeStreamMgmt}), "event-only rejected for stream-scope write on rx side")
}

// TestSstpPairToken_WrongSidRejected locks the StreamIds containment boundary: a
// pair bearer for [txSid, rxSid] must not authorize a third, unrelated SID even
// when the scope matches (issue #160 wrong-SID rejection path).
func TestSstpPairToken_WrongSidRejected(t *testing.T) {
    pair := sstpPairEat("tx-sid-3", "rx-sid-3", ScopeStreamMgmt, ScopeEventDelivery)
    assert.False(t, pair.IsAuthorized("someone-elses-sid", []string{ScopeEventDelivery}), "unrelated SID rejected for event")
    assert.False(t, pair.IsAuthorized("someone-elses-sid", []string{ScopeStreamMgmt}), "unrelated SID rejected for stream")
}

// TestSstpPairToken_OAuthWithoutStreamIdsRejected locks the OAuth/STS path for an
// SSTP-pair route (issue #160): an OAuth caller has no local EAT and therefore no
// StreamIds[] binding. Authorization must go through AuthContext.IsAuthorizedForStream
// (never a bare authCtx.Eat, which is nil here). An OAuth caller lacking the
// required scope is rejected; one holding it reduces to a pure scope check.
func TestSstpPairToken_OAuthWithoutStreamIdsRejected(t *testing.T) {
    const txSid = "tx-sid-4"

    // No scope granted -> rejected, and crucially does not panic on a nil Eat.
    noScope := &AuthContext{IsOAuthClient: true, GrantedScopes: nil}
    assert.Nil(t, noScope.Eat, "OAuth caller carries no local EAT / StreamIds")
    assert.False(t, noScope.IsAuthorizedForStream(txSid, ScopeEventDelivery), "OAuth without scope rejected for SSTP-pair route")

    // event scope granted -> read authorized despite no StreamIds binding.
    eventScope := &AuthContext{IsOAuthClient: true, GrantedScopes: []string{ScopeEventDelivery}}
    assert.True(t, eventScope.IsAuthorizedForStream(txSid, ScopeEventDelivery), "OAuth with event scope authorized for read")
    assert.False(t, eventScope.IsAuthorizedForStream(txSid, ScopeStreamMgmt), "OAuth with only event scope rejected for write")
}
