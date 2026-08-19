package services

import (
	"errors"
	"strings"
	"time"

	"github.com/MicahParks/keyfunc/v2"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// Backoff bounds for re-resolving an unresolved receive direction (ADR 0033).
// Exponential from ~10s, doubling, capped at 5 minutes — the cap matches
// RefreshRateLimit in pkg/goSet's JWKS loader so the server has a single story
// about how often it re-hits a JWKS endpoint.
const (
	jwksRetryInitialBackoff = 10 * time.Second
	jwksRetryMaxBackoff     = 5 * time.Minute
)

// normalizedJwksUrl maps the literal "NONE" (any case) to the empty string.
// Some SCIM peers write "NONE" for IssuerJWKSUrl to mean "the key is internal
// to this server" — i.e. the no-URL branch by intent. A record persisted before
// normalizeStreamTrustFields existed can still carry the literal, and reading
// it as a URL would send the resolver to fetch https://…/NONE forever
// (ADR 0033).
func normalizedJwksUrl(raw string) string {
	if strings.EqualFold(raw, "NONE") {
		return ""
	}
	return raw
}

// expectsVerificationMaterial is the ADR 0033 discriminator, and nothing else
// is: a receive direction expects verification material if and only if it has
// an issuer JWKS URL configured. NOT SigningOnly — StreamConfiguration already
// states that MUST NOT be inferred from "an issuer is configured", and the
// inference does not hold in the other direction either. NOT "a key was found",
// which is the outcome being classified and cannot also be the classifier.
//
// The no-URL branch rests on the ADR-0066 §D2 invariant enforced by
// validateBusinessStreamSecurity: SigningOnly (L2 = None) requires BOTH Iss and
// IssuerJWKSUrl, so a URL-less direction is bearer-gated by construction and
// has no verification material to be missing. That dependency is load-bearing —
// relaxing §D2 to permit a signing stream without a JWKS URL would silently
// misclassify it as not-configured and it would never retry.
func expectsVerificationMaterial(jwksUrl string) bool {
	return normalizedJwksUrl(jwksUrl) != ""
}

// errDirectionNotEnabled reports that no resolution was attempted because the
// receive direction itself is not enabled. It is the third of the three
// outcomes ADR 0033 requires be told apart from each other — "the fetch failed"
// and "nothing is expected here" are the other two. Folding it into the failed
// fetch is what would put an operator-disabled stream on the retry ladder and
// give it a next-retry time that can never arrive.
var errDirectionNotEnabled = errors.New("receive direction is not enabled")

// jwksIsUsable reports whether a resolved JWKS actually carries key material.
// Non-nil is NOT the test: keyService.GetPublicJWKS swallows every per-key
// error with a continue and returns whatever accumulated, so a total failure
// yields {"keys":[]} — which keyfunc.NewJSON parses into a non-nil, zero-key
// JWKS with a nil error. A JWKS that parses but carries zero keys is
// unresolved, not resolved (ADR 0033).
func jwksIsUsable(jwks *keyfunc.JWKS) bool {
	return jwks != nil && jwks.Len() > 0
}

// receiverCacheEntry is one slot of StreamService.receiverStreams: the stream
// record for a receive direction — keyed by that direction's SID, which is the
// inbound SID for an SSTP pair (ADR 0018) — plus this node's JWKS resolution
// bookkeeping. The bookkeeping is per entry, never global (ADR 0033).
//
// The entry exists to carry a distinction the codebase previously lacked:
// "verification material is expected here and I do not have it" versus "nothing
// is expected here". Only the first is a retry candidate. Before this, entry
// PRESENCE was the cache hit and a nil ValidateJwks meant all three of a failed
// fetch, no internally-registered key, and a disabled inbound direction — so a
// transient failure was cached as a permanent one (GH #264).
type receiverCacheEntry struct {
	// record is the stream record this direction belongs to. For an SSTP pair
	// it is the single bidirectional record; the receive-side trust fields are
	// on its SstpInbound leg.
	record *model.StreamStateRecord

	// jwksUrl is the issuer JWKS URL of THIS direction — for an SSTP pair it
	// comes from SstpInbound, not from the primary (transmit) configuration. It
	// is already "NONE"-normalized, so it is empty exactly when the direction
	// expects no verification material.
	jwksUrl string

	// jwks is the verification material handed to callers. It is only ever set
	// to a usable (non-nil, non-empty) value on a direction that expects one.
	jwks *keyfunc.JWKS

	// permanent records that the last attempt failed with an error
	// isPermanentJwksError classifies as permanent. That path has already
	// disabled the record and persisted the reason, so it is visible to an
	// operator and is not a retry candidate. It latches: nothing in the ladder
	// clears it — only an explicit re-enable of the direction
	// (resetRetryLadder) or eviction of the entry does.
	permanent bool

	// inFlight is set while an unlocked fetch is running so concurrent lookups
	// do not stampede the issuer's endpoint.
	inFlight bool

	lastErr   string
	backoff   time.Duration
	nextRetry time.Time
}

// expectsJwks reports whether this direction expects verification material.
func (e *receiverCacheEntry) expectsJwks() bool {
	return e.jwksUrl != ""
}

// resolved reports whether this entry holds usable verification material.
func (e *receiverCacheEntry) resolved() bool {
	return jwksIsUsable(e.jwks)
}

// unresolved is the ADR 0033 fault state: a URL is configured and no usable
// JWKS has been obtained for it. A direction with no URL is never unresolved.
func (e *receiverCacheEntry) unresolved() bool {
	return e.expectsJwks() && !e.resolved()
}

// dueForRetry reports whether a lookup at time now should re-attempt the fetch.
// Retry is lazy and per-entry: it happens on lookup once the deadline has
// passed and never from a background sweep (ADR 0033).
func (e *receiverCacheEntry) dueForRetry(now time.Time) bool {
	if !e.unresolved() || e.permanent || e.inFlight {
		return false
	}
	return !now.Before(e.nextRetry)
}

// resetRetryLadder makes the entry due for a fresh attempt on the next lookup.
// It is called when the entry's receive direction transitions to enabled: an
// explicit re-enable is an operator asserting the world changed, so it clears
// the permanent latch — the one state dueForRetry never leaves on its own —
// and zeroes the backoff rather than resuming a ladder whose failures predate
// the re-enable.
func (e *receiverCacheEntry) resetRetryLadder() {
	e.permanent = false
	e.backoff = 0
	e.nextRetry = time.Time{}
}

// recordAttempt folds the outcome of one resolution attempt into the entry and,
// on a retryable failure, schedules the next attempt with exponential backoff.
func (e *receiverCacheEntry) recordAttempt(now time.Time, jwks *keyfunc.JWKS, err error) {
	if !e.expectsJwks() {
		// No URL configured: a valid resting state. The internal key lookup is
		// authoritative and its result — including "no key at all" — is
		// legitimate, so this direction is never unresolved and never retried.
		e.jwks = jwks
		return
	}

	if errors.Is(err, errDirectionNotEnabled) {
		// Nothing was attempted, so this is not "resolution failing" and must
		// not enter the backoff ladder (ADR 0033). nextRetry is left zero so a
		// re-enable is picked up on the very next lookup: re-checking a
		// disabled direction returns here again without touching the network,
		// so there is no endpoint to hammer and no deadline to wait out.
		e.jwks = nil
		e.lastErr = errDirectionNotEnabled.Error()
		e.permanent = false
		e.backoff = 0
		e.nextRetry = time.Time{}
		return
	}

	if jwksIsUsable(jwks) {
		e.jwks = jwks
		e.lastErr = ""
		e.permanent = false
		e.backoff = 0
		e.nextRetry = time.Time{}
		return
	}

	e.jwks = nil
	switch {
	case err != nil:
		e.lastErr = err.Error()
		e.permanent = isPermanentJwksError(err)
	case jwks != nil:
		e.lastErr = "issuer JWKS resolved with zero keys"
	default:
		e.lastErr = "issuer JWKS unavailable"
	}

	if e.permanent {
		// The caller disables the record and persists the reason for this
		// class of error, so it is already visible to an operator. Not a retry
		// candidate.
		e.backoff = 0
		e.nextRetry = time.Time{}
		return
	}
	e.backoff = nextJwksBackoff(e.backoff)
	e.nextRetry = now.Add(e.backoff)
}

// nextJwksBackoff doubles the previous interval, starting at
// jwksRetryInitialBackoff and capped at jwksRetryMaxBackoff.
func nextJwksBackoff(prev time.Duration) time.Duration {
	if prev <= 0 {
		return jwksRetryInitialBackoff
	}
	next := prev * 2
	if next > jwksRetryMaxBackoff {
		return jwksRetryMaxBackoff
	}
	return next
}

// readiness derives this node's JWKS readiness for the entry. Readiness is
// node-local and never persisted: it describes this node's current reachability
// of a remote endpoint, not a property of the stream, so two cluster members may
// legitimately disagree and neither is stale (ADR 0033).
func (e *receiverCacheEntry) readiness() *model.JwksReadiness {
	if !e.expectsJwks() {
		return &model.JwksReadiness{State: model.JwksReadinessNotConfigured}
	}
	if e.resolved() {
		return &model.JwksReadiness{State: model.JwksReadinessReady}
	}
	out := &model.JwksReadiness{
		State:     model.JwksReadinessUnresolved,
		LastError: e.lastErr,
	}
	if !e.nextRetry.IsZero() {
		next := e.nextRetry
		out.NextRetryAt = &next
	}
	return out
}

// recordIdentifiedBy reports whether streamID names rec under any of the
// identities a caller can hold: the document _id, the primary (tx-side)
// StreamConfiguration SID, the pair's wire SID (PairId, ADR 0018), or the
// inbound SID. A plain receiver's first two are the same value; a pair's are
// three distinct ones, which is what makes eviction by key alone unsafe.
func recordIdentifiedBy(rec *model.StreamStateRecord, streamID string) bool {
	if rec == nil || streamID == "" {
		return false
	}
	if rec.StreamConfiguration.Id == streamID || rec.Id.Hex() == streamID {
		return true
	}
	if rec.PairId == streamID {
		return true
	}
	return rec.SstpInbound != nil && rec.SstpInbound.Id == streamID
}
