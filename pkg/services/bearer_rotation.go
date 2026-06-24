package services

import (
	"context"
	"crypto/subtle"
	"os"
	"strings"
	"time"

	"github.com/i2-open/i2goSignals/pkg/authSupport"
	"github.com/i2-open/i2goSignals/pkg/logger"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
)

var rotateLog = logger.Sub("BEARER_ROTATE")

const (
	// bearerRotateOnGetEnvVar gates GET-triggered bearer rotation (ADR 0022 §4).
	// Default false: existing receivers that re-read config without persisting
	// the response would otherwise be revoked out from under themselves.
	bearerRotateOnGetEnvVar = "I2SIG_BEARER_ROTATE_ON_GET"
	// bearerRotateGraceEnvVar sets the deferred-revocation grace window applied to
	// the OLD bearer at rotation (ADR 0022 §2). Default 1h; "0" = immediate.
	bearerRotateGraceEnvVar = "I2SIG_BEARER_ROTATE_GRACE"

	defaultBearerRotateGrace = time.Hour
)

// isTruthy reports whether a configuration string is an affirmative value:
// true / 1 / enabled / yes (case-insensitive). Anything else (including empty)
// is false.
func isTruthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true", "1", "enabled", "yes":
		return true
	default:
		return false
	}
}

// BearerRotateOnGetEnabled reports whether GET-triggered bearer rotation is
// enabled (ADR 0022 §4). Read from I2SIG_BEARER_ROTATE_ON_GET; defaults to false.
// Masking is NOT gated by this flag — only the rotation behavior is.
func BearerRotateOnGetEnabled() bool {
	return isTruthy(os.Getenv(bearerRotateOnGetEnvVar))
}

// BearerRotateGrace returns the deferred-revocation grace window applied to the
// old bearer at rotation (ADR 0022 §2). Read from I2SIG_BEARER_ROTATE_GRACE as a
// Go duration (e.g. "1h", "30m"). Unset or unparseable falls back to 1h; "0"
// (zero) means immediate revocation. A negative value falls back to the default.
func BearerRotateGrace() time.Duration {
	raw := strings.TrimSpace(os.Getenv(bearerRotateGraceEnvVar))
	if raw == "" {
		return defaultBearerRotateGrace
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d < 0 {
		rotateLog.Warn("Invalid I2SIG_BEARER_ROTATE_GRACE; using default", "value", raw, "default", defaultBearerRotateGrace)
		return defaultBearerRotateGrace
	}
	return d
}

// BearerRevoker schedules deferred revocation of a token and reads token records
// for lineage detection. TokenService satisfies it. Keeping this a narrow local
// interface lets the rotation logic stay in pkg/services without coupling to the
// concrete token store.
type BearerRevoker interface {
	// RevokeTokenAt stamps revoked_at to a future instant (deferred) or now/past
	// (immediate), per ADR 0022 §2.
	RevokeTokenAt(ctx context.Context, jti string, at time.Time) error
	// FindByJTI returns the tracked token record, or (nil, nil) when untracked.
	FindByJTI(ctx context.Context, jti string) (*model.TokenRecord, error)
}

// storedBearer locates the active server-issued delivery credential on a record,
// returning the credential and a setter that writes a replacement back onto the
// (mutable) record in the same place. Returns ok=false when the active direction
// carries no rotatable credential. Only the directions this server mints are
// rotatable: poll-transmit, push-receive, and the SSTP RESPONDER bearer. An SSTP
// initiator's stored bearer was minted by the peer (ADR 0022 §1 Guard A out of
// scope here) and is not offered for rotation.
func storedBearer(rec *model.StreamStateRecord) (cred string, set func(string), sstp bool, ok bool) {
	if rec.SstpMethod != nil {
		// Only the responder mints its own pair bearer; an initiator stores a
		// peer-minted bearer and must never self-rotate on a local GET.
		if rec.SstpMethod.Role == model.SstpRoleResponder && rec.SstpMethod.AuthorizationHeader != "" {
			return rec.SstpMethod.AuthorizationHeader, func(v string) { rec.SstpMethod.AuthorizationHeader = v }, true, true
		}
		return "", nil, true, false
	}
	if rec.Delivery == nil {
		return "", nil, false, false
	}
	switch rec.Delivery.GetMethod() {
	case model.DeliveryPoll:
		if m := rec.Delivery.PollTransmitMethod; m != nil && m.AuthorizationHeader != "" {
			return m.AuthorizationHeader, func(v string) { m.AuthorizationHeader = v }, false, true
		}
	case model.ReceivePush:
		if m := rec.Delivery.PushReceiveMethod; m != nil && m.AuthorizationHeader != "" {
			return m.AuthorizationHeader, func(v string) { m.AuthorizationHeader = v }, false, true
		}
	}
	return "", nil, false, false
}

// RotateBearerOnGet implements ADR 0022 §1 rotate-on-GET. When the gate is on and
// the presented Authorization value proves possession of the stream's current
// server-issued bearer, it mints a replacement (preserving scopes/project, bound
// to the stream's id(s), with the old JTI as lineage parent per ADR 0007),
// persists it, and schedules the old token for deferred revocation (ADR 0022 §2).
//
// The returned record always carries the stream's CURRENT (live) bearer. The
// reveal flag tells the caller whether to surface that live value to the client
// (true) or mask it (false). reveal is true in exactly two cases — the two times
// a credential's live value is shown (ADR 0022 §3):
//   - a fresh rotation just happened (this GET minted the replacement); or
//   - the lost-response recovery re-read (ADR 0022 §2): the presented bearer is
//     the now-superseded predecessor of the current one, still valid in the grace
//     window, so the SAME current bearer is returned again without minting a third.
//
// reveal is false (the caller masks) for every other authorized read: gate off,
// an admin/mgmt token (no string match), an EAT not bound to this stream (Guard
// B), or a credential this server did not mint (Guard A).
//
// presented is the raw Authorization header value; presentedEat is the validated
// local EAT (nil for an OAuth/STS caller, which never rotates).
func (s *StreamService) RotateBearerOnGet(ctx context.Context, sid string, presented string, presentedEat *authSupport.EventAuthToken, revoker BearerRevoker) (rec *model.StreamStateRecord, reveal bool, err error) {
	rec, err = s.GetStreamStateBySID(ctx, sid)
	if err != nil {
		return nil, false, err
	}
	if !BearerRotateOnGetEnabled() {
		return rec, false, nil
	}

	cred, set, isSstp, ok := storedBearer(rec)
	if !ok {
		return rec, false, nil
	}

	// Guard B (stream binding): the presented EAT must assert a binding that
	// contains this stream. A management token carrying the empty-StreamIds
	// wildcard is deliberately NOT treated as bound (it never rotates); only a
	// delivery EAT bound to this exact stream qualifies. This is the rotation
	// gate, distinct from the broader read authorization already performed.
	if !eatBoundToStream(presentedEat, sid) {
		return rec, false, nil
	}

	// Proof of possession: constant-time compare the presented Authorization value
	// against the stored credential.
	if subtle.ConstantTimeCompare([]byte(presented), []byte(cred)) != 1 {
		// Not the current bearer. If it is the lost-response re-read (the presented
		// superseded bearer is the lineage parent of the current one), reveal the
		// SAME current bearer again without minting a third credential (ADR 0022 §2).
		if s.isLostResponseReread(ctx, cred, presentedEat, revoker) {
			rotateLog.Info("Lost-response re-read: returning current bearer", "sid", sid)
			return rec, true, nil
		}
		return rec, false, nil
	}

	// Guard A (issuer role): rotation applies only where THIS server minted the
	// stored credential. A peer-supplied opaque bearer (e.g. an SSTP initiator's
	// stored value) does not parse as a locally issued token, so it never rotates
	// even on an exact string match.
	storedJti := localJtiOf(s.keyService.GetAuthIssuer(), cred)
	if storedJti == "" {
		return rec, false, nil
	}

	newHeader, mErr := s.mintReplacementBearer(ctx, rec, isSstp, presentedEat.ID)
	if mErr != nil {
		return rec, false, mErr
	}
	set(newHeader)
	if uErr := s.streamDAO.Update(ctx, rec); uErr != nil {
		return nil, false, uErr
	}

	// Schedule the old token for deferred revocation. grace==0 revokes immediately.
	revokeAt := time.Now().Add(BearerRotateGrace())
	if rErr := revoker.RevokeTokenAt(ctx, storedJti, revokeAt); rErr != nil {
		rotateLog.Warn("Bearer rotated but deferred revocation failed", "sid", sid, "oldJti", storedJti, "error", rErr)
	}
	rotateLog.Info("Bearer rotated on GET", "sid", sid, "oldJti", storedJti, "graceUntil", revokeAt)
	return rec, true, nil
}

// isLostResponseReread reports whether the presented (superseded) bearer is the
// lineage parent of the currently-stored bearer — i.e. a rotation already
// happened and the caller is re-reading with the old credential during the grace
// window (ADR 0022 §2). In that case the SAME current bearer is returned and no
// third credential is minted.
func (s *StreamService) isLostResponseReread(ctx context.Context, currentCred string, presentedEat *authSupport.EventAuthToken, revoker BearerRevoker) bool {
	if presentedEat == nil || revoker == nil {
		return false
	}
	currentJti := localJtiOf(s.keyService.GetAuthIssuer(), currentCred)
	if currentJti == "" {
		return false
	}
	rec, err := revoker.FindByJTI(ctx, currentJti)
	if err != nil || rec == nil {
		return false
	}
	return rec.Parent != "" && rec.Parent == presentedEat.ID
}

// mintReplacementBearer mints a fresh delivery bearer for the rotated stream via
// the same issuing function the create path used, binding it to the stream's
// current id(s) with parentJti as the lineage parent. Returns the "Bearer "
// header value.
func (s *StreamService) mintReplacementBearer(ctx context.Context, rec *model.StreamStateRecord, isSstp bool, parentJti string) (string, error) {
	issuer := s.keyService.GetAuthIssuer()
	// The lineage-parent session carries only the old JTI as the parent id
	// (mirroring the CreateStream deliveryParent shape); other claims are minted
	// fresh, so scopes/project come from the issuing function, not the old token.
	session := &authSupport.AuthContext{Eat: &authSupport.EventAuthToken{}}
	session.Eat.ID = parentJti

	if isSstp {
		// SSTP responder pair bearer binds [txSid (== PairId), rxSid (inbound SID)].
		txSid := rec.PairId
		rxSid := ""
		if rec.SstpInbound != nil {
			rxSid = rec.SstpInbound.Id
		}
		token, err := issuer.IssueSstpPairToken(txSid, rxSid, rec.ProjectId, false, session)
		if err != nil {
			return "", err
		}
		return "Bearer " + token, nil
	}

	token, err := issuer.IssueStreamToken(rec.StreamConfiguration.Id, rec.ProjectId, session)
	if err != nil {
		return "", err
	}
	return "Bearer " + token, nil
}

// eatBoundToStream reports whether the validated local EAT asserts a stream
// binding that contains sid. An EAT with no StreamIds (the management wildcard)
// is NOT considered bound — rotation can only tighten, never widen, the binding
// (ADR 0022 §1 Guard B). A nil EAT (OAuth/STS caller) is never bound.
func eatBoundToStream(eat *authSupport.EventAuthToken, sid string) bool {
	if eat == nil || len(eat.StreamIds) == 0 || sid == "" {
		return false
	}
	for _, s := range eat.StreamIds {
		if strings.EqualFold(s, sid) {
			return true
		}
	}
	return false
}

// localJtiOf parses a stored "Bearer <jwt>" credential as a locally issued token
// and returns its JTI, or "" when the credential was not minted by this server's
// issuer (the issuer-role guard, ADR 0022 §1 Guard A). The constant-time match
// already proved the value; this confirms provenance and recovers the JTI for
// lineage/revocation.
func localJtiOf(issuer *authSupport.AuthIssuer, cred string) string {
	if issuer == nil {
		return ""
	}
	tok := strings.TrimSpace(strings.TrimPrefix(cred, "Bearer "))
	if tok == "" {
		return ""
	}
	eat, err := issuer.ParseAuthTokenVerbose(tok, false)
	if err != nil || eat == nil {
		return ""
	}
	return eat.ID
}
