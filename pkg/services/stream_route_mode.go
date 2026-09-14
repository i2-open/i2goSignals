package services

import (
	"context"
	"fmt"
	"slices"

	"github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// Stream update support for the goSignals-specific settings that were
// create-only before issue #306: route_mode, iss, aud and the issuer JWKS URL.
// They are patchable on every delivery method and on each SSTP side by its own
// SID; route_mode is validated against the direction's role because the two
// roles read the field differently (a transmitter tests == FW to decide
// forward-vs-sign, a receiver tests == IM to decide consume-vs-route), so a
// value from the wrong vocabulary is silently mis-read rather than rejected —
// IM on a transmitter, for one, signs with no key and emits an empty token.

// validateRouteModeForRole rejects a route_mode outside the direction's
// vocabulary: PB|FW for a transmit direction, IM|FW for a receive direction.
// Empty is "not patched" and always passes. The rejection wraps
// ErrInvalidRequest so the HTTP layer answers 400, and names the field.
func validateRouteModeForRole(mode string, transmitter bool) error {
	if mode == "" {
		return nil
	}
	if transmitter {
		if mode == model.RouteModePublish || mode == model.RouteModeForward {
			return nil
		}
		return fmt.Errorf("%w: route_mode %q is not valid for a transmitter (accepted: %s, %s)",
			ErrInvalidRequest, mode, model.RouteModePublish, model.RouteModeForward)
	}
	if mode == model.RouteModeImport || mode == model.RouteModeForward {
		return nil
	}
	return fmt.Errorf("%w: route_mode %q is not valid for a receiver (accepted: %s, %s)",
		ErrInvalidRequest, mode, model.RouteModeImport, model.RouteModeForward)
}

// applyStreamIdentityPatch copies route_mode, iss, aud and the issuer JWKS URL
// from patch onto target under the update path's "empty means unchanged" rule.
// It reports whether the target's verification inputs (iss, JWKS URL) changed,
// which is what decides whether a receive direction's cache entry must be
// re-resolved. The route_mode value is assumed already validated for the
// target's role.
func applyStreamIdentityPatch(target *model.StreamConfiguration, patch model.StreamConfiguration) (verifyChanged bool) {
	if patch.RouteMode != "" {
		target.RouteMode = patch.RouteMode
	}
	if patch.Iss != "" && patch.Iss != target.Iss {
		target.Iss = patch.Iss
		verifyChanged = true
	}
	if len(patch.Aud) > 0 {
		target.Aud = slices.Clone(patch.Aud)
	}
	if patch.IssuerJWKSUrl != "" && normalizedJwksUrl(patch.IssuerJWKSUrl) != normalizedJwksUrl(target.IssuerJWKSUrl) {
		target.IssuerJWKSUrl = patch.IssuerJWKSUrl
		verifyChanged = true
	}
	return verifyChanged
}

// refreshReceiverEntry re-resolves the receive direction of rec and installs
// the result in the receiver cache, replacing whatever entry the direction had.
// The cache holds its own copy of the record plus the resolved JWKS (ADR 0033),
// so a persisted iss / JWKS URL change that stopped at the DAO would never be
// seen by verification until a restart. Resolution runs before the swap, as
// CreateStream does, so an unreachable endpoint records the direction
// unresolved (on the retry ladder) rather than caching a resolved-nil. rec is
// copied so the caller's record is not captured by the cache.
//
// A record with no receive direction (a transmitter, or a pair with no inbound
// half) is a no-op.
func (s *StreamService) refreshReceiverEntry(ctx context.Context, rec *model.StreamStateRecord) {
	snap := snapshotReceiveDirection(rec)
	if !snap.present || snap.sid == "" {
		return
	}
	view := *rec
	entry := s.newReceiverEntry(ctx, &view)
	s.mu.Lock()
	displaced := s.receiverStreams[snap.sid]
	s.receiverStreams[snap.sid] = entry
	s.mu.Unlock()
	// The displaced entry's keyfunc refresher would otherwise outlive it (GH #290).
	displaced.endBackground()
	ssLog.Debug("Receiver verification material refreshed after update", "sid", snap.sid, "iss", snap.iss)
}
