package services

import (
	"context"
	"errors"
	"fmt"

	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// NoActiveSigningKeyReason names the issuer and signature algorithm a signing
// transmitter has no active key for (#308). It is the save-time rejection
// message and the push runner's paused/disabled reason, so an operator reads the
// same words wherever the problem surfaces. It deliberately does not say whether
// the key was never created, or is suspended or revoked.
func NoActiveSigningKeyReason(issuer, signingAlg string) string {
	return fmt.Sprintf("no active signing key for issuer %s (%s)", issuer, algLabel(signingAlg))
}

// SigningKeyUnavailableReason is NoActiveSigningKeyReason, followed by the
// expired or not-yet-valid key and its time when a validity period is why the
// issuer has no active key (#318): the operator, and a receiver reading the
// stream status, need the time to tell an expiry from a future key. It is the
// save-time rejection and every key-unavailable pause's reason.
func (s *StreamService) SigningKeyUnavailableReason(ctx context.Context, issuer, signingAlg string) string {
	reason := NoActiveSigningKeyReason(issuer, signingAlg)
	if s == nil || s.keyService == nil {
		return reason
	}
	if detail := s.keyService.signingKeyUnavailableDetail(ctx, issuer, signingAlg); detail != "" {
		reason += "; " + detail
	}
	return reason
}

// signingTransmitterConfig returns the configuration of rec's signing transmit
// direction, or nil when rec has none. A signing transmitter is any transmitter
// not in Forward mode, an empty route mode counting as Publish: a push or poll
// transmitter, or an SSTP pair's primary (transmit) half. A receiver signs
// nothing; its iss names the remote transmitter.
func signingTransmitterConfig(rec *model.StreamStateRecord) *model.StreamConfiguration {
	if rec == nil {
		return nil
	}
	cfg := &rec.StreamConfiguration
	if rec.GetType() != model.DeliverySstpPair {
		switch cfg.Delivery.GetMethod() {
		case model.DeliveryPush, model.DeliveryPoll:
		default:
			return nil
		}
	}
	if cfg.RouteMode == model.RouteModeForward {
		return nil
	}
	return cfg
}

// requireActiveKeyFor refuses a signing transmitter configuration whose iss and
// signing_alg have no active signing key. The test is KeyService.GetSigner,
// which never selects a suspended or revoked key. A missing key is the caller's
// to fix, so it wraps ErrInvalidRequest (400); a key store that could not answer
// is not, and is returned as is.
func (s *StreamService) requireActiveKeyFor(ctx context.Context, cfg *model.StreamConfiguration) error {
	if cfg == nil || s.keyService == nil {
		return nil
	}
	rec, _, err := s.keyService.signingRecFor(ctx, cfg.Iss, cfg.SigningAlg)
	if err == nil {
		_, _, err = parseSigningRec(rec)
	}
	if err != nil {
		if errors.Is(err, interfaces.ErrKeyNotFound) {
			return fmt.Errorf("%w: %s", ErrInvalidRequest, s.SigningKeyUnavailableReason(ctx, cfg.Iss, cfg.SigningAlg))
		}
		return fmt.Errorf("checking the signing key for issuer %s: %w", cfg.Iss, err)
	}
	// Saving or enabling a stream whose key expires soon succeeds, with the
	// same WARN the background check logs (#318).
	s.keyService.warnIfExpiringSoon(rec, s.keyService.clock())
	return nil
}

// RequireActiveSigningKey is the save-time and re-enable check of #308: when rec
// is a signing transmitter it must have an active signing key for its iss and
// signing_alg, or the change is refused with an ErrInvalidRequest naming the
// issuer and algorithm. Stream create and update, SSTP pair creation, and a
// status update to enabled run it against the stream as it would be after the
// change. A Forward transmitter or a receiver always passes.
func (s *StreamService) RequireActiveSigningKey(ctx context.Context, rec *model.StreamStateRecord) error {
	return s.requireActiveKeyFor(ctx, signingTransmitterConfig(rec))
}
