// Package events contains event-profile helpers for Security Event Tokens.
package events

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/i2-open/i2goSignals/pkg/goSet"
)

// WISEEventPrefix is the event-type URI prefix currently used by the proposed
// Workload Identity Security Events (WISE) profile.
//
// WISE is a proposed profile, not an adopted OpenID specification. These
// helpers deliberately classify only the initial high-priority events below;
// callers remain responsible for transport, issuer/audience validation,
// replay handling, authorization and all operational policy.
const WISEEventPrefix = "https://schemas.openid.net/secevent/wise/event-type/"

const (
	WISECredentialRevokedURI    = WISEEventPrefix + "credential-revoked"
	WISECredentialCompromiseURI = WISEEventPrefix + "credential-compromise"
	WISETrustAnchorChangedURI   = WISEEventPrefix + "trust-anchor-changed"
	WISEWorkloadCompromisedURI  = WISEEventPrefix + "workload-compromised"
)

var (
	// ErrUnsupportedWISEEvent means that a SET contains an event outside this
	// deliberately small semantic profile. It is not a conclusion that the SET
	// is invalid under WISE; a Receiver may support additional events.
	ErrUnsupportedWISEEvent = errors.New("unsupported WISE event")

	// ErrInvalidWISEEvent means a supported event is missing a required field or
	// has a subject that cannot be interpreted by this profile helper.
	ErrInvalidWISEEvent = errors.New("invalid WISE event")
)

// WISERecommendedAction is receiver-local guidance derived from an event's
// meaning. It is not an instruction from the transmitter, an authority grant,
// or evidence that any action occurred.
type WISERecommendedAction string

const (
	WISEActionIsolateOrRevokeCredentials  WISERecommendedAction = "receiver_local_isolate_or_revoke_credentials"
	WISEActionHoldAndRevalidateCredential WISERecommendedAction = "receiver_local_hold_and_revalidate_credential"
	WISEActionRevalidateCredential        WISERecommendedAction = "receiver_local_revalidate_credential"
	WISEActionRefreshTrustMaterial        WISERecommendedAction = "receiver_local_refresh_trust_material"
	WISEActionRefreshAndRejectRevokedKey  WISERecommendedAction = "receiver_local_refresh_and_reject_revoked_key"
)

// WISEEvent is the semantic result for one supported event in a previously
// verified SET. Subject is the URI payload value, not a stable internal handle.
type WISEEvent struct {
	Type              string
	Subject           string
	RecommendedAction WISERecommendedAction
}

// ParseWISESET validates and classifies the supported WISE event payloads in a
// previously verified SET. The caller must verify the JWS and SET envelope
// before using this function, for example through goSetPoll.Poll.
//
// The proposed WISE profile describes URI as its primary workload subject
// identifier format. URI schemes such as wimse, spiffe and https are accepted;
// no receiver-scoped opaque-subject profile is inferred here.
func ParseWISESET(set *goSet.SecurityEventToken) ([]WISEEvent, error) {
	if set == nil || len(set.Events) == 0 {
		return nil, fmt.Errorf("%w: SET has no events", ErrInvalidWISEEvent)
	}

	parsed := make([]WISEEvent, 0, len(set.Events))
	for eventURI, rawPayload := range set.Events {
		payload, ok := rawPayload.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("%w: %s payload is not an object", ErrInvalidWISEEvent, eventURI)
		}
		subject, err := wiseURISubject(payload)
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %v", ErrInvalidWISEEvent, eventURI, err)
		}

		finding, err := classifyWISEEvent(eventURI, subject, payload)
		if err != nil {
			return nil, err
		}
		parsed = append(parsed, finding)
	}
	return parsed, nil
}

// ValidateWISESET is suitable for goSetPoll.ReceiverConfig.SETValidator. It
// performs no policy action; it only rejects malformed or unsupported event
// payloads for a Receiver that explicitly opts into this limited WISE profile.
func ValidateWISESET(set *goSet.SecurityEventToken) error {
	_, err := ParseWISESET(set)
	return err
}

func classifyWISEEvent(eventURI, subject string, payload map[string]interface{}) (WISEEvent, error) {
	finding := WISEEvent{Type: eventURI, Subject: subject}
	switch eventURI {
	case WISEWorkloadCompromisedURI:
		// WISE describes this as high severity and says it SHOULD trigger
		// immediate isolation or credential revocation. The exact choice stays
		// with the Receiver's local policy.
		finding.RecommendedAction = WISEActionIsolateOrRevokeCredentials
	case WISECredentialCompromiseURI:
		if !nonEmptyString(payload, "credential_type") {
			return WISEEvent{}, fmt.Errorf("%w: credential_type is required", ErrInvalidWISEEvent)
		}
		finding.RecommendedAction = WISEActionHoldAndRevalidateCredential
	case WISECredentialRevokedURI:
		if !nonEmptyString(payload, "credential_type") {
			return WISEEvent{}, fmt.Errorf("%w: credential_type is required", ErrInvalidWISEEvent)
		}
		reason, _ := payload["reason"].(string)
		if reason == "compromise" || reason == "key_compromise" {
			finding.RecommendedAction = WISEActionHoldAndRevalidateCredential
		} else {
			finding.RecommendedAction = WISEActionRevalidateCredential
		}
	case WISETrustAnchorChangedURI:
		if !nonEmptyString(payload, "anchor_type") || !nonEmptyString(payload, "change_type") || !nonEmptyString(payload, "trust_domain") {
			return WISEEvent{}, fmt.Errorf("%w: anchor_type, change_type and trust_domain are required", ErrInvalidWISEEvent)
		}
		anchorType, _ := payload["anchor_type"].(string)
		if !oneOf(anchorType, "jwks", "x509_ca") {
			return WISEEvent{}, fmt.Errorf("%w: unsupported anchor_type %q", ErrInvalidWISEEvent, anchorType)
		}
		changeType, _ := payload["change_type"].(string)
		if !oneOf(changeType, "key_added", "key_rotated", "key_revoked", "key_expired", "full_replacement") {
			return WISEEvent{}, fmt.Errorf("%w: unsupported change_type %q", ErrInvalidWISEEvent, changeType)
		}
		if changeType == "key_revoked" {
			finding.RecommendedAction = WISEActionRefreshAndRejectRevokedKey
		} else {
			finding.RecommendedAction = WISEActionRefreshTrustMaterial
		}
	default:
		return WISEEvent{}, fmt.Errorf("%w: %s", ErrUnsupportedWISEEvent, eventURI)
	}
	return finding, nil
}

func wiseURISubject(payload map[string]interface{}) (string, error) {
	rawSubject, ok := payload["subject"].(map[string]interface{})
	if !ok {
		return "", errors.New("subject must be an object")
	}
	if rawSubject["format"] != "uri" {
		return "", errors.New("subject format must be uri")
	}
	uri, ok := rawSubject["uri"].(string)
	if !ok || strings.TrimSpace(uri) == "" {
		return "", errors.New("subject uri is required")
	}
	parsed, err := url.ParseRequestURI(uri)
	if err != nil || parsed.Scheme == "" {
		return "", errors.New("subject uri is not an absolute URI")
	}
	return uri, nil
}

func nonEmptyString(payload map[string]interface{}, name string) bool {
	value, ok := payload[name].(string)
	return ok && strings.TrimSpace(value) != ""
}

func oneOf(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}
