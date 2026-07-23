package events

import (
	"errors"
	"testing"

	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func wiseSET(eventURI string, payload map[string]interface{}) *goSet.SecurityEventToken {
	return &goSet.SecurityEventToken{Events: map[string]interface{}{eventURI: payload}}
}

func wiseSubject(uri string) map[string]interface{} {
	return map[string]interface{}{"format": "uri", "uri": uri}
}

func TestParseWISESETWorkloadCompromised(t *testing.T) {
	findings, err := ParseWISESET(wiseSET(WISEWorkloadCompromisedURI, map[string]interface{}{
		"subject":          wiseSubject("wimse://trust.example/workload/payment-service"),
		"detection_method": "runtime-monitor",
	}))

	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, WISEActionIsolateOrRevokeCredentials, findings[0].RecommendedAction)
	assert.Equal(t, "wimse://trust.example/workload/payment-service", findings[0].Subject)
}

func TestParseWISESETAcceptsPrimaryURIFormats(t *testing.T) {
	for _, subject := range []string{
		"wimse://trust.example/workload/payment-service",
		"spiffe://trust.example/ns/prod/sa/payment-service",
		"https://client.example/.well-known/oauth-client",
	} {
		t.Run(subject, func(t *testing.T) {
			_, err := ParseWISESET(wiseSET(WISEWorkloadCompromisedURI, map[string]interface{}{"subject": wiseSubject(subject)}))
			require.NoError(t, err)
		})
	}
}

func TestParseWISESETCredentialRequiresType(t *testing.T) {
	_, err := ParseWISESET(wiseSET(WISECredentialCompromiseURI, map[string]interface{}{
		"subject": wiseSubject("wimse://trust.example/workload/payment-service"),
	}))

	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidWISEEvent))
}

func TestParseWISESETCredentialRevokedByCompromise(t *testing.T) {
	findings, err := ParseWISESET(wiseSET(WISECredentialRevokedURI, map[string]interface{}{
		"subject":         wiseSubject("wimse://trust.example/workload/payment-service"),
		"credential_type": "wic",
		"reason":          "key_compromise",
	}))

	require.NoError(t, err)
	assert.Equal(t, WISEActionHoldAndRevalidateCredential, findings[0].RecommendedAction)
}

func TestParseWISESETTrustAnchorRevoked(t *testing.T) {
	findings, err := ParseWISESET(wiseSET(WISETrustAnchorChangedURI, map[string]interface{}{
		"subject":      wiseSubject("wimse://trust.example"),
		"anchor_type":  "jwks",
		"change_type":  "key_revoked",
		"trust_domain": "trust.example",
	}))

	require.NoError(t, err)
	assert.Equal(t, WISEActionRefreshAndRejectRevokedKey, findings[0].RecommendedAction)
}

func TestParseWISESETTrustAnchorRejectsUnknownValues(t *testing.T) {
	_, err := ParseWISESET(wiseSET(WISETrustAnchorChangedURI, map[string]interface{}{
		"subject":      wiseSubject("wimse://trust.example"),
		"anchor_type":  "unknown",
		"change_type":  "key_rotated",
		"trust_domain": "trust.example",
	}))
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidWISEEvent))
}

func TestParseWISESETRejectsOpaqueSubjectAndUnknownEvent(t *testing.T) {
	_, err := ParseWISESET(wiseSET(WISEWorkloadCompromisedURI, map[string]interface{}{
		"subject": map[string]interface{}{"format": "opaque", "id": "receiver-local"},
	}))
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidWISEEvent))

	_, err = ParseWISESET(wiseSET(WISEEventPrefix+"not-yet-supported", map[string]interface{}{
		"subject": wiseSubject("wimse://trust.example/workload/payment-service"),
	}))
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUnsupportedWISEEvent))
}
