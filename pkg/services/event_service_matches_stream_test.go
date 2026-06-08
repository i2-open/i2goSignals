package services

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
)

const (
	typeAcctDisabled = "https://schemas.openid.net/secevent/risc/event-type/account-disabled"
	typeAcctEnabled  = "https://schemas.openid.net/secevent/risc/event-type/account-enabled"
)

func newEvent(iss string, aud []string, types ...string) *model.AgEventRecord {
	return &model.AgEventRecord{
		Event: goSet.SecurityEventToken{
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:   iss,
				Audience: jwt.ClaimStrings(aud),
			},
		},
		Types: types,
	}
}

func newStream(iss string, aud []string, delivered ...string) *model.StreamStateRecord {
	return &model.StreamStateRecord{
		StreamConfiguration: model.StreamConfiguration{
			Iss:             iss,
			Aud:             aud,
			EventsDelivered: delivered,
		},
	}
}

func TestMatchesStream_IssuerExactMatch(t *testing.T) {
	svc := NewEventService(nil)
	stream := newStream("https://issuer.example.com", nil, typeAcctDisabled)
	event := newEvent("https://issuer.example.com", nil, typeAcctDisabled)

	assert.True(t, svc.MatchesStream(stream, event), "matching issuer + type should match")
}

func TestMatchesStream_IssuerMismatchRejects(t *testing.T) {
	svc := NewEventService(nil)
	stream := newStream("https://issuer.example.com", nil, typeAcctDisabled)
	event := newEvent("https://other.example.com", nil, typeAcctDisabled)

	assert.False(t, svc.MatchesStream(stream, event), "non-matching issuer should not match")
}

func TestMatchesStream_EmptyStreamIssuerIsWildcard(t *testing.T) {
	svc := NewEventService(nil)
	stream := newStream("", nil, typeAcctDisabled)
	event := newEvent("https://any.example.com", nil, typeAcctDisabled)

	assert.True(t, svc.MatchesStream(stream, event), "empty stream issuer should match any event issuer")
}

func TestMatchesStream_EmptyEventIssuerIsWildcard(t *testing.T) {
	svc := NewEventService(nil)
	stream := newStream("https://issuer.example.com", nil, typeAcctDisabled)
	event := newEvent("", nil, typeAcctDisabled)

	assert.True(t, svc.MatchesStream(stream, event), "empty event issuer should match a constrained stream")
}

func TestMatchesStream_AudienceOverlap(t *testing.T) {
	svc := NewEventService(nil)
	stream := newStream(
		"",
		[]string{"https://a.example.com", "https://b.example.com"},
		typeAcctDisabled,
	)
	event := newEvent("", []string{"https://b.example.com", "https://c.example.com"}, typeAcctDisabled)

	assert.True(t, svc.MatchesStream(stream, event), "any audience overlap should match")
}

func TestMatchesStream_AudienceDisjointRejects(t *testing.T) {
	svc := NewEventService(nil)
	stream := newStream("", []string{"https://a.example.com"}, typeAcctDisabled)
	event := newEvent("", []string{"https://b.example.com"}, typeAcctDisabled)

	assert.False(t, svc.MatchesStream(stream, event), "disjoint audiences should not match")
}

func TestMatchesStream_EmptyEventAudienceIsWildcard(t *testing.T) {
	svc := NewEventService(nil)
	stream := newStream("", []string{"https://a.example.com"}, typeAcctDisabled)
	event := newEvent("", nil, typeAcctDisabled)

	assert.True(t, svc.MatchesStream(stream, event), "empty event audience should match a constrained stream")
}

func TestMatchesStream_ReceiverImportShortCircuits(t *testing.T) {
	svc := NewEventService(nil)
	stream := &model.StreamStateRecord{
		StreamConfiguration: model.StreamConfiguration{
			Iss:             "",
			Aud:             nil,
			EventsDelivered: []string{typeAcctDisabled},
			RouteMode:       model.RouteModeImport,
			Delivery: &model.OneOfStreamConfigurationDelivery{
				PushReceiveMethod: &model.PushReceiveMethod{Method: model.ReceivePush},
			},
		},
	}
	event := newEvent("", nil, typeAcctDisabled)

	assert.False(t, svc.MatchesStream(stream, event),
		"receiver stream in RouteModeImport must short-circuit to false even when iss/aud/type would match")
}

func TestMatchesStream_ReceiverForwardStillMatches(t *testing.T) {
	svc := NewEventService(nil)
	stream := &model.StreamStateRecord{
		StreamConfiguration: model.StreamConfiguration{
			EventsDelivered: []string{typeAcctDisabled},
			RouteMode:       model.RouteModeForward,
			Delivery: &model.OneOfStreamConfigurationDelivery{
				PushReceiveMethod: &model.PushReceiveMethod{Method: model.ReceivePush},
			},
		},
	}
	event := newEvent("", nil, typeAcctDisabled)

	assert.True(t, svc.MatchesStream(stream, event),
		"receiver stream not in Import mode is not short-circuited; iss/aud/type predicate applies")
}

func TestMatchesStream_EventTypeNotDeliveredRejects(t *testing.T) {
	svc := NewEventService(nil)
	stream := newStream("", nil, typeAcctDisabled)
	event := newEvent("", nil, typeAcctEnabled)

	assert.False(t, svc.MatchesStream(stream, event),
		"event type not in EventsDelivered should not match")
}

func TestMatchesStream_EventTypeCaseInsensitive(t *testing.T) {
	svc := NewEventService(nil)
	upper := "HTTPS://schemas.openid.net/SECEVENT/risc/event-type/account-disabled"
	stream := newStream("", nil, typeAcctDisabled)
	event := newEvent("", nil, upper)

	assert.True(t, svc.MatchesStream(stream, event),
		"event-type comparison must be case-insensitive (strings.EqualFold)")
}
