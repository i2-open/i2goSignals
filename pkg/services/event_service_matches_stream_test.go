package services

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	typeAcctDisabled = "https://schemas.openid.net/secevent/risc/event-type/account-disabled"
	typeAcctEnabled  = "https://schemas.openid.net/secevent/risc/event-type/account-enabled"
)

func newEvent(iss string, aud []string, types ...string) *model.EventRecord {
	return &model.EventRecord{
		Event: goSet.SecurityEventToken{
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:   iss,
				Audience: jwt.ClaimStrings(aud),
			},
		},
		Types: types,
	}
}

// newEventFromSid builds an inbound event record tagged with the origin stream
// SID (EventRecord.Sid) so EXPLICIT routing can be exercised.
func newEventFromSid(sid string, iss string, aud []string, types ...string) *model.EventRecord {
	rec := newEvent(iss, aud, types...)
	rec.Sid = sid
	return rec
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

// --- EventSource-aware routing (issue #199) --------------------------------

// withEventSource returns a copy of the stream tagged with an EventSource of
// the given type (and optional source stream ids for EXPLICIT).
func withEventSource(stream *model.StreamStateRecord, esType string, sourceStreamIds ...string) *model.StreamStateRecord {
	stream.EventSource = &model.EventSource{
		Type:            esType,
		SourceStreamIds: sourceStreamIds,
	}
	return stream
}

// TestMatchesStream_DirectUnchanged: an explicit DIRECT EventSource preserves
// the historical (iss, aud, event-type) predicate exactly.
func TestMatchesStream_DirectUnchanged(t *testing.T) {
	svc := NewEventService(nil)

	t.Run("aud overlap matches", func(t *testing.T) {
		stream := withEventSource(newStream("", []string{"https://a.example.com"}, typeAcctDisabled), model.EventSourceDirect)
		event := newEvent("", []string{"https://a.example.com"}, typeAcctDisabled)
		assert.True(t, svc.MatchesStream(stream, event))
	})

	t.Run("aud disjoint rejects", func(t *testing.T) {
		stream := withEventSource(newStream("", []string{"https://a.example.com"}, typeAcctDisabled), model.EventSourceDirect)
		event := newEvent("", []string{"https://b.example.com"}, typeAcctDisabled)
		assert.False(t, svc.MatchesStream(stream, event),
			"DIRECT keeps the historical aud-disjoint rejection")
	})

	t.Run("type mismatch rejects", func(t *testing.T) {
		stream := withEventSource(newStream("", nil, typeAcctDisabled), model.EventSourceDirect)
		event := newEvent("", nil, typeAcctEnabled)
		assert.False(t, svc.MatchesStream(stream, event))
	})
}

// TestMatchesStream_NilEventSourceBehavesAsDirect: a nil/unset EventSource
// resolves to effective DIRECT for routing — identical predicate behavior.
func TestMatchesStream_NilEventSourceBehavesAsDirect(t *testing.T) {
	svc := NewEventService(nil)

	// nil EventSource + aud overlap matches.
	streamMatch := newStream("", []string{"https://a.example.com"}, typeAcctDisabled)
	require.Nil(t, streamMatch.EventSource)
	assert.True(t, svc.MatchesStream(streamMatch, newEvent("", []string{"https://a.example.com"}, typeAcctDisabled)))

	// nil EventSource + aud disjoint rejects (DIRECT semantics, not AUDIENCE).
	streamReject := newStream("", []string{"https://a.example.com"}, typeAcctDisabled)
	require.Nil(t, streamReject.EventSource)
	assert.False(t, svc.MatchesStream(streamReject, newEvent("", []string{"https://b.example.com"}, typeAcctDisabled)),
		"nil EventSource must NOT relax the aud filter (it is effective DIRECT, not AUDIENCE)")
}

// TestMatchesStream_AudienceMatchesDespiteInboundAudDiffers is the core slice
// behavior: an AUDIENCE stream routes by its own aud handle even when the
// inbound event's aud differs from it.
func TestMatchesStream_AudienceMatchesDespiteInboundAudDiffers(t *testing.T) {
	svc := NewEventService(nil)
	stream := withEventSource(
		newStream("", []string{"https://downstream.example.com"}, typeAcctDisabled),
		model.EventSourceAudience,
	)
	// Inbound aud is a completely different handle.
	event := newEvent("", []string{"https://inbound.example.com"}, typeAcctDisabled)

	assert.True(t, svc.MatchesStream(stream, event),
		"AUDIENCE must match on the stream's aud handle even when the inbound aud differs")
}

// TestMatchesStream_AudienceStillRequiresEventType: relaxing aud does not relax
// the event-type filter.
func TestMatchesStream_AudienceStillRequiresEventType(t *testing.T) {
	svc := NewEventService(nil)
	stream := withEventSource(
		newStream("", []string{"https://downstream.example.com"}, typeAcctDisabled),
		model.EventSourceAudience,
	)
	event := newEvent("", []string{"https://inbound.example.com"}, typeAcctEnabled)

	assert.False(t, svc.MatchesStream(stream, event),
		"AUDIENCE relaxes only the aud filter; the event-type filter still applies")
}

// TestMatchesStream_ExplicitMatchesOnSourceStreamId: EXPLICIT routes when the
// inbound event's origin SID is in SourceStreamIds.
func TestMatchesStream_ExplicitMatchesOnSourceStreamId(t *testing.T) {
	svc := NewEventService(nil)
	stream := withEventSource(
		newStream("", nil, typeAcctDisabled),
		model.EventSourceExplicit, "src-stream-1", "src-stream-2",
	)
	event := newEventFromSid("src-stream-2", "", nil, typeAcctDisabled)

	assert.True(t, svc.MatchesStream(stream, event),
		"EXPLICIT must match when EventRecord.Sid is in SourceStreamIds")
}

// TestMatchesStream_ExplicitRejectsUnlistedSid: EXPLICIT rejects an event whose
// origin SID is not named in SourceStreamIds.
func TestMatchesStream_ExplicitRejectsUnlistedSid(t *testing.T) {
	svc := NewEventService(nil)
	stream := withEventSource(
		newStream("", nil, typeAcctDisabled),
		model.EventSourceExplicit, "src-stream-1",
	)
	event := newEventFromSid("some-other-stream", "", nil, typeAcctDisabled)

	assert.False(t, svc.MatchesStream(stream, event),
		"EXPLICIT must reject an event whose origin SID is not in SourceStreamIds")
}

// TestMatchesStream_ExplicitStillRequiresEventType: EXPLICIT SID membership does
// not bypass the event-type filter.
func TestMatchesStream_ExplicitStillRequiresEventType(t *testing.T) {
	svc := NewEventService(nil)
	stream := withEventSource(
		newStream("", nil, typeAcctDisabled),
		model.EventSourceExplicit, "src-stream-1",
	)
	event := newEventFromSid("src-stream-1", "", nil, typeAcctEnabled)

	assert.False(t, svc.MatchesStream(stream, event),
		"EXPLICIT matches on SID but the event-type filter still applies")
}

// --- FW/PB iss rule (issue #199) -------------------------------------------

// newStreamWithMode builds a transmitter stream with a RouteMode set.
func newStreamWithMode(routeMode string, iss string, aud []string, delivered ...string) *model.StreamStateRecord {
	stream := newStream(iss, aud, delivered...)
	stream.RouteMode = routeMode
	return stream
}

// TestMatchesStream_ForwardRequiresIssMatch: in FW mode iss matching is
// mandatory — a mismatching issuer rejects.
func TestMatchesStream_ForwardRequiresIssMatch(t *testing.T) {
	svc := NewEventService(nil)

	t.Run("iss match routes", func(t *testing.T) {
		stream := newStreamWithMode(model.RouteModeForward, "https://issuer.example.com", nil, typeAcctDisabled)
		event := newEvent("https://issuer.example.com", nil, typeAcctDisabled)
		assert.True(t, svc.MatchesStream(stream, event))
	})

	t.Run("iss mismatch rejects", func(t *testing.T) {
		stream := newStreamWithMode(model.RouteModeForward, "https://issuer.example.com", nil, typeAcctDisabled)
		event := newEvent("https://other.example.com", nil, typeAcctDisabled)
		assert.False(t, svc.MatchesStream(stream, event),
			"FW mode must require an iss match")
	})
}

// TestMatchesStream_PublishIgnoresIss: in PB mode iss matching is ignored — a
// mismatching issuer still routes (aud/type permitting).
func TestMatchesStream_PublishIgnoresIss(t *testing.T) {
	svc := NewEventService(nil)
	stream := newStreamWithMode(model.RouteModePublish, "https://issuer.example.com", nil, typeAcctDisabled)
	event := newEvent("https://completely-different.example.com", nil, typeAcctDisabled)

	assert.True(t, svc.MatchesStream(stream, event),
		"PB mode must ignore the iss filter")
}
