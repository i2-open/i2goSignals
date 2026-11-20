package goSetValidate

import (
	"testing"

	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/goSet/events"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testStreamId = "f67e39a0a4d34d56b3aa1bc4cff0069f"

// setWithStreamSubject builds the SET envelope both SSF stream-management events
// require: a top-level sub_id of format "opaque" carrying the stream id
// (SSF §8.1.4.1, §8.1.5).
func setWithStreamSubject(streamId string) *goSet.SecurityEventToken {
	subject := &goSet.EventSubject{
		SubjectIdentifier: goSet.SubjectIdentifier{
			Format:           "opaque",
			OpaqueIdentifier: goSet.OpaqueIdentifier{Id: streamId},
		},
	}
	set := goSet.CreateSet(subject, "https://transmitter.example.com", []string{"receiver.example.com"})
	return &set
}

func TestValidatorSet_NilReceiverReportsValid(t *testing.T) {
	set := setWithStreamSubject(testStreamId)
	set.AddEventPayload(fakeVocabularyUri, map[string]any{"anything": true})

	result := (*ValidatorSet)(nil).Validate(set)
	assert.Equal(t, Valid, result.Disposition)
	assert.Nil(t, result.Results)
}

func TestValidatorSet_NilSetReportsValid(t *testing.T) {
	vs := NewValidatorSet(BuiltinRegistry(), nil)
	result := vs.Validate(nil)
	assert.Equal(t, Valid, result.Disposition)
	assert.Nil(t, result.Results)
}

func TestValidatorSet_EmptyEventsReportsValid(t *testing.T) {
	vs := NewValidatorSet(BuiltinRegistry(), nil)
	result := vs.Validate(setWithStreamSubject(testStreamId))
	assert.Equal(t, Valid, result.Disposition)
	assert.Empty(t, result.Results)
}

// TestValidatorSet_EngagedAndValid is the ordinary in-contract path.
func TestValidatorSet_EngagedAndValid(t *testing.T) {
	set := events.CreateVerifyEvent(testStreamId, "opaque-state", "https://transmitter.example.com", []string{"receiver.example.com"})

	vs := NewValidatorSet(BuiltinRegistry(), []string{SsfVerificationEventUri})
	result := vs.Validate(set)

	assert.Equal(t, Valid, result.Disposition)
	require.Len(t, result.Results, 1)
	assert.Equal(t, SsfVerificationEventUri, result.Results[0].EventURI)
	assert.Equal(t, Valid, result.Results[0].Disposition)
	assert.Empty(t, result.Results[0].Claim)
	assert.Empty(t, result.Results[0].Detail)
}

// TestValidatorSet_OutOfContractIsUnsupported pins the ADR decision that
// out-of-contract (matching no negotiated events_delivered pattern) is identical
// to unsupported.
func TestValidatorSet_OutOfContractIsUnsupported(t *testing.T) {
	set := setWithStreamSubject(testStreamId)
	set.AddEventPayload(fakeVocabularyUri, map[string]any{"ok": true})

	// The validator exists in the registry, but the URI is NOT engaged.
	registry := BuiltinRegistry().Register(fakeVocabularyUri, noopValidator())
	vs := NewValidatorSet(registry, []string{"urn:example:something-else"})

	result := vs.Validate(set)
	assert.Equal(t, Unsupported, result.Disposition)
	require.Len(t, result.Results, 1)
	assert.Equal(t, Unsupported, result.Results[0].Disposition)
}

// TestValidatorSet_EngagedButUnregisteredIsUnsupported: engagement without a
// validator still means "no validator engaged for the URI".
func TestValidatorSet_EngagedButUnregisteredIsUnsupported(t *testing.T) {
	set := setWithStreamSubject(testStreamId)
	set.AddEventPayload(fakeVocabularyUri, map[string]any{"ok": true})

	vs := NewValidatorSet(BuiltinRegistry(), []string{fakeVocabularyUri})
	result := vs.Validate(set)

	assert.Equal(t, Unsupported, result.Disposition)
	require.Len(t, result.Results, 1)
	assert.Equal(t, Unsupported, result.Results[0].Disposition)
	assert.Empty(t, result.Results[0].Claim, "Claim is empty unless the disposition is Malformed")
	assert.Empty(t, result.Results[0].Detail, "Detail is empty unless the disposition is Malformed")
}

// TestValidatorSet_EmbedderRegisteredValidatorIsConsulted is story 18's
// embedder path: a caller registers a validator for a URI absent from the
// built-in registry and it is consulted.
func TestValidatorSet_EmbedderRegisteredValidatorIsConsulted(t *testing.T) {
	set := setWithStreamSubject(testStreamId)
	set.AddEventPayload(fakeVocabularyUri, map[string]any{"frobnicated": false})

	called := false
	registry := BuiltinRegistry().Register(fakeVocabularyUri,
		ValidatorFunc(func(eventURI string, payload map[string]any, s *goSet.SecurityEventToken) Result {
			called = true
			assert.Equal(t, fakeVocabularyUri, eventURI)
			assert.Equal(t, false, payload["frobnicated"])
			assert.Same(t, set, s)
			return Result{EventURI: eventURI, Disposition: Malformed, Claim: "frobnicated", Detail: "must be true"}
		}))

	vs := NewValidatorSet(registry, []string{fakeVocabularyUri})
	result := vs.Validate(set)

	assert.True(t, called, "an embedder-registered validator must be consulted")
	assert.Equal(t, Malformed, result.Disposition)
	require.Len(t, result.Results, 1)
	assert.Equal(t, "frobnicated", result.Results[0].Claim)
}

// TestValidatorSet_WorstDispositionWins reduces per-URI dispositions to a
// whole-SET decision over a multi-URI payload.
func TestValidatorSet_WorstDispositionWins(t *testing.T) {
	const validUri = "urn:example:a-valid"
	const unsupportedUri = "urn:example:b-unsupported"
	const malformedUri = "urn:example:c-malformed"

	registry := NewRegistry().
		Register(validUri, noopValidator()).
		Register(malformedUri, ValidatorFunc(func(eventURI string, payload map[string]any, s *goSet.SecurityEventToken) Result {
			return Result{EventURI: eventURI, Disposition: Malformed, Claim: "boom", Detail: "always malformed"}
		}))

	tests := []struct {
		name    string
		uris    []string
		engaged []string
		want    Disposition
	}{
		{"all valid", []string{validUri}, []string{validUri}, Valid},
		{"valid + unsupported", []string{validUri, unsupportedUri}, []string{validUri}, Unsupported},
		{"valid + malformed", []string{validUri, malformedUri}, []string{validUri, malformedUri}, Malformed},
		{
			"valid + unsupported + malformed",
			[]string{validUri, unsupportedUri, malformedUri},
			[]string{validUri, malformedUri},
			Malformed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			set := setWithStreamSubject(testStreamId)
			for _, uri := range tt.uris {
				set.AddEventPayload(uri, map[string]any{})
			}

			result := NewValidatorSet(registry, tt.engaged).Validate(set)
			assert.Equal(t, tt.want, result.Disposition)
			assert.Len(t, result.Results, len(tt.uris), "one entry per event URI in the SET")
		})
	}
}

// TestValidatorSet_ResultsAreDeterministicallyOrdered: goSet.SecurityEventToken
// carries events in a Go map, whose iteration order is randomised and which does
// not retain JSON payload order. Results are therefore emitted in a stable
// lexicographic URI order so callers, logs, and tests can rely on them.
func TestValidatorSet_ResultsAreDeterministicallyOrdered(t *testing.T) {
	set := setWithStreamSubject(testStreamId)
	for _, uri := range []string{"urn:example:c", "urn:example:a", "urn:example:b"} {
		set.AddEventPayload(uri, map[string]any{})
	}

	vs := NewValidatorSet(NewRegistry(), nil)
	for i := 0; i < 10; i++ {
		result := vs.Validate(set)
		require.Len(t, result.Results, 3)
		assert.Equal(t, "urn:example:a", result.Results[0].EventURI)
		assert.Equal(t, "urn:example:b", result.Results[1].EventURI)
		assert.Equal(t, "urn:example:c", result.Results[2].EventURI)
	}
}

// TestValidatorSet_SsfStreamManagementAlwaysInContract is the story-11 rule: the
// two SSF stream-management events are validated regardless of what the stream
// negotiated, so a narrowly-scoped STRICT stream never rejects its own
// verification handshake. Normative basis: SSF §8.1.5 explicitly permits sending
// a Stream Updated event even when it is absent from events_supported /
// events_requested / events_delivered.
func TestValidatorSet_SsfStreamManagementAlwaysInContract(t *testing.T) {
	// engagedURIs deliberately excludes both SSF stream-management URIs.
	engaged := []string{fakeVocabularyUri}

	t.Run("verification is validated, not reported unsupported", func(t *testing.T) {
		set := events.CreateVerifyEvent(testStreamId, "opaque-state", "https://transmitter.example.com", []string{"receiver.example.com"})
		result := NewValidatorSet(BuiltinRegistry(), engaged).Validate(set)
		assert.Equal(t, Valid, result.Disposition)
		require.Len(t, result.Results, 1)
		assert.Equal(t, Valid, result.Results[0].Disposition)
	})

	t.Run("stream-updated is validated, not reported unsupported", func(t *testing.T) {
		set := events.CreateStatusUpdatedEvent(testStreamId, "paused", "Internal error", "https://transmitter.example.com", []string{"receiver.example.com"})
		result := NewValidatorSet(BuiltinRegistry(), engaged).Validate(set)
		assert.Equal(t, Valid, result.Disposition)
	})

	t.Run("a malformed always-in-contract event reports Malformed, not Unsupported", func(t *testing.T) {
		set := setWithStreamSubject(testStreamId)
		set.AddEventPayload(SsfStreamUpdatedEventUri, map[string]any{"reason": "no status claim"})
		result := NewValidatorSet(BuiltinRegistry(), engaged).Validate(set)
		assert.Equal(t, Malformed, result.Disposition,
			"proves the validator actually ran even though the URI was not engaged")
		require.Len(t, result.Results, 1)
		assert.Equal(t, "status", result.Results[0].Claim)
	})
}

// TestNewValidatorSet_NilRegistryUsesBuiltins keeps the always-in-contract rule
// working for a caller that passes no registry.
func TestNewValidatorSet_NilRegistryUsesBuiltins(t *testing.T) {
	set := events.CreateVerifyEvent(testStreamId, "state", "https://transmitter.example.com", []string{"receiver.example.com"})
	result := NewValidatorSet(nil, nil).Validate(set)
	assert.Equal(t, Valid, result.Disposition)
	require.Len(t, result.Results, 1)
	assert.Equal(t, Valid, result.Results[0].Disposition)
}

// TestValidatorSet_StructPayloadIsNormalised: in-process producers attach typed
// payload structs via AddEventPayload; the validator interface always sees a
// claim map.
func TestValidatorSet_StructPayloadIsNormalised(t *testing.T) {
	set := setWithStreamSubject(testStreamId)
	set.AddEventPayload(SsfStreamUpdatedEventUri, events.StreamUpdatePayload{Status: "enabled"})

	result := NewValidatorSet(BuiltinRegistry(), []string{SsfStreamUpdatedEventUri}).Validate(set)
	assert.Equal(t, Valid, result.Disposition)
}

// TestValidatorSet_NonObjectPayloadIsMalformed: RFC 8417 §2.2 makes each event
// payload a JSON object; a scalar cannot carry claims.
func TestValidatorSet_NonObjectPayloadIsMalformed(t *testing.T) {
	for _, payload := range []any{"a string", 42, nil, []any{"a", "list"}} {
		set := setWithStreamSubject(testStreamId)
		set.AddEventPayload(SsfVerificationEventUri, payload)

		result := NewValidatorSet(BuiltinRegistry(), []string{SsfVerificationEventUri}).Validate(set)
		assert.Equal(t, Malformed, result.Disposition, "payload %#v must be malformed", payload)
	}
}

// TestValidatorSet_ValidatorReturningEmptyEventUriIsBackfilled keeps a
// third-party validator from producing an unattributable Result.
func TestValidatorSet_ValidatorReturningEmptyEventUriIsBackfilled(t *testing.T) {
	set := setWithStreamSubject(testStreamId)
	set.AddEventPayload(fakeVocabularyUri, map[string]any{})

	registry := NewRegistry().Register(fakeVocabularyUri,
		ValidatorFunc(func(eventURI string, payload map[string]any, s *goSet.SecurityEventToken) Result {
			return Result{Disposition: Valid} // EventURI deliberately unset
		}))

	result := NewValidatorSet(registry, []string{fakeVocabularyUri}).Validate(set)
	require.Len(t, result.Results, 1)
	assert.Equal(t, fakeVocabularyUri, result.Results[0].EventURI)
}

// TestValidatorFunc_ImplementsValidator pins the adapter.
func TestValidatorFunc_ImplementsValidator(t *testing.T) {
	var v Validator = ValidatorFunc(func(eventURI string, payload map[string]any, s *goSet.SecurityEventToken) Result {
		return Result{EventURI: eventURI, Disposition: Malformed}
	})
	got := v.Validate("urn:example:x", nil, nil)
	assert.Equal(t, Malformed, got.Disposition)
	assert.Equal(t, "urn:example:x", got.EventURI)
}

// A payload map assembled in-process can hold typed Go values, which validators
// asserting map[string]any would reject as Malformed for a SET that is perfectly
// conformant once serialized. normalizePayload documents a JSON round-trip; this
// pins that it actually happens rather than being short-circuited by the map
// type check.
func TestNormalizePayload_RoundTripsTypedMembers(t *testing.T) {
	type scimResource struct {
		Id   string `json:"id"`
		Name string `json:"userName"`
	}

	payload, err := normalizePayload(map[string]any{
		"data": scimResource{Id: "2819c223", Name: "bjensen"},
	})
	require.NoError(t, err)

	data, ok := payload["data"].(map[string]any)
	require.True(t, ok, "a typed struct member must reach validators as a JSON object")
	assert.Equal(t, "2819c223", data["id"])
	assert.Equal(t, "bjensen", data["userName"])
}

// Nesting must not let a typed value through: the walk is recursive, so a struct
// buried in a slice inside a map still forces the round-trip.
func TestNormalizePayload_RoundTripsNestedTypedMembers(t *testing.T) {
	type ref struct {
		URI string `json:"uri"`
	}

	payload, err := normalizePayload(map[string]any{
		"outer": map[string]any{"list": []any{ref{URI: "urn:example"}}},
	})
	require.NoError(t, err)

	outer := payload["outer"].(map[string]any)
	list := outer["list"].([]any)
	entry, ok := list[0].(map[string]any)
	require.True(t, ok, "a struct nested in a slice must still be round-tripped")
	assert.Equal(t, "urn:example", entry["uri"])
}

// A payload that came off the wire is already wire-shaped, so it is returned
// verbatim — the round-trip is not paid on the receive hot path.
func TestNormalizePayload_WireShapedMapIsReturnedAsIs(t *testing.T) {
	in := map[string]any{
		"subject": map[string]any{"format": "email", "email": "user@example.com"},
		"count":   float64(3),
		"tags":    []any{"a", "b"},
		"ok":      true,
		"none":    nil,
	}
	out, err := normalizePayload(in)
	require.NoError(t, err)

	// Same backing map, not a copy: identity is the observable proof no
	// marshal/unmarshal happened.
	out["probe"] = "sentinel"
	assert.Equal(t, "sentinel", in["probe"],
		"a wire-shaped payload must be passed through without a round-trip")
}
