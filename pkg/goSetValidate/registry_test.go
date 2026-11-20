package goSetValidate

import (
	"testing"

	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const fakeVocabularyUri = "urn:example:vocab:event-type:widget-frobnicated"

func noopValidator() ValidatorFunc {
	return func(eventURI string, payload map[string]any, set *goSet.SecurityEventToken) Result {
		return Result{EventURI: eventURI, Disposition: Valid}
	}
}

func TestNewRegistry_IsEmpty(t *testing.T) {
	r := NewRegistry()
	require.NotNil(t, r)
	_, ok := r.Lookup(SsfVerificationEventUri)
	assert.False(t, ok, "a bare registry must not carry the built-in pack")
}

// TestRegistry_RegisterChains covers the story-18 embedder path: Register
// returns the receiver so built-in packs and embedder registrations chain.
func TestRegistry_RegisterChains(t *testing.T) {
	r := NewRegistry().
		Register("urn:example:a", noopValidator()).
		Register("urn:example:b", noopValidator())
	require.NotNil(t, r)

	_, ok := r.Lookup("urn:example:a")
	assert.True(t, ok)
	_, ok = r.Lookup("urn:example:b")
	assert.True(t, ok)
	_, ok = r.Lookup("urn:example:c")
	assert.False(t, ok)
}

func TestRegistry_LookupMiss(t *testing.T) {
	v, ok := NewRegistry().Lookup("urn:example:missing")
	assert.False(t, ok)
	assert.Nil(t, v)
}

// TestBuiltinRegistry_CarriesSsfStreamManagementValidators is the built-in pack
// this slice ships. Later slices extend it.
func TestBuiltinRegistry_CarriesSsfStreamManagementValidators(t *testing.T) {
	r := BuiltinRegistry()
	require.NotNil(t, r)

	for _, uri := range []string{SsfVerificationEventUri, SsfStreamUpdatedEventUri} {
		v, ok := r.Lookup(uri)
		assert.True(t, ok, "built-in registry must carry a validator for %s", uri)
		assert.NotNil(t, v)
	}
}

// TestBuiltinRegistry_ReturnsIndependentInstances protects embedders from each
// other: registering onto the result of BuiltinRegistry must not mutate shared
// process-wide state.
func TestBuiltinRegistry_ReturnsIndependentInstances(t *testing.T) {
	a := BuiltinRegistry()
	a.Register(fakeVocabularyUri, noopValidator())

	b := BuiltinRegistry()
	_, ok := b.Lookup(fakeVocabularyUri)
	assert.False(t, ok, "BuiltinRegistry must hand back a fresh registry, not a shared singleton")
}

func TestRegistry_NilAndEmptyRegistrationsIgnored(t *testing.T) {
	r := NewRegistry().
		Register("", noopValidator()).
		Register("urn:example:nilvalidator", nil)

	_, ok := r.Lookup("")
	assert.False(t, ok)
	_, ok = r.Lookup("urn:example:nilvalidator")
	assert.False(t, ok)
}

// TestRegistry_NilReceiverIsSafe keeps a zero-value/nil registry from panicking
// a caller that has not built one yet.
func TestRegistry_NilReceiverIsSafe(t *testing.T) {
	var r *Registry
	assert.NotPanics(t, func() {
		_, ok := r.Lookup(SsfVerificationEventUri)
		assert.False(t, ok)
	})
}

// TestSsfUriConstants_AliasGoSetEvents pins the constants to pkg/goSet/events so
// the two definitions can never drift.
func TestSsfUriConstants_AliasGoSetEvents(t *testing.T) {
	assert.Equal(t, "https://schemas.openid.net/secevent/ssf/event-type/verification", SsfVerificationEventUri)
	assert.Equal(t, "https://schemas.openid.net/secevent/ssf/event-type/stream-updated", SsfStreamUpdatedEventUri)
}
