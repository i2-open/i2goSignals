package goSetValidate

import (
	"strings"
	"testing"

	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The router compares event types case-insensitively (pkg/services
// event-matching uses strings.EqualFold), so registry lookup and engagement must
// agree. Before this fix a case-variant URI was routed but reported Unsupported,
// which STRICT turned into a rejection of legitimate traffic and ENFORCE turned
// into an unvalidated pass (code-review finding on spec #247 #249).
func TestRegistryLookupIsCaseInsensitive(t *testing.T) {
	const uri = "https://example.com/vocab/Widget-Changed"

	r := NewRegistry().Register(uri, ValidatorFunc(
		func(eventURI string, _ map[string]any, _ *goSet.SecurityEventToken) Result {
			return Result{EventURI: eventURI, Disposition: Valid}
		}))

	for _, probe := range []string{uri, strings.ToLower(uri), strings.ToUpper(uri)} {
		_, ok := r.Lookup(probe)
		assert.True(t, ok, "Lookup(%q) must hit the registration", probe)
	}
}

// Registering a case variant must REPLACE, not shadow, an existing entry —
// otherwise two validators could both claim one event type with the winner
// decided by map iteration.
func TestRegisterCaseVariantReplaces(t *testing.T) {
	const uri = "https://example.com/vocab/thing"

	first := ValidatorFunc(func(string, map[string]any, *goSet.SecurityEventToken) Result {
		return Result{Disposition: Valid, Detail: "first"}
	})
	second := ValidatorFunc(func(string, map[string]any, *goSet.SecurityEventToken) Result {
		return Result{Disposition: Valid, Detail: "second"}
	})

	r := NewRegistry().Register(uri, first).Register(strings.ToUpper(uri), second)

	v, ok := r.Lookup(uri)
	require.True(t, ok)
	assert.Equal(t, "second", v.Validate(uri, nil, nil).Detail,
		"a case-variant Register must replace the earlier entry")
}

// Engagement must fold case too: a stream that negotiated the canonical URI has
// engaged the event type, whatever case the transmitter sends it in.
func TestValidatorSetEngagementIsCaseInsensitive(t *testing.T) {
	const canonical = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"

	vs := NewValidatorSet(BuiltinRegistry(), []string{canonical})

	set := &goSet.SecurityEventToken{}
	set.Events = map[string]interface{}{
		strings.ToUpper(canonical): map[string]any{},
	}

	result := vs.Validate(set)
	require.Len(t, result.Results, 1)
	assert.NotEqual(t, Unsupported, result.Results[0].Disposition,
		"a case-variant of an engaged URI must not report Unsupported")
	// The reported URI keeps the wire form so logs and error descriptions name
	// what actually arrived.
	assert.Equal(t, strings.ToUpper(canonical), result.Results[0].EventURI)
}
