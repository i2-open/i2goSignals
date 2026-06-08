package goSetSstp

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBoolPtr(t *testing.T) {
	p := BoolPtr(true)
	require.NotNil(t, p)
	assert.True(t, *p)

	q := BoolPtr(false)
	require.NotNil(t, q)
	assert.False(t, *q)
}

// TestReturnEventsResolved covers the §2.1 default: omitted returnEvents → true.
func TestReturnEventsResolved(t *testing.T) {
	tests := []struct {
		name string
		in   *bool
		want bool
	}{
		{"nil defaults to true", nil, true},
		{"explicit true honored", BoolPtr(true), true},
		{"explicit false honored", BoolPtr(false), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := Message{ReturnEvents: tt.in}
			assert.Equal(t, tt.want, m.ReturnEventsResolved())
		})
	}
}

// TestReturnImmediatelyResolved covers the §2.1 default: omitted returnImmediately → false.
func TestReturnImmediatelyResolved(t *testing.T) {
	tests := []struct {
		name string
		in   *bool
		want bool
	}{
		{"nil defaults to false", nil, false},
		{"explicit true honored", BoolPtr(true), true},
		{"explicit false honored", BoolPtr(false), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := Message{ReturnImmediately: tt.in}
			assert.Equal(t, tt.want, m.ReturnImmediatelyResolved())
		})
	}
}

// TestMessage_RoundTrip_PopulatedPointers verifies both *bool fields survive a JSON
// round-trip when populated, including the false-is-not-omitted case.
func TestMessage_RoundTrip_PopulatedPointers(t *testing.T) {
	in := Message{
		ReturnEvents:      BoolPtr(false),
		ReturnImmediately: BoolPtr(true),
		SetErrs: map[string]SetErr{
			"jti-9": {Err: ErrJwtAud, Description: "The audience value was incorrect."},
		},
	}

	raw, err := json.Marshal(in)
	require.NoError(t, err)
	assert.Contains(t, string(raw), `"returnEvents":false`)
	assert.Contains(t, string(raw), `"returnImmediately":true`)

	var out Message
	require.NoError(t, json.Unmarshal(raw, &out))

	require.NotNil(t, out.ReturnEvents)
	require.NotNil(t, out.ReturnImmediately)
	assert.False(t, *out.ReturnEvents)
	assert.True(t, *out.ReturnImmediately)
	assert.Equal(t, in.SetErrs, out.SetErrs)
}
