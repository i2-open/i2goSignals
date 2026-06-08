package goSetSstp

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMessage_RoundTrip_NilPointers verifies that a Message with both *bool fields nil
// round-trips cleanly: the boolean attributes are omitted from the wire form, and they
// decode back to nil.
func TestMessage_RoundTrip_NilPointers(t *testing.T) {
	in := Message{
		Sets: map[string]string{"jti-1": "header.payload.sig"},
		Ack:  []string{"jti-0"},
	}

	raw, err := json.Marshal(in)
	require.NoError(t, err)

	// Nil pointer fields must be omitted from the wire form.
	assert.NotContains(t, string(raw), "returnEvents")
	assert.NotContains(t, string(raw), "returnImmediately")

	var out Message
	require.NoError(t, json.Unmarshal(raw, &out))

	assert.Nil(t, out.ReturnEvents)
	assert.Nil(t, out.ReturnImmediately)
	assert.Equal(t, in.Sets, out.Sets)
	assert.Equal(t, in.Ack, out.Ack)
}
