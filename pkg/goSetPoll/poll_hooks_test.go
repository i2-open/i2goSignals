package goSetPoll

import (
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPollRequest_JSONHooksAgree: encoding/json goes through the streaming
// MarshalJSONTo / UnmarshalJSONFrom, the legacy MarshalJSON / UnmarshalJSON
// are kept for direct callers, and the hooks pin v1 options. All three entry
// points must produce the same wire bytes and read them back the same way.
func TestPollRequest_JSONHooksAgree(t *testing.T) {
	for _, req := range []PollRequest{
		{AckOnly: true, ReturnImmediately: true, Acks: []string{"jti-1"}},
		{MaxEvents: 5},
		{},
	} {
		v1, err := json.Marshal(req)
		require.NoError(t, err)
		v2, err := jsonv2.Marshal(req)
		require.NoError(t, err)
		legacy, err := req.MarshalJSON()
		require.NoError(t, err)
		assert.Equal(t, string(v1), string(v2), "encoding/json/v2 must match encoding/json")
		assert.Equal(t, string(v1), string(legacy), "MarshalJSON must match encoding/json")

		var parsed PollRequest
		require.NoError(t, parsed.UnmarshalJSON(v1))
		assert.Equal(t, req, parsed)
	}
}
