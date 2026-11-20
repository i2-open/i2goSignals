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
// are kept for direct callers, and the hooks pin v1 options. json.Marshal,
// jsonv2.Marshal and MarshalJSON must produce the same wire bytes for an
// ack-only, an explicit and an absent maxEvents, and json.Unmarshal,
// jsonv2.Unmarshal and UnmarshalJSON must read them back to the same request.
func TestPollRequest_JSONHooksAgree(t *testing.T) {
	for name, req := range map[string]PollRequest{
		"ack-only": {AckOnly: true, ReturnImmediately: true, Acks: []string{"jti-1"}},
		"explicit": {MaxEvents: 5},
		"absent":   {},
	} {
		t.Run(name, func(t *testing.T) {
			v1, err := json.Marshal(req)
			require.NoError(t, err)
			v2, err := jsonv2.Marshal(req)
			require.NoError(t, err)
			legacy, err := req.MarshalJSON()
			require.NoError(t, err)
			assert.Equal(t, string(v1), string(v2), "encoding/json/v2 must match encoding/json")
			assert.Equal(t, string(v1), string(legacy), "MarshalJSON must match encoding/json")

			var viaV1, viaV2, viaLegacy PollRequest
			require.NoError(t, json.Unmarshal(v1, &viaV1))
			require.NoError(t, jsonv2.Unmarshal(v1, &viaV2))
			require.NoError(t, viaLegacy.UnmarshalJSON(v1))
			assert.Equal(t, req, viaV1)
			assert.Equal(t, req, viaV2)
			assert.Equal(t, req, viaLegacy)
		})
	}
}
