package goSet

import (
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSecurityEventToken_JSONHooksAgree: encoding/json goes through the
// streaming MarshalJSONTo / UnmarshalJSONFrom, the legacy MarshalJSON /
// UnmarshalJSON are kept for direct callers, and the hooks pin v1 options.
// All three entry points must produce the same wire bytes, with and without a
// fractional toe.
func TestSecurityEventToken_JSONHooksAgree(t *testing.T) {
	for _, toe := range []time.Time{time.Unix(1786735851, 0), time.Unix(1786735851, 123456000)} {
		set := toeAt(toe)

		v1, err := json.Marshal(set)
		require.NoError(t, err)
		v2, err := jsonv2.Marshal(set)
		require.NoError(t, err)
		legacy, err := set.MarshalJSON()
		require.NoError(t, err)
		assert.Equal(t, string(v1), string(v2), "encoding/json/v2 must match encoding/json")
		assert.Equal(t, string(v1), string(legacy), "MarshalJSON must match encoding/json")

		var parsed SecurityEventToken
		require.NoError(t, parsed.UnmarshalJSON(v1))
		require.NotNil(t, parsed.TimeOfEvent)
		assert.True(t, parsed.TimeOfEvent.Time.Equal(toe), "parsed toe %v, want %v", parsed.TimeOfEvent.Time, toe)
	}
}
