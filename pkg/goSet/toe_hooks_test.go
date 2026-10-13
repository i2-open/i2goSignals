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
// json.Marshal, jsonv2.Marshal and MarshalJSON must produce the same wire
// bytes for a whole-second, a fractional and an absent toe, and
// json.Unmarshal, jsonv2.Unmarshal and UnmarshalJSON must read them back to
// the same toe.
func TestSecurityEventToken_JSONHooksAgree(t *testing.T) {
	whole := time.Unix(1786735851, 0)
	fractional := time.Unix(1786735851, 123456000)
	for name, set := range map[string]SecurityEventToken{
		"whole-second": toeAt(whole),
		"fractional":   toeAt(fractional),
		"absent":       {Issuer: "https://issuer.example"},
	} {
		t.Run(name, func(t *testing.T) {
			v1, err := json.Marshal(set)
			require.NoError(t, err)
			v2, err := jsonv2.Marshal(set)
			require.NoError(t, err)
			legacy, err := set.MarshalJSON()
			require.NoError(t, err)
			assert.Equal(t, string(v1), string(v2), "encoding/json/v2 must match encoding/json")
			assert.Equal(t, string(v1), string(legacy), "MarshalJSON must match encoding/json")

			var viaV1, viaV2, viaLegacy SecurityEventToken
			require.NoError(t, json.Unmarshal(v1, &viaV1))
			require.NoError(t, jsonv2.Unmarshal(v1, &viaV2))
			require.NoError(t, viaLegacy.UnmarshalJSON(v1))
			for _, parsed := range []SecurityEventToken{viaV1, viaV2, viaLegacy} {
				if set.TimeOfEvent == nil {
					assert.Nil(t, parsed.TimeOfEvent)
					continue
				}
				require.NotNil(t, parsed.TimeOfEvent)
				assert.True(t, parsed.TimeOfEvent.Time.Equal(set.TimeOfEvent.Time), "parsed toe %v, want %v", parsed.TimeOfEvent.Time, set.TimeOfEvent.Time)
			}
		})
	}
}
