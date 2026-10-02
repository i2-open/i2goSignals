package goSet

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/v2/bson"
)

// toeAt builds a SET whose toe carries a sub-second component. The struct is
// filled directly rather than through jwt.NewNumericDate, which truncates to
// jwt.TimePrecision (one second) before the SET is ever encoded.
func toeAt(toe time.Time) SecurityEventToken {
	return SecurityEventToken{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:   "https://issuer.example",
			ID:       "urn:uuid:toe-precision",
			IssuedAt: jwt.NewNumericDate(time.Unix(1786735851, 0)),
		},
		TimeOfEvent: &jwt.NumericDate{Time: toe},
		Events:      map[string]interface{}{"urn:example:event": map[string]interface{}{}},
	}
}

// TestTimeOfEvent_SubSecondSurvivesAJSONHop: a router parses a SET and
// re-encodes it for the next hop. A sub-second toe must come out the other
// side at microsecond precision, or a delivery-age measurement taken from it
// is quantized to a whole second (#325).
func TestTimeOfEvent_SubSecondSurvivesAJSONHop(t *testing.T) {
	toe := time.Unix(1786735851, 123456000)
	set := toeAt(toe)

	wire, err := json.Marshal(&set)
	require.NoError(t, err)
	assert.Contains(t, string(wire), `"toe":1786735851.123456`)

	var parsed SecurityEventToken
	require.NoError(t, json.Unmarshal(wire, &parsed))
	require.NotNil(t, parsed.TimeOfEvent)
	assert.True(t, parsed.TimeOfEvent.Time.Equal(toe), "parsed toe %v, want %v", parsed.TimeOfEvent.Time, toe)

	again, err := json.Marshal(&parsed)
	require.NoError(t, err)
	assert.JSONEq(t, string(wire), string(again), "a second hop must not lose precision either")
}

// TestTimeOfEvent_SubSecondSurvivesTheEventStore: the router persists the SET
// before forwarding it, so the BSON round trip must keep the fraction too.
func TestTimeOfEvent_SubSecondSurvivesTheEventStore(t *testing.T) {
	toe := time.Unix(1786735851, 500250000)
	set := toeAt(toe)

	raw, err := bson.Marshal(set)
	require.NoError(t, err)
	var got SecurityEventToken
	require.NoError(t, bson.Unmarshal(raw, &got))
	require.NotNil(t, got.TimeOfEvent)
	assert.True(t, got.TimeOfEvent.Time.Equal(toe), "stored toe %v, want %v", got.TimeOfEvent.Time, toe)
}

// TestTimeOfEvent_WholeSecondsAreUnchanged: a toe with no fraction — every SET
// a real producer sends today — encodes exactly as before.
func TestTimeOfEvent_WholeSecondsAreUnchanged(t *testing.T) {
	set := toeAt(time.Unix(1786735851, 0))
	wire, err := json.Marshal(&set)
	require.NoError(t, err)
	assert.Contains(t, string(wire), `"toe":1786735851,`)

	var parsed SecurityEventToken
	require.NoError(t, json.Unmarshal([]byte(`{"iss":"x","jti":"j","toe":1786735851,"events":{}}`), &parsed))
	require.NotNil(t, parsed.TimeOfEvent)
	assert.Equal(t, int64(1786735851), parsed.TimeOfEvent.Unix())
	assert.Equal(t, 0, parsed.TimeOfEvent.Nanosecond())

	var bad SecurityEventToken
	assert.Error(t, json.Unmarshal([]byte(`{"iss":"x","toe":"soon","events":{}}`), &bad), "a non-numeric toe is still rejected")
}
