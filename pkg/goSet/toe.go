package goSet

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// The toe claim keeps its sub-second part (to the microsecond) through a
// parse and re-encode. jwt.NumericDate on its own truncates to
// jwt.TimePrecision — one second — on both decode and encode, so a router
// that parses, stores and re-signs a SET would drop the fraction, and an
// end-to-end delivery age measured from toe would be quantized to a whole
// second (i2goSignals#325). Only toe is affected: iat/exp/nbf are reset or
// checked per hop and keep the library's precision. A toe with no fraction
// (every producer today) encodes byte-for-byte as before.

// MarshalJSON encodes the SET with a fractional toe when it has one.
func (set SecurityEventToken) MarshalJSON() ([]byte, error) {
	type plain SecurityEventToken
	toe := set.TimeOfEvent
	if toe == nil || toe.Unix() < 0 || toe.Nanosecond()/1000 == 0 {
		return json.Marshal(plain(set))
	}
	return json.Marshal(struct {
		plain
		TimeOfEvent json.RawMessage `json:"toe"`
	}{
		plain:       plain(set),
		TimeOfEvent: fmt.Appendf(nil, "%d.%06d", toe.Unix(), toe.Nanosecond()/1000),
	})
}

// UnmarshalJSON decodes the SET, keeping a fractional toe's microseconds.
func (set *SecurityEventToken) UnmarshalJSON(b []byte) error {
	type plain SecurityEventToken
	aux := struct {
		*plain
		TimeOfEvent json.RawMessage `json:"toe"`
	}{plain: (*plain)(set)}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}
	raw := aux.TimeOfEvent
	if len(raw) == 0 {
		return nil
	}
	if string(raw) == "null" {
		set.TimeOfEvent = nil
		return nil
	}
	var toe jwt.NumericDate
	if err := json.Unmarshal(raw, &toe); err != nil {
		return err
	}
	if bytes.ContainsAny(raw, ".eE") {
		if f, err := strconv.ParseFloat(string(raw), 64); err == nil {
			sec, frac := math.Modf(f)
			toe.Time = time.Unix(int64(sec), int64(math.Round(frac*1e6))*1000)
		}
	}
	set.TimeOfEvent = &toe
	return nil
}
