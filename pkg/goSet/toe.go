package goSet

import (
	"bytes"
	"encoding/json"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
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

//
// The hooks are the json/v2 streaming forms, which encoding/json and
// encoding/json/v2 both call in preference to MarshalJSON / UnmarshalJSON. A
// legacy hook on a type this size is dear: the encoder re-validates and copies
// every byte it returns, and the decoder buffers the whole SET and decodes it a
// second time (BenchmarkSetJsonBytes +42%, 10 -> 13 allocs/op). The streaming
// hooks write into, and read from, the caller's own encoder and decoder. They
// pin v1 options, as the legacy hooks did by calling encoding/json, so the wire
// shape does not depend on which package the caller encodes with.
//
// MarshalJSONTo keeps a value receiver on purpose: under v1 method semantics a
// pointer-receiver MarshalJSONTo is skipped for a non-addressable value and the
// legacy MarshalJSON is called instead, which would recurse through json.Marshal.

// setJSONOptions are the encoding/json (v1) semantics the SET wire form uses,
// minus v1 error reporting. Under v1 error semantics UnmarshalDecode scans the
// whole next value for syntax errors before decoding it; the top-level
// encoding/json call has already done that for the body, so the nested call in
// UnmarshalJSONFrom would validate every byte a second time
// (BenchmarkSetJsonUnmarshal +12%). The top-level call still reports errors in
// v1 form.
var setJSONOptions = jsonv2.JoinOptions(json.DefaultOptionsV1(), json.ReportErrorsWithLegacySemantics(false))

// MarshalJSONTo encodes the SET with a fractional toe when it has one.
func (set SecurityEventToken) MarshalJSONTo(enc *jsontext.Encoder) error {
	type plain SecurityEventToken
	toe := set.TimeOfEvent
	if toe == nil || toe.Unix() < 0 || toe.Nanosecond()/1000 == 0 {
		return jsonv2.MarshalEncode(enc, (*plain)(&set), setJSONOptions)
	}
	return jsonv2.MarshalEncode(enc, &struct {
		*plain
		TimeOfEvent json.RawMessage `json:"toe"`
	}{
		plain:       (*plain)(&set),
		TimeOfEvent: fmt.Appendf(nil, "%d.%06d", toe.Unix(), toe.Nanosecond()/1000),
	}, setJSONOptions)
}

// UnmarshalJSONFrom decodes the SET, keeping a fractional toe's microseconds.
func (set *SecurityEventToken) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	type plain SecurityEventToken
	aux := struct {
		*plain
		TimeOfEvent json.RawMessage `json:"toe"`
	}{plain: (*plain)(set)}
	if err := jsonv2.UnmarshalDecode(dec, &aux, setJSONOptions); err != nil {
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
		f, err := strconv.ParseFloat(string(raw), 64)
		if err != nil {
			return fmt.Errorf("invalid toe %s: %w", raw, err)
		}
		sec, frac := math.Modf(f)
		toe.Time = time.Unix(int64(sec), int64(math.Round(frac*1e6))*1000)
	}
	set.TimeOfEvent = &toe
	return nil
}

// MarshalJSON is kept for callers that use the json.Marshaler interface
// directly; encoding/json itself goes through MarshalJSONTo.
func (set SecurityEventToken) MarshalJSON() ([]byte, error) {
	return json.Marshal(set)
}

// UnmarshalJSON is kept for callers that use the json.Unmarshaler interface
// directly; encoding/json itself goes through UnmarshalJSONFrom.
func (set *SecurityEventToken) UnmarshalJSON(b []byte) error {
	return json.Unmarshal(b, set)
}
