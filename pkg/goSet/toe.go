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
// second (prerequisite for the latency benchmark in i2goSignals#325; af56b65,
// PR #353). Only toe is affected: iat/exp/nbf are reset or checked per hop and
// keep the library's precision. A toe with no fraction (every producer today)
// encodes byte-for-byte as before.

// JSONOptionsV1 are the options the SET and poll-request codecs pass to their
// nested json/v2 calls: encoding/json (v1) semantics, minus v1 error
// reporting. goSetPoll shares it so both wire forms are pinned the same way.
//
// The codecs are the json/v2 streaming hooks, MarshalJSONTo / UnmarshalJSONFrom,
// which encoding/json and encoding/json/v2 both call in preference to
// MarshalJSON / UnmarshalJSON. A legacy hook is dear: the encoder re-validates
// and copies every byte it returns, and the decoder buffers the whole value and
// decodes it a second time (BenchmarkSetJsonBytes +45.9%, 10 -> 13 allocs/op;
// BenchmarkPollRequestMarshal +68.8%, 5 -> 9). The streaming hooks write into,
// and read from, the caller's own encoder and decoder.
//
// Pinning DefaultOptionsV1 means the wire shape does not depend on which
// package the caller encodes with. It also means a caller that reaches these
// types through encoding/json/v2 directly gets v1 decoding leniency for them
// (duplicate names and invalid UTF-8 accepted, case-insensitive name matching)
// and v1 HTML-escaped output, where before this change v2's stricter defaults
// applied. No production caller does that today.
//
// ReportErrorsWithLegacySemantics is cleared because, with it on,
// UnmarshalDecode syntax-checks the whole next value before decoding it, and
// the top-level encoding/json call has already done that for the body, so the
// nested call would validate every byte a second time
// (BenchmarkSetJsonUnmarshal +12%, BenchmarkParsePollRequest +11%). The cost:
// the nested decode stops at the first semantic error, where v1 kept filling
// later fields. The caller still gets a v1-typed error from the top-level call
// and should discard the target either way, as ParseSet does. Syntax errors
// are still caught before any field is written.
//
// MarshalJSONTo keeps a value receiver on purpose: under v1 method semantics a
// pointer-receiver MarshalJSONTo is skipped for a non-addressable value and the
// legacy MarshalJSON is called instead, which would recurse through json.Marshal.
// The copy costs one allocation on a by-value encode.
var JSONOptionsV1 = jsonv2.JoinOptions(json.DefaultOptionsV1(), json.ReportErrorsWithLegacySemantics(false))

// MarshalJSONTo encodes the SET with a fractional toe when it has one.
func (set SecurityEventToken) MarshalJSONTo(enc *jsontext.Encoder) error {
	type plain SecurityEventToken
	toe := set.TimeOfEvent
	if toe == nil || toe.Unix() < 0 || toe.Nanosecond()/1000 == 0 {
		return jsonv2.MarshalEncode(enc, (*plain)(&set), JSONOptionsV1)
	}
	return jsonv2.MarshalEncode(enc, &struct {
		*plain
		TimeOfEvent json.RawMessage `json:"toe"`
	}{
		plain:       (*plain)(&set),
		TimeOfEvent: fmt.Appendf(nil, "%d.%06d", toe.Unix(), toe.Nanosecond()/1000),
	}, JSONOptionsV1)
}

// UnmarshalJSONFrom decodes the SET, keeping a fractional toe's microseconds.
func (set *SecurityEventToken) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	type plain SecurityEventToken
	aux := struct {
		*plain
		TimeOfEvent json.RawMessage `json:"toe"`
	}{plain: (*plain)(set)}
	if err := jsonv2.UnmarshalDecode(dec, &aux, JSONOptionsV1); err != nil {
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
