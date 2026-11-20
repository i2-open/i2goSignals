package goSetValidate

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"
)

// customMarshaler is a payload member that renders itself through the v1
// json.Marshaler interface, which json/v2 honours for compatibility.
type customMarshaler struct{}

func (customMarshaler) MarshalJSON() ([]byte, error) {
	return []byte(`{"format":"opaque","id":"8f4b"}`), nil
}

// The json/v2 pilot for spec #101 slice #276.
//
// normalizePayload is this package's only JSON work and its only hot-path
// allocation: an event payload that was assembled in-process rather than parsed
// off the wire is round-tripped through the encoder so validators only ever see
// wire shapes. The pilot asks one question — does the Go 1.27 encoding/json/v2
// implementation of that round-trip beat v1 on BOTH ns/op and allocs/op? — and
// the answer is recorded in docs/perf/go127-baseline.md either way.
//
// It does: v2 came in ~35% faster with ten fewer allocations per round-trip and
// was adopted, so validatorset.go now holds the v2 form and the superseded v1
// one lives here — the non-adopted variant ships with the tests, never with the
// binary, and the A/B stays runnable so a later toolchain can be re-checked
// against the same shapes.
//
//	go test -run='^$' -bench=NormalizePayload -benchmem ./pkg/goSetValidate

// normalizePayloadV1 is normalizePayload with the round-trip left on
// encoding/json v1 — the implementation this package shipped before the pilot.
// Everything else — the nil check, the isWireShape short-circuit, the null
// result check — is identical, so a benchmark difference is the encoder and
// nothing else.
func normalizePayloadV1(rawPayload any) (map[string]any, error) {
	if rawPayload == nil {
		return nil, errors.New("payload is null")
	}
	if m, ok := rawPayload.(map[string]any); ok && isWireShape(m) {
		return m, nil
	}
	encoded, err := json.Marshal(rawPayload)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(encoded, &m); err != nil {
		return nil, err
	}
	if m == nil {
		return nil, errors.New("payload is null")
	}
	return m, nil
}

// benchStructPayload is the in-process shape normalizePayload exists for: a
// typed struct that has to be round-tripped before a validator, which asserts
// map[string]any, can read it.
type benchStructPayload struct {
	Data     benchStructData `json:"data"`
	Attempts int             `json:"attempts"`
	Reason   string          `json:"reason,omitempty"`
}

type benchStructData struct {
	UserName string   `json:"userName"`
	Emails   []string `json:"emails"`
	Active   bool     `json:"active"`
	Version  float64  `json:"version"`
}

func benchStruct() benchStructPayload {
	return benchStructPayload{
		Data: benchStructData{
			UserName: "jdoe",
			Emails:   []string{"jdoe@example.com", "j.doe@example.com"},
			Active:   true,
			Version:  3,
		},
		Attempts: 2,
		Reason:   "provisioning",
	}
}

// benchWirePayload is the receive-side shape: already wire-typed all the way
// down, so both variants short-circuit and neither encodes anything.
func benchWirePayload() map[string]any {
	return map[string]any{
		"data": map[string]any{
			"userName": "jdoe",
			"emails":   []any{"jdoe@example.com"},
			"active":   true,
			"version":  float64(3),
		},
		"attempts": float64(2),
	}
}

// TestNormalizePayloadPilotAgrees keeps the comparison honest: the two variants
// must produce the same claim map for every shape benchmarked, or the numbers
// below are measuring two different jobs.
func TestNormalizePayloadPilotAgrees(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   any
	}{
		{"wire map", benchWirePayload()},
		{"struct", benchStruct()},
		{"map holding a struct", map[string]any{"data": benchStruct()}},
		// json/v2 honours the v1 json.Marshaler interface for compatibility.
		// Event payloads in this repo reach AddEventPayload as ordinary structs
		// today, but a type that marshals itself is exactly where the two
		// encoders could quietly disagree, so the substitution is held to it.
		{"custom marshaler", map[string]any{
			"when":    time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC),
			"subject": customMarshaler{},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got1, err1 := normalizePayloadV1(tc.in)
			got2, err2 := normalizePayload(tc.in)
			if (err1 == nil) != (err2 == nil) {
				t.Fatalf("v1 err = %v, v2 err = %v", err1, err2)
			}
			if !reflect.DeepEqual(got1, got2) {
				t.Errorf("v1 = %#v\nv2 = %#v", got1, got2)
			}
		})
	}
}

// TestNormalizePayloadPilotUsesV1Shapes pins the property the whole
// substitution rests on: json/v2 decodes into an `any` with the same six wire
// types v1 uses, so isWireShape and every validator's type assertion keep
// holding. A v2 that produced, say, json.Number here would turn conformant
// payloads into Malformed results.
func TestNormalizePayloadPilotUsesV1Shapes(t *testing.T) {
	m, err := normalizePayload(benchStruct())
	if err != nil {
		t.Fatalf("normalizePayload: %v", err)
	}
	if !isWireShape(m) {
		t.Errorf("json/v2 produced a non-wire shape: %#v", m)
	}
	if _, ok := m["attempts"].(float64); !ok {
		t.Errorf("attempts = %T, want float64", m["attempts"])
	}
	// Sanity: v1 is the reference and must satisfy the same property.
	var round map[string]any
	encoded, _ := json.Marshal(benchStruct())
	if err := json.Unmarshal(encoded, &round); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(m, round) {
		t.Errorf("v2 = %#v\nv1 = %#v", m, round)
	}
}

// BenchmarkNormalizePayload is the A/B the pilot turns on. "wire" is the
// receive hot path (both variants short-circuit, so it measures isWireShape);
// "struct" and "map-with-struct" are the round-trip the pilot is about.
func BenchmarkNormalizePayload(b *testing.B) {
	wire := benchWirePayload()
	strct := benchStruct()
	mixed := map[string]any{"data": benchStruct()}

	for _, variant := range []struct {
		name string
		fn   func(any) (map[string]any, error)
	}{
		{"v1", normalizePayloadV1},
		{"v2", normalizePayload},
	} {
		for _, shape := range []struct {
			name string
			in   any
		}{
			{"wire", wire},
			{"struct", strct},
			{"map-with-struct", mixed},
		} {
			b.Run(variant.name+"/"+shape.name, func(b *testing.B) {
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if _, err := variant.fn(shape.in); err != nil {
						b.Fatalf("normalize: %v", err)
					}
				}
			})
		}
	}
}
