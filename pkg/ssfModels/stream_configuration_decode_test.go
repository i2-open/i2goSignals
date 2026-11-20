package model

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
)

// TestUnmarshalStreamConfigurationJSON_StringAudToArray locks down RFC 7519 §4.1.3
// compatibility: a transmitter may emit "aud" as a single JSON string, and the
// receiver must normalize it into the []string field on StreamConfiguration.
// Reverting b3bc82a (which introduced normalizeAudToArray) makes this test fail.
func TestUnmarshalStreamConfigurationJSON_StringAudToArray(t *testing.T) {
	data := []byte(`{"stream_id":"s1","aud":"https://receiver","iss":"https://transmitter"}`)

	var cfg StreamConfiguration
	if err := UnmarshalStreamConfigurationJSON(data, &cfg); err != nil {
		t.Fatalf("UnmarshalStreamConfigurationJSON returned error for string-form aud: %v", err)
	}

	want := []string{"https://receiver"}
	if !reflect.DeepEqual(cfg.Aud, want) {
		t.Errorf("Aud = %#v, want %#v", cfg.Aud, want)
	}
	if cfg.Id != "s1" {
		t.Errorf("Id = %q, want %q", cfg.Id, "s1")
	}
	if cfg.Iss != "https://transmitter" {
		t.Errorf("Iss = %q, want %q", cfg.Iss, "https://transmitter")
	}
}

// TestUnmarshalStreamConfigurationJSON_ArrayAudPreserved confirms the normalizer
// is a no-op when aud is already an array — the original ordering and contents
// flow through unchanged.
func TestUnmarshalStreamConfigurationJSON_ArrayAudPreserved(t *testing.T) {
	data := []byte(`{"stream_id":"s2","aud":["https://a","https://b"]}`)

	var cfg StreamConfiguration
	if err := UnmarshalStreamConfigurationJSON(data, &cfg); err != nil {
		t.Fatalf("UnmarshalStreamConfigurationJSON returned error for array-form aud: %v", err)
	}

	want := []string{"https://a", "https://b"}
	if !reflect.DeepEqual(cfg.Aud, want) {
		t.Errorf("Aud = %#v, want %#v", cfg.Aud, want)
	}
}

// TestNormalizeAudToArray_SplicesInPlace pins the ONE rewrite the normalizer is
// allowed to make: the string aud becomes a one-element array and nothing else
// in the document moves. Member order, spacing and nested bytes are the
// transmitter's, not ours — re-encoding through a map would sort the members
// and compact the whitespace, which is a wire change this function has no
// mandate to make.
func TestNormalizeAudToArray_SplicesInPlace(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		want string
	}{
		{
			"member order preserved",
			`{"stream_id":"s1","aud":"https://receiver","iss":"https://transmitter"}`,
			`{"stream_id":"s1","aud":["https://receiver"],"iss":"https://transmitter"}`,
		},
		{
			"surrounding whitespace preserved",
			`{ "stream_id" : "s1" , "aud" : "https://receiver" }`,
			`{ "stream_id" : "s1" , "aud" : ["https://receiver"] }`,
		},
		{
			"nested value bytes untouched",
			`{"aud":"r","delivery":{"method":"urn:push","endpoint_url":"https://e/ep"}}`,
			`{"aud":["r"],"delivery":{"method":"urn:push","endpoint_url":"https://e/ep"}}`,
		},
		{
			"escapes in the aud value survive verbatim",
			`{"aud":"https://r/é","iss":"i"}`,
			`{"aud":["https://r/é"],"iss":"i"}`,
		},
		{
			"aud last member",
			`{"iss":"i","aud":"r"}`,
			`{"iss":"i","aud":["r"]}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := string(normalizeAudToArray([]byte(tc.in)))
			if got != tc.want {
				t.Errorf("normalizeAudToArray:\n got %s\nwant %s", got, tc.want)
			}
		})
	}
}

// TestNormalizeAudToArray_PassThroughIsByteIdentical: every shape the
// normalizer does not rewrite must come back as the SAME slice, not a copy
// that happens to compare equal. Returning a re-encoding would silently
// reorder members and drop the caller's bytes for no benefit, and it is the
// pass-through path that the golden stream-configuration documents ride.
func TestNormalizeAudToArray_PassThroughIsByteIdentical(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
	}{
		{"aud absent", `{"stream_id":"s1","iss":"https://transmitter"}`},
		{"aud already an array", `{"aud":["https://a","https://b"],"iss":"i"}`},
		{"aud empty array", `{"aud":[]}`},
		{"aud null", `{"aud":null}`},
		{"aud a number", `{"aud":1}`},
		{"aud an object", `{"aud":{"x":1}}`},
		{"nested aud only", `{"delivery":{"aud":"r"}}`},
		{"not an object", `["a","b"]`},
		{"not JSON at all", `not json`},
		{"truncated", `{"aud":`},
		{"empty", ``},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := []byte(tc.in)
			got := normalizeAudToArray(in)
			if len(in) == 0 {
				if len(got) != 0 {
					t.Fatalf("got %q, want empty", got)
				}
				return
			}
			if &got[0] != &in[0] || len(got) != len(in) {
				t.Errorf("normalizeAudToArray copied a document it does not rewrite: got %s", got)
			}
		})
	}
}

// TestUnmarshalStreamConfigurationJSON_NestedAudUntouched: only the top-level
// aud carries JWT audience semantics. A member of the same name inside a
// nested object is that object's own data and must reach the nested decoder
// unchanged.
func TestUnmarshalStreamConfigurationJSON_NestedAudUntouched(t *testing.T) {
	data := []byte(`{"stream_id":"s3","aud":"https://receiver","delivery":{"method":"urn:ietf:rfc:8935","endpoint_url":"https://e/ep"}}`)

	var cfg StreamConfiguration
	if err := UnmarshalStreamConfigurationJSON(data, &cfg); err != nil {
		t.Fatalf("UnmarshalStreamConfigurationJSON: %v", err)
	}
	if !reflect.DeepEqual(cfg.Aud, []string{"https://receiver"}) {
		t.Errorf("Aud = %#v", cfg.Aud)
	}
	if cfg.Delivery == nil || cfg.Delivery.PushTransmitMethod == nil {
		t.Fatalf("delivery did not survive normalisation: %#v", cfg.Delivery)
	}
	if got := cfg.Delivery.PushTransmitMethod.EndpointUrl; got != "https://e/ep" {
		t.Errorf("endpoint_url = %q", got)
	}
}

// TestNormalizeAudToArray_GoldenStreamConfigurationsUnchanged ties the
// pass-through guarantee to the wire bytes #273 pinned: every golden stream
// configuration carries aud in its array form or not at all, so the normaliser
// must hand each one straight back and the configuration must decode to the
// same value with or without it. A normaliser that re-encoded would reorder
// these documents' members and the byte comparison would catch it.
func TestNormalizeAudToArray_GoldenStreamConfigurationsUnchanged(t *testing.T) {
	for _, name := range []string{
		"stream_configuration_populated",
		"stream_configuration_mixed",
		"stream_configuration_zero",
	} {
		t.Run(name, func(t *testing.T) {
			golden, err := os.ReadFile(filepath.Join("testdata", name+".golden.json"))
			if err != nil {
				t.Fatalf("reading golden: %v", err)
			}
			if got := normalizeAudToArray(golden); !bytes.Equal(got, golden) {
				t.Errorf("golden document rewritten:\n got %s\nwant %s", got, golden)
			}

			var viaNormalizer, direct StreamConfiguration
			if err := UnmarshalStreamConfigurationJSON(golden, &viaNormalizer); err != nil {
				t.Fatalf("UnmarshalStreamConfigurationJSON: %v", err)
			}
			if err := json.Unmarshal(golden, &direct); err != nil {
				t.Fatalf("json.Unmarshal: %v", err)
			}
			if !reflect.DeepEqual(viaNormalizer, direct) {
				t.Errorf("normalised decode differs from the plain decode")
			}
		})
	}
}

// TestNormalizeAudToArray_ScannerReuse: the normaliser borrows a decoder from a
// pool and abandons it mid-document on every pass-through, so the next borrower
// inherits whatever state the last one left. The alternation below — rewrite,
// pass-through, malformed, rewrite — is the sequence that would expose a
// decoder that was not fully reset, and the concurrent half makes the same
// point under -race.
func TestNormalizeAudToArray_ScannerReuse(t *testing.T) {
	check := func(t *testing.T) {
		t.Helper()
		for i := 0; i < 200; i++ {
			if got := string(normalizeAudToArray([]byte(`{"iss":"i","aud":"r"}`))); got != `{"iss":"i","aud":["r"]}` {
				t.Fatalf("rewrite after reuse: %s", got)
			}
			if got := string(normalizeAudToArray([]byte(`{"aud":["r"],"iss":"i"}`))); got != `{"aud":["r"],"iss":"i"}` {
				t.Fatalf("pass-through after reuse: %s", got)
			}
			if got := string(normalizeAudToArray([]byte(`{"aud":`))); got != `{"aud":` {
				t.Fatalf("malformed after reuse: %s", got)
			}
			if got := string(normalizeAudToArray([]byte(`{"a":{"b":[1,2]},"aud":"r2"}`))); got != `{"a":{"b":[1,2]},"aud":["r2"]}` {
				t.Fatalf("nested rewrite after reuse: %s", got)
			}
		}
	}
	check(t)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			check(t)
		}()
	}
	wg.Wait()
}
