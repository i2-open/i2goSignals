package model

import (
    "reflect"
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
