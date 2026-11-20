package model

import (
	"bytes"
	"strings"
	"testing"
)

// Benchmarks for normalizeAudToArray, the aud-shape guard every foreign stream
// configuration passes through on the receiver auto-registration path.
//
// The workload is the golden populated stream configuration (see
// testdata/stream_configuration_populated.golden.json), with aud rewritten into
// each of the three shapes the function distinguishes. These numbers back the
// #276 row in docs/perf/go127-baseline.md; pkg/ssfModels is deliberately NOT in
// the Makefile's BENCH_PKGS set, so run them explicitly:
//
//	go test -run='^$' -bench=NormalizeAud -benchmem ./pkg/ssfModels
const benchStreamConfigTemplate = `{"stream_id":"stream-bench-1","iss":"https://tx.example.com",` +
	`"aud":%s,` +
	`"events_supported":["urn:example:event:a","urn:example:event:b"],` +
	`"description":"bench stream","events_requested":["urn:example:event:a"],` +
	`"events_delivered":["urn:example:event:a"],` +
	`"delivery":{"method":"urn:ietf:rfc:8936","endpoint_url":"https://tx.example.com/poll",` +
	`"authorization_header":"Bearer bench","poll_config":{"maxEvents":25,"returnImmediately":true,"timeoutSecs":30}},` +
	`"min_verification_interval":60,"inactivity_timeout":3600,"format":"iss_sub",` +
	`"receiverJWKSUrl":"https://rx.example.com/jwks.json","issuerJWKSUrl":"https://tx.example.com/jwks.json",` +
	`"route_mode":"IMPORT","signingOnly":true,` +
	`"tx_well_known_url":"https://tx.example.com/.well-known/ssf-configuration","tx_token":"tx-token"}`

func benchStreamConfig(aud string) []byte {
	return []byte(strings.Replace(benchStreamConfigTemplate, "%s", aud, 1))
}

// BenchmarkNormalizeAudToArray covers the three shapes with different costs:
// the string form is the only one that copies, the array form is the common
// case and must not, and the absent form has to scan every member before it can
// say so.
func BenchmarkNormalizeAudToArray(b *testing.B) {
	for _, tc := range []struct {
		name string
		doc  []byte
	}{
		{"string", benchStreamConfig(`"https://rx.example.com"`)},
		{"array", benchStreamConfig(`["https://rx.example.com"]`)},
		{"absent", bytes.Replace(benchStreamConfig(`"x"`), []byte(`"aud":"x",`), nil, 1)},
	} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if len(normalizeAudToArray(tc.doc)) == 0 {
					b.Fatal("empty result")
				}
			}
		})
	}
}

// BenchmarkUnmarshalStreamConfigurationJSON measures the normaliser inside the
// decode it guards, so a change to the scan can be read against the cost of the
// unmarshal it precedes.
func BenchmarkUnmarshalStreamConfigurationJSON(b *testing.B) {
	doc := benchStreamConfig(`"https://rx.example.com"`)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var cfg StreamConfiguration
		if err := UnmarshalStreamConfigurationJSON(doc, &cfg); err != nil {
			b.Fatalf("unmarshal: %v", err)
		}
	}
}
