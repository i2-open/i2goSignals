package goSetPoll

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Benchmarks for the pkg/goSetPoll wire hot path: RFC 8936 poll request
// decode and poll response encode, at the batch sizes a busy stream actually
// carries.
//
// These are part of the spec #101 (Go 1.27 adoption) measurement floor
// recorded in docs/perf/go127-baseline.md. Both sides are pure encoding/json
// work, which makes this package the most direct read on the Go 1.27 json/v2
// engine change. Keep the workload stable — the per-slice delta table
// compares against these exact batch sizes.

// benchSetToken is a stand-in wire token: poll encoding never inspects the
// SET, it only moves the string, so a fixed-length opaque value keeps the
// measurement about the encoder rather than about signing.
const benchSetToken = "eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHBzOi8vdHJhbnNtaXR0ZXIuZXhhbXBsZS5jb20iLCJ0eXAiOiJzZWNldmVudCtqd3QifQ." +
	"eyJhdWQiOlsicmVjZWl2ZXIuZXhhbXBsZS5jb20iXSwiZXZlbnRzIjp7InVybjppZXRmOnBhcmFtczpzY2ltOmV2ZW50OnByb3Y6Y3JlYXRlOmZ1bGwiOnt9fX0." +
	"c2lnbmF0dXJlLXBsYWNlaG9sZGVyLWJ5dGVzLXRoYXQtYXJlLXJvdWdobHktdGhlLXJpZ2h0LWxlbmd0aA"

// benchJtis builds n synthetic jtis in the pre-#274 ksuid shape. The
// server mints UUIDv7 jtis now, but this workload stays deliberately frozen so
// the per-slice delta table keeps comparing like with like.
func benchJtis(n int) []string {
	jtis := make([]string, n)
	for i := range jtis {
		jtis[i] = fmt.Sprintf("2fY4Xz9kQpLmNbVcRsTuWxYz%04d", i)
	}
	return jtis
}

// benchPollRequest is the receiver-side request shape: a bounded batch
// request that also acknowledges the previous batch.
func benchPollRequest(acks int) PollRequest {
	return PollRequest{
		MaxEvents:         100,
		ReturnImmediately: false,
		Acks:              benchJtis(acks),
		SetErrs: map[string]SetErrType{
			"2fY4Xz9kQpLmNbVcRsTuWxYzBAD0": {Error: "invalid_key", Description: "kid not found in issuer JWKS"},
		},
		TimeoutSecs: 30,
	}
}

// benchPollResponse is the transmitter-side response shape: n SETs keyed by
// jti, with more still queued.
func benchPollResponse(sets int) PollResponse {
	m := make(map[string]string, sets)
	for _, jti := range benchJtis(sets) {
		m[jti] = benchSetToken
	}
	return PollResponse{Sets: m, MoreAvailable: true}
}

// BenchmarkParsePollRequest measures transmitter-side request decode.
func BenchmarkParsePollRequest(b *testing.B) {
	body, err := json.Marshal(benchPollRequest(100))
	if err != nil {
		b.Fatalf("marshal: %v", err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := httptest.NewRequest(http.MethodPost, "/poll", bytes.NewReader(body))
		req, err := ParsePollRequest(r)
		if err != nil {
			b.Fatalf("ParsePollRequest: %v", err)
		}
		if len(req.Acks) != 100 {
			b.Fatalf("expected 100 acks, got %d", len(req.Acks))
		}
	}
}

// BenchmarkWritePollResponse measures transmitter-side response encode at the
// batch sizes a poll stream actually returns. WritePollResponse uses
// MarshalIndent, so this is the real cost the server pays per poll.
func BenchmarkWritePollResponse(b *testing.B) {
	for _, sets := range []int{1, 10, 100} {
		response := benchPollResponse(sets)
		b.Run(fmt.Sprintf("sets=%d", sets), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				w := httptest.NewRecorder()
				WritePollResponse(w, response)
				if w.Code != http.StatusOK {
					b.Fatalf("status %d", w.Code)
				}
			}
		})
	}
}

// BenchmarkPollRequestMarshal measures the receiver side of the same wire:
// encoding the request body it POSTs each cycle.
func BenchmarkPollRequestMarshal(b *testing.B) {
	request := benchPollRequest(100)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := json.Marshal(request); err != nil {
			b.Fatalf("marshal: %v", err)
		}
	}
}

// BenchmarkPollResponseUnmarshal measures the receiver side decoding a full
// batch of SETs out of the response body.
func BenchmarkPollResponseUnmarshal(b *testing.B) {
	body, err := json.Marshal(benchPollResponse(100))
	if err != nil {
		b.Fatalf("marshal: %v", err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var response PollResponse
		if err := json.Unmarshal(body, &response); err != nil {
			b.Fatalf("unmarshal: %v", err)
		}
		if len(response.Sets) != 100 {
			b.Fatalf("expected 100 sets, got %d", len(response.Sets))
		}
	}
}
