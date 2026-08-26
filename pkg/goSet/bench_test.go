package goSet

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"testing"

	"github.com/MicahParks/keyfunc/v2"
	"github.com/golang-jwt/jwt/v5"
)

// Benchmarks for the pkg/goSet hot path: SET construction, JSON
// marshal/unmarshal, JWS signing, and both parse entry points (verified
// Parse and unverified Peek).
//
// These are the measurement floor for spec #101 (Go 1.27 adoption) —
// docs/perf/go127-baseline.md records their numbers under go1.26.5 and
// go1.27.0, and every later slice of the spec re-runs them and appends a
// delta row. Keep the workload stable: changing what a benchmark measures
// invalidates every row already in that table.

const (
	benchIssuer   = "https://transmitter.example.com"
	benchAudience = "receiver.example.com"
	benchEventUri = "urn:ietf:params:SCIM:event:prov:create:full"
)

// benchKey is generated once for the whole package. RSA keygen is orders of
// magnitude slower than anything under test, so it must never land inside a
// timed loop.
var benchKey = func() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic("goSet bench: rsa keygen: " + err.Error())
	}
	return key
}()

// benchSubject is a representative sub_id: a SCIM subject carrying the three
// identifier members the router actually filters on.
func benchSubject() *EventSubject {
	return &EventSubject{
		SubjectIdentifier: *NewScimSubjectIdentifier("/Users/2819c223-7f76-453a-919d-413861904646").
			AddUsername("bjensen").
			AddEmail("bjensen@example.com"),
	}
}

// benchSet builds the SET every benchmark below operates on: a sub_id
// subject plus one SCIM event payload with a handful of claims. This is the
// shape the event router marshals and parses per event.
func benchSet() *SecurityEventToken {
	set := CreateSet(benchSubject(), benchIssuer, []string{benchAudience})
	set.Kid = benchIssuer
	set.AddEventPayload(benchEventUri, map[string]interface{}{
		"attributes": []string{"id", "name", "userName", "password", "emails"},
		"ref":        "https://scim.example.com/v2/Users/2819c223-7f76-453a-919d-413861904646",
	})
	return &set
}

// benchSigned returns a signed wire token plus a JWKS that verifies it.
func benchSigned(b *testing.B) (string, *keyfunc.JWKS) {
	b.Helper()
	token, err := benchSet().JWS(jwt.SigningMethodRS256, benchKey)
	if err != nil {
		b.Fatalf("JWS: %v", err)
	}
	jwks := keyfunc.NewGiven(map[string]keyfunc.GivenKey{
		benchIssuer: keyfunc.NewGivenRSA(&benchKey.PublicKey, keyfunc.GivenKeyOptions{Algorithm: "RS256"}),
	})
	return token, jwks
}

// BenchmarkCreateSet measures envelope construction, which includes the
// per-event UUIDv7 jti allocation.
func BenchmarkCreateSet(b *testing.B) {
	subject := benchSubject()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		set := CreateSet(subject, benchIssuer, []string{benchAudience})
		_ = set.ID
	}
}

// BenchmarkSetJsonBytes measures the marshal side — the encoding/json path
// that json/v2 replaces in Go 1.27.
func BenchmarkSetJsonBytes(b *testing.B) {
	set := benchSet()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if len(set.JsonBytes()) == 0 {
			b.Fatal("JsonBytes returned empty")
		}
	}
}

// BenchmarkSetJsonUnmarshal measures the unmarshal side into the SET struct,
// whose deeply embedded SubjectIdentifier is the interesting case for a
// decoder change.
func BenchmarkSetJsonUnmarshal(b *testing.B) {
	raw := benchSet().JsonBytes()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var set SecurityEventToken
		if err := json.Unmarshal(raw, &set); err != nil {
			b.Fatalf("Unmarshal: %v", err)
		}
	}
}

// BenchmarkSetJWS measures signing, the transmitter-side per-event cost.
func BenchmarkSetJWS(b *testing.B) {
	set := benchSet()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := set.JWS(jwt.SigningMethodRS256, benchKey); err != nil {
			b.Fatalf("JWS: %v", err)
		}
	}
}

// BenchmarkSetPeek measures the unverified parse used by push receivers for
// pre-verify routing.
func BenchmarkSetPeek(b *testing.B) {
	token, _ := benchSigned(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Peek(token); err != nil {
			b.Fatalf("Peek: %v", err)
		}
	}
}

// BenchmarkSetParse measures the verified trust path: parse plus RSA
// signature verification against a JWKS.
func BenchmarkSetParse(b *testing.B) {
	token, jwks := benchSigned(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Parse(token, jwks); err != nil {
			b.Fatalf("Parse: %v", err)
		}
	}
}
