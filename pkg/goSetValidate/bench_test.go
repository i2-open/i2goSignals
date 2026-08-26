package goSetValidate

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/MicahParks/keyfunc/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/i2-open/i2goSignals/pkg/goSet"
)

// Benchmarks for the pkg/goSetValidate hot path: per-SET event-payload
// validation as the receiver runs it, plus the ParseAndValidate entry point
// that fuses signature verification with validation.
//
// These are part of the spec #101 (Go 1.27 adoption) measurement floor
// recorded in docs/perf/go127-baseline.md. Keep the workload stable — the
// per-slice delta table compares against these exact shapes.

const benchIssuer = "https://transmitter.example.com"

// benchScimSet builds the well-formed RFC 9967 envelope the SCIM pack expects:
// a format "scim" sub_id plus one create:full payload.
func benchScimSet() *goSet.SecurityEventToken {
	set := goSet.CreateSet(nil, benchIssuer, []string{"receiver.example.com"})
	set.SubjectId = &goSet.SubjectIdentifier{
		Format:                    "scim",
		UniformResourceIdentifier: goSet.UniformResourceIdentifier{Uri: "/Users/2b2f880af6674ac284bae9381673d462"},
	}
	set.AddEventPayload(scimCreateFullEventUri, map[string]any{
		"data": map[string]any{
			"userName": "jdoe",
			"name":     map[string]any{"givenName": "John", "familyName": "Doe"},
			"emails":   []any{map[string]any{"value": "jdoe@example.com", "primary": true}},
		},
	})
	return &set
}

// BenchmarkBuiltinRegistry measures the per-call cost of building the full
// validator pack set (SSF + CAEP + RISC + SCIM + WISE). SharedBuiltinRegistry
// exists precisely so the hot path does not pay this; the benchmark keeps that
// justification measurable.
func BenchmarkBuiltinRegistry(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if BuiltinRegistry() == nil {
			b.Fatal("nil registry")
		}
	}
}

// BenchmarkNewValidatorSet measures per-stream engagement-set construction.
func BenchmarkNewValidatorSet(b *testing.B) {
	registry := SharedBuiltinRegistry()
	engaged := []string{scimCreateFullEventUri, scimPatchFullEventUri, scimDeleteEventUri, caepSessionRevokedEventUri}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if NewValidatorSet(registry, engaged) == nil {
			b.Fatal("nil validator set")
		}
	}
}

// BenchmarkValidateEngaged is the ordinary in-contract path: one engaged SCIM
// event whose payload passes every check.
func BenchmarkValidateEngaged(b *testing.B) {
	set := benchScimSet()
	vs := NewValidatorSet(SharedBuiltinRegistry(), []string{scimCreateFullEventUri})
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if vs.Validate(set).Disposition != Valid {
			b.Fatal("expected Valid")
		}
	}
}

// BenchmarkValidateUnsupported is the out-of-contract path: engagement lookup
// misses, so nothing vouches for the payload and no validator runs.
func BenchmarkValidateUnsupported(b *testing.B) {
	set := benchScimSet()
	vs := NewValidatorSet(SharedBuiltinRegistry(), []string{scimDeleteEventUri})
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if vs.Validate(set).Disposition != Unsupported {
			b.Fatal("expected Unsupported")
		}
	}
}

// BenchmarkValidateMultiEvent exercises the sort + reduce loop over a SET
// carrying several event URIs, which is where per-event cost compounds.
func BenchmarkValidateMultiEvent(b *testing.B) {
	set := benchScimSet()
	set.AddEventPayload(scimCreateNoticeEventUri, map[string]any{"attributes": []any{"userName", "emails"}})
	set.AddEventPayload(scimActivateEventUri, map[string]any{})
	set.AddEventPayload(scimFeedAddEventUri, map[string]any{})

	vs := NewValidatorSet(SharedBuiltinRegistry(), []string{
		scimCreateFullEventUri, scimCreateNoticeEventUri, scimActivateEventUri, scimFeedAddEventUri,
	})
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if vs.Validate(set).Disposition != Valid {
			b.Fatal("expected Valid")
		}
	}
}

// BenchmarkParseAndValidate measures the fused receiver entry point: verified
// parse of a signed wire token followed by payload validation.
func BenchmarkParseAndValidate(b *testing.B) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatalf("rsa keygen: %v", err)
	}
	set := benchScimSet()
	set.Kid = benchIssuer
	token, err := set.JWS(jwt.SigningMethodRS256, key)
	if err != nil {
		b.Fatalf("JWS: %v", err)
	}
	jwks := keyfunc.NewGiven(map[string]keyfunc.GivenKey{
		benchIssuer: keyfunc.NewGivenRSA(&key.PublicKey, keyfunc.GivenKeyOptions{Algorithm: "RS256"}),
	})
	vs := NewValidatorSet(SharedBuiltinRegistry(), []string{scimCreateFullEventUri})

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, result, err := ParseAndValidate(token, jwks, vs)
		if err != nil {
			b.Fatalf("ParseAndValidate: %v", err)
		}
		if result.Disposition != Valid {
			b.Fatalf("expected Valid, got %v", result.Disposition)
		}
	}
}
