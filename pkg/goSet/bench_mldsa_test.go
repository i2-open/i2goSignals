package goSet

// RFC 9964 signing/verification benchmarks (i2goSignals#278).
//
// These are NEW rows against docs/perf/go127-baseline.md, not deltas: nothing
// signed SETs with ML-DSA before this slice. They sit beside BenchmarkSetJWS
// and BenchmarkSetParse deliberately, so the pair can be read as the actual
// cost of a stream's signing_alg opt-in on the same SET, on the same machine,
// in the same run.
//
// The number that matters most is not in the ns/op column: an ML-DSA-65
// signature is 3309 bytes against RS256's 256, so the benchmark also reports
// the wire size — the cost the receiver pays and the reason the opt-in is per
// stream (ADR 0034).

import (
	cryptomldsa "crypto/mldsa"
	"testing"

	"github.com/MicahParks/keyfunc/v2"

	"github.com/i2-open/i2goSignals/pkg/goSet/mldsa"
)

// benchMLDSAKey is generated once for the package, for the same reason
// benchKey is: keygen must never land inside a timed loop.
var benchMLDSAKey = func() *cryptomldsa.PrivateKey {
	key, err := mldsa.GenerateKey()
	if err != nil {
		panic("goSet bench: mldsa keygen: " + err.Error())
	}
	return key
}()

func benchMLDSAJwks() *keyfunc.JWKS {
	return keyfunc.NewGiven(map[string]keyfunc.GivenKey{
		benchIssuer: keyfunc.NewGivenCustom(benchMLDSAKey.PublicKey(),
			keyfunc.GivenKeyOptions{Algorithm: mldsa.Alg}),
	})
}

// BenchmarkSetJWSMLDSA is BenchmarkSetJWS's post-quantum counterpart: the
// transmitter-side per-event signing cost for a stream on signing_alg
// ML-DSA-65.
func BenchmarkSetJWSMLDSA(b *testing.B) {
	set := benchSet()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := set.JWS(mldsa.SigningMethodMLDSA65, benchMLDSAKey); err != nil {
			b.Fatalf("JWS: %v", err)
		}
	}
}

// BenchmarkSetParseMLDSA is BenchmarkSetParse's counterpart: the receiver-side
// per-event verified parse of a PQ-signed SET.
func BenchmarkSetParseMLDSA(b *testing.B) {
	set := benchSet()
	token, err := set.JWS(mldsa.SigningMethodMLDSA65, benchMLDSAKey)
	if err != nil {
		b.Fatalf("JWS: %v", err)
	}
	jwks := benchMLDSAJwks()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Parse(token, jwks); err != nil {
			b.Fatalf("Parse: %v", err)
		}
	}
}

// BenchmarkSetWireSizeByAlg reports no meaningful time — it exists for its
// custom metric. bytes/token is the figure an operator needs before opting a
// stream in, and putting it in the benchmark output keeps it measured rather
// than quoted from the spec.
func BenchmarkSetWireSizeByAlg(b *testing.B) {
	set := benchSet()
	classical, err := set.JWS(SigningMethodOrRS256(""), benchKey)
	if err != nil {
		b.Fatalf("JWS: %v", err)
	}
	postQuantum, err := set.JWS(SigningMethodOrRS256(mldsa.Alg), benchMLDSAKey)
	if err != nil {
		b.Fatalf("JWS: %v", err)
	}

	b.Run("RS256", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = len(classical)
		}
		b.ReportMetric(float64(len(classical)), "bytes/token")
	})
	b.Run("ML-DSA-65", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = len(postQuantum)
		}
		b.ReportMetric(float64(len(postQuantum)), "bytes/token")
	})
}
