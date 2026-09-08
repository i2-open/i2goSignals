package goSetSstp_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/MicahParks/keyfunc/v2"
	"github.com/golang-jwt/jwt/v5"

	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/goSetSstp"
)

// Batch-verification benchmarks: how long does it take to verify the SETs of
// one inbound SSTP (or poll) batch, serially as the acceptor and the dialer's
// inbound half do today, versus fanned out over a worker pool?
//
//	go test ./pkg/goSetSstp -run xxx -bench BenchmarkVerifyBatch -benchmem -cpuprofile cpu.out
//
// The reported ns/op is per BATCH; batch-size and worker count are in the
// sub-benchmark name.

type benchSigner struct {
	alg    string
	method jwt.SigningMethod
	key    crypto.Signer
	jwks   *keyfunc.JWKS
}

func newBenchSigner(b *testing.B, alg string) benchSigner {
	b.Helper()
	const kid = "bench-kid"
	var (
		key crypto.Signer
		pub any
		m   jwt.SigningMethod
		err error
	)
	switch alg {
	case "RS256":
		var k *rsa.PrivateKey
		k, err = rsa.GenerateKey(rand.Reader, 2048)
		key, pub, m = k, &k.PublicKey, jwt.SigningMethodRS256
	case "ES256":
		var k *ecdsa.PrivateKey
		k, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		key, pub, m = k, &k.PublicKey, jwt.SigningMethodES256
	case "EdDSA":
		var pk ed25519.PublicKey
		var k ed25519.PrivateKey
		pk, k, err = ed25519.GenerateKey(rand.Reader)
		key, pub, m = k, pk, jwt.SigningMethodEdDSA
	default:
		b.Fatalf("unknown alg %s", alg)
	}
	if err != nil {
		b.Fatalf("gen %s key: %v", alg, err)
	}
	given := keyfunc.NewGivenCustom(pub, keyfunc.GivenKeyOptions{Algorithm: alg})
	return benchSigner{alg: alg, method: m, key: key, jwks: keyfunc.NewGiven(map[string]keyfunc.GivenKey{kid: given})}
}

// signBenchBatch signs n SETs shaped like a typical SCIM/CAEP event: one
// event URI with a small payload and an email subject.
func signBenchBatch(b *testing.B, s benchSigner, n int) []string {
	b.Helper()
	out := make([]string, n)
	for i := range out {
		set := goSet.SecurityEventToken{
			RegisteredClaims: jwt.RegisteredClaims{
				ID:       fmt.Sprintf("jti-%06d", i),
				Issuer:   testIssuer,
				Audience: jwt.ClaimStrings{testAudience},
				IssuedAt: jwt.NewNumericDate(time.Now()),
			},
			Events: map[string]any{
				"https://schemas.openid.net/secevent/caep/event-type/session-revoked": map[string]any{
					"subject":         map[string]any{"format": "email", "email": fmt.Sprintf("user%d@example.com", i)},
					"event_timestamp": time.Now().Unix(),
					"reason_admin":    map[string]any{"en": "benchmark"},
				},
			},
			Kid: "bench-kid",
		}
		tok, err := set.JWS(s.method, s.key)
		if err != nil {
			b.Fatalf("sign: %v", err)
		}
		out[i] = tok
	}
	return out
}

func verifySerial(b *testing.B, toks []string, cfg goSetSstp.VerifyConfig) {
	for _, t := range toks {
		if _, err := goSetSstp.VerifySET(t, cfg); err != nil {
			b.Fatalf("verify: %v", err)
		}
	}
}

// verifyPool verifies toks with `workers` goroutines pulling from a shared
// index; results land in a preallocated slice so ordering is preserved.
func verifyPool(b *testing.B, toks []string, cfg goSetSstp.VerifyConfig, workers int) {
	if workers > len(toks) {
		workers = len(toks)
	}
	if workers <= 1 {
		verifySerial(b, toks, cfg)
		return
	}
	results := make([]goSetSstp.VerifiedSET, len(toks))
	errs := make([]error, len(toks))
	next := make(chan int, len(toks))
	for i := range toks {
		next <- i
	}
	close(next)
	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			for i := range next {
				results[i], errs[i] = goSetSstp.VerifySET(toks[i], cfg)
			}
		}()
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			b.Fatalf("verify: %v", err)
		}
	}
}

func BenchmarkVerifyBatch(b *testing.B) {
	sizes := []int{1, 10, 100, 1000}
	workerCounts := []int{1, 2, 4, 8, runtime.GOMAXPROCS(0)}
	for _, alg := range []string{"RS256", "ES256", "EdDSA"} {
		s := newBenchSigner(b, alg)
		cfg := goSetSstp.VerifyConfig{
			JWKS:              s.jwks,
			ExpectedIssuer:    testIssuer,
			ExpectedAudiences: []string{testAudience},
			RequireSignature:  true,
		}
		for _, n := range sizes {
			toks := signBenchBatch(b, s, n)
			for _, w := range workerCounts {
				if w > n {
					continue
				}
				b.Run(fmt.Sprintf("%s/batch=%d/workers=%d", alg, n, w), func(b *testing.B) {
					b.ReportAllocs()
					for i := 0; i < b.N; i++ {
						verifyPool(b, toks, cfg, w)
					}
					b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N)/float64(n)/1000, "µs/SET")
				})
			}
		}
	}
}

// BenchmarkVerifyStages isolates the pieces of one RS256 VerifySET call so a
// profile can be read against them: the unverified pre-parse, the verified
// parse (signature), and the whole thing.
func BenchmarkVerifyStages(b *testing.B) {
	s := newBenchSigner(b, "RS256")
	tok := signBenchBatch(b, s, 1)[0]
	cfg := goSetSstp.VerifyConfig{JWKS: s.jwks, ExpectedIssuer: testIssuer, ExpectedAudiences: []string{testAudience}, RequireSignature: true}
	b.Run("peek-unverified", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := goSet.Peek(tok); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("goSet.Parse-verified", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := goSet.Parse(tok, s.jwks); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("rsa.VerifyPKCS1v15-only", func(b *testing.B) {
		pub := &s.key.(*rsa.PrivateKey).PublicKey
		digest := make([]byte, 32)
		sig, _ := rsa.SignPKCS1v15(rand.Reader, s.key.(*rsa.PrivateKey), crypto.SHA256, digest)
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest, sig); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("VerifySET", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := goSetSstp.VerifySET(tok, cfg); err != nil {
				b.Fatal(err)
			}
		}
	})
	// The transmitter-side counterpart: re-signing one SET in PUBLISH mode,
	// which every outbound poll/SSTP batch pays per SET.
	b.Run("sign-RS256", func(b *testing.B) {
		set := goSet.SecurityEventToken{
			RegisteredClaims: jwt.RegisteredClaims{ID: "jti-sign", Issuer: testIssuer, Audience: jwt.ClaimStrings{testAudience}, IssuedAt: jwt.NewNumericDate(time.Now())},
			Events:           map[string]any{"https://schemas.openid.net/secevent/caep/event-type/session-revoked": map[string]any{"subject": map[string]any{"format": "email", "email": "user@example.com"}}},
			Kid:              "bench-kid",
		}
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := set.JWS(jwt.SigningMethodRS256, s.key); err != nil {
				b.Fatal(err)
			}
		}
	})
}
