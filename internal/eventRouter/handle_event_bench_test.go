package eventRouter

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/MicahParks/keyfunc/v2"
	"github.com/golang-jwt/jwt/v5"

	"github.com/i2-open/i2goSignals/internal/providers/dbProviders"
	"github.com/i2-open/i2goSignals/pkg/authSupport"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/goSetSstp"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// Mongo-backed router benchmarks. They measure the per-SET cost of the paths a
// batch pays on the dev replica set, so the numbers include the DAO round
// trips the in-memory provider hides:
//
//	ingest        HandleEvent for one SET arriving on an SSTP pair's inbound
//	              side and fanning out to one outbound poll stream — what the
//	              acceptor, the dialer's inbound half, the poll receiver and
//	              the push receiver each pay AFTER signature verification.
//	verify+ingest VerifySET (RS256) followed by HandleEvent — the full per-SET
//	              cost of an inbound SSTP batch on the responder.
//	drain+ack     GetEventRecord + RS256 re-sign + AckEvent — the transmitter
//	              side of one outbound SET in PUBLISH mode.
//
// The database is a throwaway (handle_event_bench) dropped on exit. Point
// MONGO_URL at another replica set to run elsewhere; the benchmarks skip when
// Mongo is unreachable.
//
//	go test ./internal/eventRouter -run xxx -bench BenchmarkMongoRouter -benchtime 300x -benchmem -cpuprofile cpu.out

const benchMongoDefaultURL = "mongodb://root:dockTest@mongo1:30001,mongo2:30002,mongo3:30003/?retryWrites=true&replicaSet=dbrs&readPreference=primary&serverSelectionTimeoutMS=5000&connectTimeoutMS=10000&authSource=admin&authMechanism=SCRAM-SHA-256"

func benchMongoURL() string {
	if u := os.Getenv("MONGO_URL"); u != "" {
		return u
	}
	return benchMongoDefaultURL
}

const benchEventType = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"

type mongoRouterBench struct {
	p         *dbProviders.Persistence
	r         *router
	ctx       context.Context
	rxSid     string // SSTP inbound (receive) SID the SETs arrive on
	outSid    string // outbound poll stream the SETs fan out to
	signer    *rsa.PrivateKey
	verifyCfg goSetSstp.VerifyConfig
}

func newMongoRouterBench(b *testing.B) *mongoRouterBench {
	b.Helper()
	b.Setenv("I2SIG_STORE_MONGO_RESUME_FILE", filepath.Join(b.TempDir(), "mongo_token.json"))
	p, err := dbProviders.OpenPersistence(benchMongoURL(), "handle_event_bench")
	if err != nil {
		b.Skipf("mongo unreachable (%v); set MONGO_URL or start the dev stack", err)
	}
	if err := p.Storage.Check(); err != nil {
		_ = p.Storage.Close()
		b.Skipf("mongo unreachable (%v); set MONGO_URL or start the dev stack", err)
	}
	b.Cleanup(func() {
		_ = p.Storage.ResetDb(false)
		_ = p.Storage.Close()
	})
	r := NewRouter(RouterDeps{
		StreamService: p.StreamService,
		KeyService:    p.KeyService,
		EventService:  p.EventService,
		Coordinator:   p.Coordinator,
	}, "node-bench").(*router)
	b.Cleanup(r.Shutdown)

	iat, err := p.KeyService.GetAuthIssuer().IssueProjectIat(nil)
	if err != nil {
		b.Fatal(err)
	}
	parsed, err := p.KeyService.GetAuthIssuer().ParseAuthToken(iat)
	if err != nil {
		b.Fatal(err)
	}
	projectId := parsed.ProjectId
	ctx := context.WithValue(context.Background(), authSupport.AuthContextKey, authSupport.ConvertProject(projectId))

	baseUrl, _ := url.Parse("https://local.example")
	p.StreamService.SetBaseUrl(baseUrl)
	pair, err := p.StreamService.CreateSstpPair(context.Background(), model.SstpPairBootstrap{
		Role:        model.SstpRoleResponder,
		Description: "bench pair",
		Primary:     model.SstpDirection{Iss: "https://tx.issuer.example", Aud: []string{"https://tx.audience.example"}, Mode: model.SstpModePublish, Events: []string{benchEventType}},
		Inbound:     model.SstpDirection{Iss: "https://rx.issuer.example", Aud: []string{"https://rx.audience.example"}, Mode: model.SstpModeForward, Events: []string{benchEventType}},
	}, projectId, nil)
	if err != nil {
		b.Fatal(err)
	}

	created, err := p.StreamService.CreateStream(ctx, model.StreamStateRecord{
		StreamConfiguration: model.StreamConfiguration{
			Aud:             []string{"https://downstream.example.com"},
			RouteMode:       model.RouteModePublish,
			EventsRequested: []string{benchEventType},
			Delivery: &model.OneOfStreamConfigurationDelivery{
				PollTransmitMethod: &model.PollTransmitMethod{Method: model.DeliveryPoll, EndpointUrl: "https://transmitter.example.com/events"},
			},
		},
		EventSource: &model.EventSource{Type: model.EventSourceAudience},
	}, projectId, nil)
	if err != nil {
		b.Fatal(err)
	}
	state, err := p.StreamService.GetStreamState(context.Background(), created.Id)
	if err != nil {
		b.Fatal(err)
	}
	r.UpdateStreamState(state)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatal(err)
	}
	given := keyfunc.NewGivenCustom(&key.PublicKey, keyfunc.GivenKeyOptions{Algorithm: "RS256"})
	return &mongoRouterBench{
		p: p, r: r, ctx: ctx, rxSid: pair.SstpInbound.Id, outSid: created.Id, signer: key,
		verifyCfg: goSetSstp.VerifyConfig{
			JWKS:              keyfunc.NewGiven(map[string]keyfunc.GivenKey{"bench-kid": given}),
			ExpectedIssuer:    "https://rx.issuer.example",
			ExpectedAudiences: []string{"https://rx.audience.example"},
			RequireSignature:  true,
		},
	}
}

func (m *mongoRouterBench) mkSet(i int) *goSet.SecurityEventToken {
	return &goSet.SecurityEventToken{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:       fmt.Sprintf("bench-jti-%d-%d", time.Now().UnixNano(), i),
			Issuer:   "https://rx.issuer.example",
			Audience: jwt.ClaimStrings{"https://rx.audience.example"},
			IssuedAt: jwt.NewNumericDate(time.Now()),
		},
		Events: map[string]any{benchEventType: map[string]any{"subject": map[string]any{"format": "email", "email": "user@example.com"}}},
		Kid:    "bench-kid",
	}
}

func (m *mongoRouterBench) sign(b *testing.B, set *goSet.SecurityEventToken) string {
	b.Helper()
	tok, err := set.JWS(jwt.SigningMethodRS256, m.signer)
	if err != nil {
		b.Fatal(err)
	}
	return tok
}

// pendingOut reports how many SETs are queued on the outbound stream, so a run
// where fan-out silently stopped matching is visible in the output.
func (m *mongoRouterBench) pendingOut(max int) int {
	jtis, _ := m.p.EventService.GetEventIds(context.Background(), m.outSid, model.PollParameters{MaxEvents: int32(max), ReturnImmediately: true})
	return len(jtis)
}

func BenchmarkMongoRouter(b *testing.B) {
	m := newMongoRouterBench(b)

	b.Run("ingest", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := m.r.HandleEvent(m.mkSet(i), "eyJ.bench.raw", m.rxSid); err != nil {
				b.Fatal(err)
			}
		}
		b.StopTimer()
		b.ReportMetric(float64(m.pendingOut(b.N+1)), "pending-out")
	})

	// One 100-SET batch ingested through `workers` goroutines: what the
	// acceptor would pay per SET if it pipelined HandleEvent across the batch
	// instead of walking it serially. ns/op is per batch; see µs/SET.
	for _, w := range []int{1, 4, 8, 16} {
		b.Run(fmt.Sprintf("ingest-batch100/workers=%d", w), func(b *testing.B) {
			const n = 100
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				sets := make([]*goSet.SecurityEventToken, n)
				for j := range sets {
					sets[j] = m.mkSet(3_000_000 + i*n + j)
				}
				next := make(chan int, n)
				for j := 0; j < n; j++ {
					next <- j
				}
				close(next)
				errs := make([]error, n)
				var wg sync.WaitGroup
				wg.Add(w)
				for k := 0; k < w; k++ {
					go func() {
						defer wg.Done()
						for j := range next {
							errs[j] = m.r.HandleEvent(sets[j], "eyJ.bench.raw", m.rxSid)
						}
					}()
				}
				wg.Wait()
				for _, err := range errs {
					if err != nil {
						b.Fatal(err)
					}
				}
			}
			b.StopTimer()
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N)/n/1000, "µs/SET")
		})
	}

	b.Run("verify+ingest", func(b *testing.B) {
		toks := make([]string, b.N)
		for i := range toks {
			toks[i] = m.sign(b, m.mkSet(1_000_000+i))
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			v, err := goSetSstp.VerifySET(toks[i], m.verifyCfg)
			if err != nil {
				b.Fatal(err)
			}
			if err := m.r.HandleEvent(v.Token, toks[i], m.rxSid); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("drain+ack", func(b *testing.B) {
		// Everything ingested above is pending on the outbound stream; take
		// b.N of it through the transmitter's per-SET sequence.
		jtis, _ := m.p.EventService.GetEventIds(context.Background(), m.outSid, model.PollParameters{MaxEvents: int32(b.N), ReturnImmediately: true})
		for len(jtis) < b.N {
			if err := m.r.HandleEvent(m.mkSet(2_000_000+len(jtis)), "eyJ.bench.raw", m.rxSid); err != nil {
				b.Fatal(err)
			}
			jtis, _ = m.p.EventService.GetEventIds(context.Background(), m.outSid, model.PollParameters{MaxEvents: int32(b.N), ReturnImmediately: true})
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			rec := m.p.EventService.GetEventRecord(context.Background(), jtis[i])
			if rec == nil {
				b.Fatalf("event %s vanished", jtis[i])
			}
			tok := &rec.Event
			tok.Issuer = "https://local.example"
			tok.Audience = jwt.ClaimStrings{"https://downstream.example.com"}
			tok.IssuedAt = jwt.NewNumericDate(time.Now())
			if _, err := tok.JWS(jwt.SigningMethodRS256, m.signer); err != nil {
				b.Fatal(err)
			}
			if err := m.p.EventService.AckEvent(context.Background(), jtis[i], m.outSid, 0); err != nil {
				b.Fatal(err)
			}
		}
	})
}
