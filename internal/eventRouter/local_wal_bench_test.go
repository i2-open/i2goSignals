package eventRouter

import (
	"sync"
	"testing"
	"time"

	"github.com/i2-open/i2goSignals/internal/wal"
)

// BenchmarkMongoRouterWalIngest ingests 5000 SETs from 16 concurrent clients
// through the router against a real MongoDB, once in the default majority
// mode and once in ADR 0045 local mode. Run with -benchtime=1x; see
// docs/perf/local-wal-340.md.
//
//	ack-ev/s    SETs acknowledged per second (what an ingest client sees)
//	stored-ev/s SETs acknowledged AND in Mongo per second (local mode waits
//	            for the drain worker to empty the WAL)
func BenchmarkMongoRouterWalIngest(b *testing.B) {
	const events, clients = 5000, 16
	for _, mode := range []string{"majority", "local"} {
		b.Run(mode, func(b *testing.B) {
			var log wal.Log
			if mode == "local" {
				l, err := wal.OpenBolt(b.TempDir())
				if err != nil {
					b.Fatal(err)
				}
				log = l
			}
			m := newMongoRouterBenchWith(b, log)
			b.ResetTimer()
			for n := 0; n < b.N; n++ {
				start := time.Now()
				var wg sync.WaitGroup
				for c := 0; c < clients; c++ {
					wg.Add(1)
					go func(c int) {
						defer wg.Done()
						for i := c; i < events; i += clients {
							if err := m.r.HandleEvent(m.mkSet(n*events+i), "eyJ.bench.raw", m.rxSid); err != nil {
								b.Error(err)
								return
							}
						}
					}(c)
				}
				wg.Wait()
				acked := time.Since(start)
				if log != nil {
					for log.Depth() > 0 {
						time.Sleep(time.Millisecond)
					}
				}
				stored := time.Since(start)
				b.ReportMetric(float64(events)/acked.Seconds(), "ack-ev/s")
				b.ReportMetric(float64(events)/stored.Seconds(), "stored-ev/s")
			}
		})
	}
}
