package services

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"testing/synctest"
	"time"

	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/dao/memory"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// TestPingPurger_FirstRunDrainsPreUpgradeBacklog (#389): a 30-day backlog of
// pre-upgrade pings (no receivedAt, delivery rows loaded from disk without a
// marker) drains oldest-first in one-hour windows, pausing between windows;
// a run cut short resumes where it stopped, so the windows stay ascending and
// contiguous across runs, and the backlog drains fully.
func TestPingPurger_FirstRunDrainsPreUpgradeBacklog(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const days, perRun = 30, 100
		start := time.Now().UTC().Truncate(time.Hour).Add(-(days + 1) * 24 * time.Hour)
		evs := map[string]*model.EventRecord{}
		var delivered []interfaces.DeliveredEvent
		for i := 0; i < days*24; i++ {
			at := start.Add(time.Duration(i) * time.Hour)
			jti := fmt.Sprintf("pre-%03d", i)
			rec := pingRecord(jti, at)
			rec.ReceivedAt = time.Time{} // stored before ADR 0048
			evs[jti] = rec
			delivered = append(delivered, interfaces.DeliveredEvent{
				DeliverableEvent: interfaces.DeliverableEvent{Jti: jti, AckJti: jti, CreatedAt: at},
				AckDate:          at,
			})
		}
		mem := memory.NewEventDAO()
		mem.SetState(evs, map[string][]interfaces.DeliverableEvent{}, map[string][]interfaces.DeliveredEvent{"s1": delivered})

		d := &hookDAO{EventDAOMemory: mem}
		coord := &fakePurgeCoord{now: time.Now}
		const pause = time.Second
		p := NewPingPurger(d, coord, "n1", PingPurgeOptions{Retention: 24 * time.Hour, Pause: pause})

		var deliveries, bodies int64
		for run := 0; ; run++ {
			if run > days*24/perRun+1 {
				t.Fatalf("backlog not drained after %d runs", run)
			}
			ctx, cancel := context.WithCancel(context.Background())
			base := d.windowCount()
			d.after = func(n int) {
				if n-base == perRun {
					cancel()
				}
			}
			sum, err := p.RunOnce(ctx)
			cancel()
			deliveries += sum.Deliveries
			bodies += sum.Bodies
			if sum.Windows > 1 && sum.Duration < time.Duration(sum.Windows-1)*pause {
				t.Fatalf("run %d: %d windows in %v, want >= %v of pauses", run, sum.Windows, sum.Duration, time.Duration(sum.Windows-1)*pause)
			}
			if err == nil {
				if !sum.Ran {
					t.Fatalf("run %d did not run: %+v", run, sum)
				}
				break
			}
			if !errors.Is(err, context.Canceled) || sum.Windows != perRun {
				t.Fatalf("run %d = %+v, %v; want cancelled after %d windows", run, sum, err, perRun)
			}
		}

		// Each run's cutoff is its own now-Retention, and the pauses advance the
		// clock, so the last run may add a short window past the backlog.
		windows := d.windows
		if len(windows) < days*24 {
			t.Fatalf("windows = %d, want >= %d", len(windows), days*24)
		}
		for i, w := range windows {
			want := start.Add(time.Duration(i) * time.Hour)
			if i > 0 && !w[0].Equal(windows[i-1][1]) {
				t.Fatalf("window %d starts at %v, previous ended at %v: not contiguous", i, w[0], windows[i-1][1])
			}
			if i < days*24 && (!w[0].Equal(want) || !w[1].Equal(want.Add(time.Hour))) {
				t.Fatalf("window %d = [%v, %v), want [%v, %v)", i, w[0], w[1], want, want.Add(time.Hour))
			}
			if !w[1].After(w[0]) || w[1].Sub(w[0]) > time.Hour {
				t.Fatalf("window %d = [%v, %v): not ascending one-hour", i, w[0], w[1])
			}
		}
		if deliveries != days*24 || bodies != days*24 {
			t.Fatalf("purged %d deliveries and %d bodies, want %d each", deliveries, bodies, days*24)
		}
		if _, ok, err := d.OldestPingStoredAt(context.Background()); err != nil || ok {
			t.Fatalf("pings left after the drain: ok=%v err=%v", ok, err)
		}
	})
}

// TestEventDAOMemory_LoadMarksPings (#389): delivery rows loaded from disk
// carry the ping marker derived from their body, so the purge deletes a
// loaded delivered ping row and keeps a loaded data row.
func TestEventDAOMemory_LoadMarksPings(t *testing.T) {
	at := pingT0
	ping := pingRecord("ping", at)
	data := pingRecord("data", at)
	data.Types = []string{"urn:test"}
	row := func(jti string) interfaces.DeliveredEvent {
		return interfaces.DeliveredEvent{DeliverableEvent: interfaces.DeliverableEvent{Jti: jti, AckJti: jti, CreatedAt: at}, AckDate: at}
	}
	d := memory.NewEventDAO()
	d.SetState(map[string]*model.EventRecord{"ping": ping, "data": data}, map[string][]interfaces.DeliverableEvent{},
		map[string][]interfaces.DeliveredEvent{"s1": {row("ping"), row("data")}})
	res, err := d.PurgePingWindow(context.Background(), at.Add(-time.Hour), at.Add(time.Hour))
	if err != nil || res.Deliveries != 1 || res.Bodies != 1 {
		t.Fatalf("PurgePingWindow = (%+v, %v), want the loaded ping row and body", res, err)
	}
	if !bodyStored(t, d, "data") {
		t.Fatal("data body purged")
	}
}
