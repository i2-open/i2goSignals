// Package groupcommit coalesces concurrent EventDAO writes into bulk calls
// (community #330, planning spec #111 Stage 1 "Group commit").
//
// Wrap decorates an EventDAO so that Insert/InsertMany calls arriving from
// different goroutines within a short window are merged into ONE InsertMany
// on the wrapped DAO, InsertWithPending calls are merged into ONE
// InsertWithPending (the one-trip ingest write, ADR 0043), and
// AddPending/AddPendingMany calls for the same stream are merged into ONE
// AddPendingMany. Every other method passes straight through.
//
// Contract:
//
//   - Each caller receives exactly its own outcome. A coalesced InsertMany's
//     index-aligned per-record errors are sliced back to the records each
//     caller submitted, so a duplicate JTI (interfaces.ErrDuplicateJTI, ADR
//     0017) is reported to the one caller that submitted it and to no one else.
//     Batching never bypasses the store's unique JTI index — it only changes
//     how many documents one round trip carries.
//   - A batch that fails as a whole (connection or write-concern error) returns
//     that error to every caller in the batch.
//   - Pending writes are grouped per stream because the store's AddPendingMany
//     takes one stream; the single error it returns goes to every caller of
//     that stream's batch.
//   - A batch collects callers for at most Config.Window after it opens and is
//     flushed early the moment it reaches Config.Max items, so the added
//     latency under load is bounded by the window and a burst flushes as soon
//     as it fills. A caller whose own call already carries Max or more items
//     bypasses the batcher.
//   - A Window of 0 (or a Max of 1) disables batching: Wrap returns the inner
//     DAO unchanged, so behaviour is identical to an undecorated store.
//
// Context choice: the coalesced write runs on context.Background(), detached
// from every caller. One caller cancelling (or timing out) must not abort the
// write the other callers in the same batch are waiting on, and taking any one
// caller's context values into a write shared by others would leak them. A
// caller whose context ends while its batch is still in flight gets
// ctx.Err() back immediately; its item may still be persisted by the batch,
// which is the same ambiguous outcome a cancelled direct write has today (a
// retried push then resolves through ErrDuplicateJTI). A caller whose context
// is already done is rejected before it joins a batch. Durability is unchanged
// (ADR 0038): a coalesced write is still one majority-journaled bulk write, and
// no caller is answered before it completes.
package groupcommit

import (
	"context"
	"os"
	"strconv"
	"sync"
	"time"

	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/logger"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

var gcLog = logger.Sub("GROUPCOMMIT")

const (
	// EnvWindow names the env var holding the collection window as a Go
	// duration ("1ms", "500us"); "0" disables batching.
	EnvWindow = "I2SIG_STORE_GROUP_COMMIT_WINDOW"
	// EnvMax names the env var holding the maximum items per coalesced write.
	EnvMax = "I2SIG_STORE_GROUP_COMMIT_MAX"

	// DefaultWindow is the collection window used when EnvWindow is unset.
	DefaultWindow = time.Millisecond
	// DefaultMax is the batch cap used when EnvMax is unset.
	DefaultMax = 128
)

// Config tunes the batcher.
type Config struct {
	// Window is how long a batch collects callers after it opens. 0 disables
	// batching.
	Window time.Duration
	// Max caps the items in one coalesced write; a batch flushes as soon as it
	// holds Max items. 1 disables batching.
	Max int
}

// Enabled reports whether c turns batching on.
func (c Config) Enabled() bool {
	return c.Window > 0 && c.Max > 1
}

// ConfigFromEnv reads EnvWindow and EnvMax, falling back to the defaults (with
// a warning) for unset or unparsable values. Batching is on by default.
func ConfigFromEnv() Config {
	cfg := Config{Window: DefaultWindow, Max: DefaultMax}
	if v := os.Getenv(EnvWindow); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d < 0 {
			gcLog.Warn("Invalid group-commit window; using default", "env", EnvWindow, "value", v, "default", DefaultWindow)
		} else {
			cfg.Window = d
		}
	}
	if v := os.Getenv(EnvMax); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			gcLog.Warn("Invalid group-commit max; using default", "env", EnvMax, "value", v, "default", DefaultMax)
		} else {
			cfg.Max = n
		}
	}
	return cfg
}

// Wrap returns inner with its writes coalesced per cfg, or inner itself when
// cfg disables batching.
func Wrap(inner interfaces.EventDAO, cfg Config) interfaces.EventDAO {
	if !cfg.Enabled() {
		return inner
	}
	d := &eventDAO{
		EventDAO: inner,
		cfg:      cfg,
		pending:  make(map[string]*coalescer[interfaces.PendingRef]),
	}
	d.inserts = &coalescer[*model.EventRecord]{cfg: cfg, flush: d.flushInsert}
	d.ingests = &coalescer[ingestItem]{cfg: cfg, flush: d.flushIngest}
	return d
}

// batch is one coalesced write being collected or in flight. Its items are the
// concatenation of every joined caller's items; each caller remembers its
// offset.
type batch[T any] struct {
	items []T
	full  chan struct{} // closed when the batch reaches Max and must flush now
	done  chan struct{} // closed when results/err are final
	// results is index-aligned with items (nil for a write without per-item
	// outcomes); err is the whole-batch error.
	results []error
	err     error
}

// coalescer collects callers into one open batch at a time and flushes each
// batch with one call to flush.
type coalescer[T any] struct {
	cfg   Config
	flush func(items []T) ([]error, error)

	mu  sync.Mutex
	cur *batch[T] // open batch, nil when none
}

// seal detaches b so no further caller joins it and wakes its flusher. c.mu
// must be held and b must be c.cur.
func (c *coalescer[T]) seal(b *batch[T]) {
	c.cur = nil
	close(b.full)
}

// join appends items to the open batch, opening one (and starting its flusher)
// when there is none or the open one cannot take them. It returns the batch
// and the caller's offset in it.
func (c *coalescer[T]) join(items []T) (*batch[T], int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	b := c.cur
	if b != nil && len(b.items)+len(items) > c.cfg.Max {
		c.seal(b)
		b = nil
	}
	if b == nil {
		b = &batch[T]{full: make(chan struct{}), done: make(chan struct{})}
		c.cur = b
		go c.run(b)
	}
	off := len(b.items)
	b.items = append(b.items, items...)
	if len(b.items) >= c.cfg.Max {
		c.seal(b)
	}
	return b, off
}

// run waits for the window to close or the batch to fill, detaches the batch,
// then performs the coalesced write.
func (c *coalescer[T]) run(b *batch[T]) {
	t := time.NewTimer(c.cfg.Window)
	select {
	case <-t.C:
		c.mu.Lock()
		if c.cur == b {
			c.cur = nil
		}
		c.mu.Unlock()
	case <-b.full:
		t.Stop()
	}
	// No caller can join b any more, so reading b.items is race-free.
	b.results, b.err = c.flush(b.items)
	close(b.done)
}

// submit coalesces items with concurrent callers and returns this caller's
// slice of the per-item results (nil when the write has none) or the
// whole-batch error.
func (c *coalescer[T]) submit(ctx context.Context, items []T) ([]error, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	b, off := c.join(items)
	select {
	case <-b.done:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if b.err != nil {
		return nil, b.err
	}
	if b.results == nil {
		return nil, nil
	}
	out := make([]error, len(items))
	copy(out, b.results[off:off+len(items)])
	return out, nil
}

type eventDAO struct {
	// The embedded EventDAO supplies every pass-through method.
	interfaces.EventDAO
	cfg Config

	inserts *coalescer[*model.EventRecord]
	ingests *coalescer[ingestItem]

	pendMu  sync.Mutex
	pending map[string]*coalescer[interfaces.PendingRef] // per stream ID, created on first use
}

// flushInsert is the coalesced InsertMany. The write runs on a detached
// context (see the package doc).
func (d *eventDAO) flushInsert(records []*model.EventRecord) ([]error, error) {
	results, err := d.EventDAO.InsertMany(context.Background(), records)
	if err != nil {
		return nil, err
	}
	if len(results) != len(records) {
		// Defensive: a store that breaks the index-aligned contract must not
		// push a caller's slice out of range.
		aligned := make([]error, len(records))
		copy(aligned, results)
		results = aligned
	}
	return results, nil
}

func (d *eventDAO) Insert(ctx context.Context, record *model.EventRecord) error {
	results, err := d.inserts.submit(ctx, []*model.EventRecord{record})
	if err != nil {
		return err
	}
	return results[0]
}

func (d *eventDAO) InsertMany(ctx context.Context, records []*model.EventRecord) ([]error, error) {
	if len(records) == 0 {
		return nil, nil
	}
	if len(records) >= d.cfg.Max {
		return d.EventDAO.InsertMany(ctx, records)
	}
	return d.inserts.submit(ctx, records)
}

// pendingFor returns streamID's pending coalescer. Entries are never removed:
// one small struct per stream that has ever received an event.
func (d *eventDAO) pendingFor(streamID string) *coalescer[interfaces.PendingRef] {
	d.pendMu.Lock()
	defer d.pendMu.Unlock()
	c := d.pending[streamID]
	if c == nil {
		c = &coalescer[interfaces.PendingRef]{cfg: d.cfg, flush: func(refs []interfaces.PendingRef) ([]error, error) {
			return nil, d.EventDAO.AddPendingMany(context.Background(), refs, streamID)
		}}
		d.pending[streamID] = c
	}
	return c
}

func (d *eventDAO) AddPending(ctx context.Context, ref interfaces.PendingRef, streamID string) error {
	_, err := d.pendingFor(streamID).submit(ctx, []interfaces.PendingRef{ref})
	return err
}

func (d *eventDAO) AddPendingMany(ctx context.Context, refs []interfaces.PendingRef, streamID string) error {
	if len(refs) == 0 {
		return nil
	}
	if len(refs) >= d.cfg.Max {
		return d.EventDAO.AddPendingMany(ctx, refs, streamID)
	}
	_, err := d.pendingFor(streamID).submit(ctx, refs)
	return err
}

// ingestItem is one record of an InsertWithPending call with the streams its
// caller wants it queued on. Carrying the streams per record lets a coalesced
// write rebuild one merged pending map without mixing callers' intents.
type ingestItem struct {
	rec     *model.EventRecord
	streams []interfaces.StreamPending
}

// flushIngest is the coalesced InsertWithPending. The write runs on a
// detached context (see the package doc).
func (d *eventDAO) flushIngest(items []ingestItem) ([]error, error) {
	records := make([]*model.EventRecord, len(items))
	pending := make(map[string][]interfaces.PendingRef)
	for i, it := range items {
		records[i] = it.rec
		for _, sp := range it.streams {
			pending[sp.StreamID] = append(pending[sp.StreamID], sp.Ref)
		}
	}
	results, err := d.EventDAO.InsertWithPending(context.Background(), records, pending)
	if err != nil {
		return nil, err
	}
	if len(results) != len(records) {
		// Defensive: see flushInsert.
		aligned := make([]error, len(records))
		copy(aligned, results)
		results = aligned
	}
	return results, nil
}

func (d *eventDAO) InsertWithPending(ctx context.Context, records []*model.EventRecord, pending map[string][]interfaces.PendingRef) ([]error, error) {
	if len(records) == 0 {
		return nil, nil
	}
	if len(records) >= d.cfg.Max {
		return d.EventDAO.InsertWithPending(ctx, records, pending)
	}
	byJti := interfaces.StreamsByJti(pending)
	items := make([]ingestItem, len(records))
	for i, r := range records {
		items[i] = ingestItem{rec: r, streams: byJti[r.Jti]}
	}
	return d.ingests.submit(ctx, items)
}
