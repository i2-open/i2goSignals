package main

import (
	"context"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	mongoopts "go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/readpref"
)

// WiredTiger journal counters read from db.serverStatus().wiredTiger.log.
// They are server-wide: on the dev stack both goSignals nodes share one
// replica set, so a run's delta covers ingest on goSignals1 and delivery
// bookkeeping on goSignals2 together.
const (
	wtLogSyncs      = "log sync operations"
	wtLogWrites     = "log write operations"
	wtLogFlushes    = "log flush operations"
	wtLogBytes      = "log bytes written"
	wtLogSyncMicros = "log sync time duration (usecs)"
)

// journalCounters is one serverStatus snapshot of the journal counters.
type journalCounters struct {
	Host        string
	Syncs       float64
	Writes      float64
	Flushes     float64
	Bytes       float64
	SyncMicros  float64
	CollectedAt time.Time
}

// journalResult is the before/after delta recorded in the result.
type journalResult struct {
	Host         string  `json:"host"`
	Syncs        int64   `json:"syncs"`
	Writes       int64   `json:"writes"`
	Flushes      int64   `json:"flushes"`
	BytesWritten int64   `json:"bytes_written"`
	SyncMs       float64 `json:"sync_ms"`
	SyncsPerSET  float64 `json:"syncs_per_set"`
	WritesPerSET float64 `json:"writes_per_set"`
}

// journalProbe snapshots the journal counters of the replica-set primary.
type journalProbe struct {
	client *mongo.Client
}

func openJournalProbe(uri string) (*journalProbe, error) {
	c, err := mongo.Connect(mongoopts.Client().ApplyURI(uri).SetReadPreference(readpref.Primary()).SetServerSelectionTimeout(10 * time.Second))
	if err != nil {
		return nil, fmt.Errorf("mongo connect: %w", err)
	}
	return &journalProbe{client: c}, nil
}

func (p *journalProbe) close() {
	if p == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = p.client.Disconnect(ctx)
}

func (p *journalProbe) snapshot() (*journalCounters, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	raw, err := p.client.Database("admin").RunCommand(ctx, bson.D{{Key: "serverStatus", Value: 1}}).Raw()
	if err != nil {
		return nil, fmt.Errorf("serverStatus: %w", err)
	}
	return journalFromStatus(raw)
}

// serverStatusReply is the slice of the serverStatus reply the probe reads.
type serverStatusReply struct {
	Host       string `bson:"host"`
	WiredTiger *struct {
		Log bson.M `bson:"log"`
	} `bson:"wiredTiger"`
}

// journalFromStatus extracts the wiredTiger.log counters from a raw
// serverStatus reply.
func journalFromStatus(raw bson.Raw) (*journalCounters, error) {
	var status serverStatusReply
	if err := bson.Unmarshal(raw, &status); err != nil {
		return nil, fmt.Errorf("decode serverStatus: %w", err)
	}
	if status.WiredTiger == nil {
		return nil, fmt.Errorf("serverStatus has no wiredTiger section (storage engine not WiredTiger?)")
	}
	log := status.WiredTiger.Log
	if log == nil {
		return nil, fmt.Errorf("serverStatus has no wiredTiger.log section")
	}
	c := &journalCounters{CollectedAt: time.Now(), Host: status.Host}
	for key, dst := range map[string]*float64{
		wtLogSyncs: &c.Syncs, wtLogWrites: &c.Writes, wtLogFlushes: &c.Flushes,
		wtLogBytes: &c.Bytes, wtLogSyncMicros: &c.SyncMicros,
	} {
		v, found := log[key]
		if !found {
			if key == wtLogSyncs || key == wtLogWrites {
				return nil, fmt.Errorf("wiredTiger.log has no %q counter", key)
			}
			continue
		}
		f, isNum := toFloat(v)
		if !isNum {
			return nil, fmt.Errorf("wiredTiger.log %q is %T, not a number", key, v)
		}
		*dst = f
	}
	return c, nil
}

func toFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case int32:
		return float64(n), true
	case int64:
		return float64(n), true
	case int:
		return float64(n), true
	case float64:
		return n, true
	}
	return 0, false
}

// diffJournal returns the counters accumulated between two snapshots,
// normalised by the number of SETs the run ingested.
func diffJournal(before, after *journalCounters, sets int) *journalResult {
	if before == nil || after == nil {
		return nil
	}
	r := &journalResult{
		Host:         after.Host,
		Syncs:        int64(after.Syncs - before.Syncs),
		Writes:       int64(after.Writes - before.Writes),
		Flushes:      int64(after.Flushes - before.Flushes),
		BytesWritten: int64(after.Bytes - before.Bytes),
		SyncMs:       (after.SyncMicros - before.SyncMicros) / 1000,
	}
	if sets > 0 {
		r.SyncsPerSET = float64(r.Syncs) / float64(sets)
		r.WritesPerSET = float64(r.Writes) / float64(sets)
	}
	return r
}
