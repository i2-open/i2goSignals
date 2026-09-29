package wal

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	bolt "go.etcd.io/bbolt"
)

var bucketName = []byte("wal")

var crcTable = crc32.MakeTable(crc32.Castagnoli)

// boltLog is a Log on bbolt (MIT, pure Go). Appends are group-committed:
// while one bbolt transaction is committing (two fsyncs), every Append that
// arrives queues, and the next transaction writes the whole queue, so
// concurrent appends share an fsync. bbolt's own DB.Batch is not used: it
// closes a batch on a fixed timer, so under a slow fsync the batches queued
// behind the writer lock hold one call each and throughput collapses to one
// SET per commit. Values carry a CRC32C prefix so a torn record is detected
// and skipped on read.
type boltLog struct {
	db     *bolt.DB
	depth  atomic.Int64
	mu     sync.RWMutex
	closed bool

	qmu     sync.Mutex
	queue   []*appendReq
	writing bool // a leader is committing; new requests queue
}

// appendReq is one queued Append or Truncate (truncate > 0). done is closed
// when it was committed (last/err set) or when it was handed leadership
// (lead set). Truncations ride the same group commit as appends, so the drain
// worker's truncate does not cost the ingest path a transaction of its own.
type appendReq struct {
	batch    [][]byte
	truncate uint64
	last     uint64
	err      error
	lead     bool
	done     chan struct{}
}

// OpenBolt opens (creating if needed) the WAL file under dir.
func OpenBolt(dir string) (Log, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("wal: create dir %s: %w", dir, err)
	}
	path := filepath.Join(dir, FileName)
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("wal: open %s: %w", path, err)
	}
	l := &boltLog{db: db}
	if err := db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(bucketName)
		if err != nil {
			return err
		}
		l.depth.Store(int64(b.Stats().KeyN))
		return nil
	}); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("wal: init %s: %w", path, err)
	}
	return l, nil
}

func seqKey(seq uint64) []byte {
	k := make([]byte, 8)
	binary.BigEndian.PutUint64(k, seq)
	return k
}

func encode(data []byte) []byte {
	v := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(v, crc32.Checksum(data, crcTable))
	copy(v[4:], data)
	return v
}

// decode returns the payload, or false for a short or corrupt record.
func decode(v []byte) ([]byte, bool) {
	if len(v) < 4 {
		return nil, false
	}
	data := v[4:]
	if binary.BigEndian.Uint32(v) != crc32.Checksum(data, crcTable) {
		return nil, false
	}
	out := make([]byte, len(data))
	copy(out, data)
	return out, true
}

func (l *boltLog) Append(batch [][]byte) (uint64, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.closed {
		return 0, ErrClosed
	}
	if len(batch) == 0 {
		return 0, nil
	}
	return l.submit(&appendReq{batch: batch, done: make(chan struct{})})
}

// submit queues req and returns once a leader (possibly this caller) has
// committed it.
func (l *boltLog) submit(req *appendReq) (uint64, error) {
	l.qmu.Lock()
	l.queue = append(l.queue, req)
	if l.writing {
		l.qmu.Unlock()
		<-req.done
		if !req.lead {
			return req.last, req.err
		}
		l.qmu.Lock()
	} else {
		l.writing = true
	}
	// Leader: commit everything queued, which includes req.
	reqs := l.queue
	l.queue = nil
	l.qmu.Unlock()

	l.commit(reqs)

	// Hand leadership to the oldest waiter, so no caller commits for others
	// indefinitely.
	l.qmu.Lock()
	if len(l.queue) > 0 {
		next := l.queue[0]
		next.lead = true
		close(next.done)
	} else {
		l.writing = false
	}
	l.qmu.Unlock()
	for _, r := range reqs {
		if r != req {
			close(r.done)
		}
	}
	if req.err != nil {
		return 0, req.err
	}
	return req.last, nil
}

// commit writes reqs in one bbolt transaction and records each outcome:
// truncations first, then appends in queue order.
func (l *boltLog) commit(reqs []*appendReq) {
	var added, removed int64
	err := l.db.Update(func(tx *bolt.Tx) error {
		added, removed = 0, 0
		b := tx.Bucket(bucketName)
		var through uint64
		for _, r := range reqs {
			through = max(through, r.truncate)
		}
		if through > 0 {
			c := b.Cursor()
			limit := seqKey(through)
			for k, _ := c.First(); k != nil && string(k) <= string(limit); k, _ = c.First() {
				if err := c.Delete(); err != nil {
					return err
				}
				removed++
			}
		}
		for _, r := range reqs {
			for _, d := range r.batch {
				seq, err := b.NextSequence()
				if err != nil {
					return err
				}
				if err := b.Put(seqKey(seq), encode(d)); err != nil {
					return err
				}
				r.last = seq
			}
			added += int64(len(r.batch))
		}
		return nil
	})
	if err != nil {
		err = fmt.Errorf("wal: commit: %w", err)
		for _, r := range reqs {
			r.last, r.err = 0, err
		}
		return
	}
	l.depth.Add(added - removed)
}

func (l *boltLog) ReadFrom(seq uint64, limit int) ([]Entry, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.closed {
		return nil, ErrClosed
	}
	var out []Entry
	err := l.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketName).Cursor()
		for k, v := c.Seek(seqKey(seq)); k != nil; k, v = c.Next() {
			if limit > 0 && len(out) >= limit {
				break
			}
			if len(k) != 8 {
				continue
			}
			data, ok := decode(v)
			if !ok {
				continue
			}
			out = append(out, Entry{Seq: binary.BigEndian.Uint64(k), Data: data})
		}
		return nil
	})
	return out, err
}

func (l *boltLog) Truncate(seq uint64) error {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.closed {
		return ErrClosed
	}
	if seq == 0 {
		return nil
	}
	_, err := l.submit(&appendReq{truncate: seq, done: make(chan struct{})})
	return err
}

func (l *boltLog) Depth() int { return int(l.depth.Load()) }

func (l *boltLog) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	return l.db.Close()
}
