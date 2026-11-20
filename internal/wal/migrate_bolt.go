package wal

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"
	"time"

	bolt "go.etcd.io/bbolt"
)

// bucketName is the bucket the bbolt backend (ADR 0045) kept entries in:
// key = big-endian seq, value = CRC32C prefix + payload.
var bucketName = []byte("wal")

// migrateBolt moves the entries of an ingest.wal written by the bbolt
// backend into the segment log and removes the file. The migrated entries
// are renumbered from after bbolt's counter so no sequence number is ever
// reused. A crash between the last append and the remove migrates the file
// again on the next start; the duplicate entries are absorbed by JTI dedup
// at the store (ADR 0017). Called on Open, after recovery, before any append.
func (l *segmentLog) migrateBolt() error {
	path := filepath.Join(l.dir, FileName)
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("wal: stat %s: %w", path, err)
	}
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 2 * time.Second, ReadOnly: true})
	if err != nil {
		return fmt.Errorf("wal: open legacy %s: %w", path, err)
	}
	var (
		batch  [][]byte
		maxSeq uint64
	)
	err = db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketName)
		if b == nil {
			return nil
		}
		maxSeq = b.Sequence()
		return b.ForEach(func(k, v []byte) error {
			if len(k) != 8 || len(v) < 4 {
				return nil
			}
			data := v[4:]
			if binary.BigEndian.Uint32(v) != crc32.Checksum(data, crcTable) {
				return nil // torn record, skipped as the old reader did
			}
			batch = append(batch, append([]byte(nil), data...))
			return nil
		})
	})
	_ = db.Close()
	if err != nil {
		return fmt.Errorf("wal: read legacy %s: %w", path, err)
	}
	l.nextSeq = max(l.nextSeq, maxSeq+1)
	const chunk = 512
	for len(batch) > 0 {
		n := min(chunk, len(batch))
		if _, err := l.Append(batch[:n]); err != nil {
			return fmt.Errorf("wal: migrate legacy %s: %w", path, err)
		}
		batch = batch[n:]
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("wal: remove legacy %s: %w", path, err)
	}
	return syncDir(l.dir)
}
