package wal

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
)

// Segment-log layout (ADR 0046).
//
// The log is a directory of append-only segment files, ingest-NNNNNNNN.seg,
// numbered in creation order. Each starts with a fixed header and is followed
// by records, written back to back:
//
//	header: magic "I2SIGWAL" | u32 version | u64 firstSeq (the next sequence number when the segment was created)
//	record: u32 payloadLen | u32 crc32c(type|seq|payload) | u8 type | u64 seq | payload
//
// Type 1 is an entry; type 2 is a truncate marker whose seq is the highest
// sequence number removed (it has no payload). A group commit is one write
// of every queued record followed by one fdatasync, so concurrent appends
// share a single flush. Recovery scans the segments in order, applies the
// markers, and stops at the first short or checksum-failed record: because
// nothing is acknowledged before its fsync returns, a bad record can only be
// the torn tail of a crash and is cut off. Segments whose entries have all
// been truncated are deleted; a marker in a later segment keeps the deletion
// safe to lose.
const (
	segmentMagic   = "I2SIGWAL"
	segmentVersion = uint32(1)
	segmentHeader  = 8 + 4 + 8
	recordHeader   = 4 + 4 + 1 + 8
	recEntry       = byte(1)
	recTruncate    = byte(2)

	segmentPrefix = "ingest-"
	segmentSuffix = ".seg"
	lockFileName  = "wal.lock"
)

var crcTable = crc32.MakeTable(crc32.Castagnoli)

// maxSegmentBytes is the size past which the next group opens a new segment.
// Smaller segments free disk sooner after a drain; larger ones mean fewer
// files. One group larger than this gets a segment of its own. A variable so
// tests can force rollovers.
var maxSegmentBytes int64 = 64 << 20

// segment is one open segment file. The active (last) segment is the only
// one written; every live segment stays open for ReadAt.
type segment struct {
	index int
	path  string
	f     *os.File
	size  int64
	live  int // entries in this segment not yet truncated
}

// indexEntry locates one live record in its segment.
type indexEntry struct {
	seq uint64
	seg *segment
	off int64
	n   uint32
}

// segmentLog is a Log on the segment layout above.
type segmentLog struct {
	dir   string
	lock  *os.File
	depth atomic.Int64

	mu     sync.RWMutex // guards closed against Close
	closed bool

	// imu guards the index and segment list. commit takes it only after the
	// group is on disk, so readers never wait for an fsync.
	imu     sync.RWMutex
	index   []indexEntry
	segs    []*segment
	nextSeq uint64

	// Writer state, owned by the current group-commit leader.
	buf []byte

	qmu     sync.Mutex
	queue   []*appendReq
	writing bool // a leader is committing; new requests queue
}

// appendReq is one queued Append or Truncate (truncate > 0). done is closed
// when it was committed (last/err set) or when it was handed leadership
// (lead set). Truncations ride the same group commit as appends, so the drain
// worker's truncate does not cost the ingest path a flush of its own.
type appendReq struct {
	batch    [][]byte
	truncate uint64
	last     uint64
	err      error
	lead     bool
	done     chan struct{}
}

// Open opens (creating if needed) the segment log under dir. A second
// process opening the same dir fails on the lock file. An ingest.wal left by
// the earlier bbolt backend is migrated into the segment log and removed.
func Open(dir string) (Log, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("wal: create dir %s: %w", dir, err)
	}
	lock, err := lockDir(filepath.Join(dir, lockFileName))
	if err != nil {
		return nil, err
	}
	l := &segmentLog{dir: dir, lock: lock, nextSeq: 1}
	if err := l.recover(); err != nil {
		_ = lock.Close()
		l.closeSegments()
		return nil, err
	}
	if err := l.migrateBolt(); err != nil {
		_ = l.Close()
		return nil, err
	}
	return l, nil
}

// OpenBolt is kept for callers written against the bbolt backend; it opens
// the segment log.
func OpenBolt(dir string) (Log, error) { return Open(dir) }

func segmentPath(dir string, index int) string {
	return filepath.Join(dir, fmt.Sprintf("%s%08d%s", segmentPrefix, index, segmentSuffix))
}

// recover loads the live index from the segments on disk.
func (l *segmentLog) recover() error {
	names, err := filepath.Glob(filepath.Join(l.dir, segmentPrefix+"*"+segmentSuffix))
	if err != nil {
		return fmt.Errorf("wal: list %s: %w", l.dir, err)
	}
	type named struct {
		index int
		path  string
	}
	var found []named
	for _, p := range names {
		base := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(p), segmentPrefix), segmentSuffix)
		idx, err := strconv.Atoi(base)
		if err != nil {
			continue
		}
		found = append(found, named{idx, p})
	}
	sort.Slice(found, func(i, j int) bool { return found[i].index < found[j].index })

	for i, n := range found {
		last := i == len(found)-1
		seg, err := l.loadSegment(n.index, n.path, last)
		if err != nil {
			return err
		}
		if seg == nil {
			continue // a torn, never-acknowledged segment; removed
		}
		l.segs = append(l.segs, seg)
	}
	l.dropEmptySegments()
	l.depth.Store(int64(len(l.index)))
	return nil
}

// loadSegment scans one segment into the index. A segment whose header is
// short or torn is removed when it is the last one (a crash during rollover
// before any acknowledgement) and an error otherwise.
func (l *segmentLog) loadSegment(index int, path string, last bool) (*segment, error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("wal: open %s: %w", path, err)
	}
	seg := &segment{index: index, path: path, f: f}
	hdr := make([]byte, segmentHeader)
	if _, err := io.ReadFull(f, hdr); err != nil || string(hdr[:8]) != segmentMagic || binary.BigEndian.Uint32(hdr[8:12]) != segmentVersion {
		_ = f.Close()
		if last && (err != nil || string(hdr[:8]) != segmentMagic) {
			if rmErr := os.Remove(path); rmErr != nil {
				return nil, fmt.Errorf("wal: remove torn segment %s: %w", path, rmErr)
			}
			return nil, nil
		}
		if err != nil {
			return nil, fmt.Errorf("wal: segment %s header: %w", path, err)
		}
		return nil, fmt.Errorf("wal: segment %s: bad magic or version", path)
	}
	l.nextSeq = max(l.nextSeq, binary.BigEndian.Uint64(hdr[12:20]))

	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("wal: stat %s: %w", path, err)
	}
	// Segments are bounded, so one read of the file is the simplest scan.
	data := make([]byte, info.Size()-segmentHeader)
	if _, err := io.ReadFull(f, data); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("wal: read %s: %w", path, err)
	}
	off := 0
	for off+recordHeader <= len(data) {
		n := int(binary.BigEndian.Uint32(data[off:]))
		end := off + recordHeader + n
		if end > len(data) {
			break // short tail
		}
		rec := data[off+8 : end]
		if binary.BigEndian.Uint32(data[off+4:]) != crc32.Checksum(rec, crcTable) {
			break // torn tail
		}
		typ, seq := rec[0], binary.BigEndian.Uint64(rec[1:9])
		switch typ {
		case recEntry:
			l.index = append(l.index, indexEntry{seq: seq, seg: seg, off: int64(segmentHeader + off + recordHeader), n: uint32(n)})
			seg.live++
			l.nextSeq = max(l.nextSeq, seq+1)
		case recTruncate:
			l.truncateIndex(seq)
			l.nextSeq = max(l.nextSeq, seq+1)
		default:
			_ = f.Close()
			return nil, fmt.Errorf("wal: segment %s: record type %d at offset %d written by a newer version", path, typ, segmentHeader+off)
		}
		off = end
	}
	seg.size = int64(segmentHeader + off)
	if seg.size < info.Size() {
		// Cut the torn tail so the next group starts at a clean record boundary.
		if err := f.Truncate(seg.size); err != nil {
			_ = f.Close()
			return nil, fmt.Errorf("wal: trim %s: %w", path, err)
		}
	}
	return seg, nil
}

// truncateIndex drops index entries with seq <= through. Called with imu
// held (or during single-threaded recovery).
func (l *segmentLog) truncateIndex(through uint64) int {
	i := sort.Search(len(l.index), func(i int) bool { return l.index[i].seq > through })
	for _, e := range l.index[:i] {
		e.seg.live--
	}
	l.index = l.index[i:]
	// Give the backing array back once the live window has slid far enough.
	if cap(l.index) > 1024 && len(l.index) < cap(l.index)/4 {
		l.index = append([]indexEntry(nil), l.index...)
	}
	return i
}

// dropEmptySegments removes every non-active segment with no live entries.
// Called with imu held (or during recovery).
func (l *segmentLog) dropEmptySegments() {
	kept := l.segs[:0]
	removed := false
	for i, s := range l.segs {
		if s.live == 0 && i < len(l.segs)-1 {
			_ = s.f.Close()
			_ = os.Remove(s.path)
			removed = true
			continue
		}
		kept = append(kept, s)
	}
	l.segs = kept
	if removed {
		_ = syncDir(l.dir)
	}
}

// active returns the segment appends go to, opening the first one when the
// log is empty.
func (l *segmentLog) active() (*segment, error) {
	if len(l.segs) > 0 {
		return l.segs[len(l.segs)-1], nil
	}
	return l.roll()
}

// roll opens a new segment after the current one and makes it durable
// before it is written to.
func (l *segmentLog) roll() (*segment, error) {
	index := 1
	if len(l.segs) > 0 {
		index = l.segs[len(l.segs)-1].index + 1
	}
	path := segmentPath(l.dir, index)
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("wal: create %s: %w", path, err)
	}
	hdr := make([]byte, segmentHeader)
	copy(hdr, segmentMagic)
	binary.BigEndian.PutUint32(hdr[8:], segmentVersion)
	binary.BigEndian.PutUint64(hdr[12:], l.nextSeq)
	if _, err := f.Write(hdr); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("wal: write %s header: %w", path, err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("wal: sync %s: %w", path, err)
	}
	if err := syncDir(l.dir); err != nil {
		_ = f.Close()
		return nil, err
	}
	seg := &segment{index: index, path: path, f: f, size: segmentHeader}
	l.imu.Lock()
	l.segs = append(l.segs, seg)
	l.imu.Unlock()
	return seg, nil
}

func (l *segmentLog) Append(batch [][]byte) (uint64, error) {
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
func (l *segmentLog) submit(req *appendReq) (uint64, error) {
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

// putRecord appends one record to l.buf.
func (l *segmentLog) putRecord(typ byte, seq uint64, payload []byte) {
	start := len(l.buf)
	l.buf = binary.BigEndian.AppendUint32(l.buf, uint32(len(payload)))
	l.buf = append(l.buf, 0, 0, 0, 0) // crc, filled below
	l.buf = append(l.buf, typ)
	l.buf = binary.BigEndian.AppendUint64(l.buf, seq)
	l.buf = append(l.buf, payload...)
	binary.BigEndian.PutUint32(l.buf[start+4:], crc32.Checksum(l.buf[start+8:], crcTable))
}

// commit writes reqs as one group: one truncate marker (the highest
// requested), then the appends in queue order, one write and one fdatasync.
// Only then are the index and depth updated, so a reader never observes a
// record that is not yet durable.
func (l *segmentLog) commit(reqs []*appendReq) {
	fail := func(err error) {
		err = fmt.Errorf("wal: commit: %w", err)
		for _, r := range reqs {
			r.last, r.err = 0, err
		}
	}

	var through uint64
	var added int
	for _, r := range reqs {
		through = max(through, r.truncate)
		added += len(r.batch)
	}

	l.imu.RLock()
	seq := l.nextSeq
	l.imu.RUnlock()

	l.buf = l.buf[:0]
	if through > 0 {
		l.putRecord(recTruncate, through, nil)
	}
	type placed struct {
		seq uint64
		off int
		n   uint32
	}
	entries := make([]placed, 0, added)
	for _, r := range reqs {
		for _, d := range r.batch {
			entries = append(entries, placed{seq: seq, off: len(l.buf) + recordHeader, n: uint32(len(d))})
			l.putRecord(recEntry, seq, d)
			r.last = seq
			seq++
		}
	}

	seg, err := l.active()
	if err != nil {
		fail(err)
		return
	}
	if seg.size > segmentHeader && seg.size+int64(len(l.buf)) > maxSegmentBytes {
		if seg, err = l.roll(); err != nil {
			fail(err)
			return
		}
	}
	base := seg.size
	// Positional write: after recovery the descriptor's offset may sit past a
	// trimmed tail, and WriteAt is independent of it.
	if _, err := seg.f.WriteAt(l.buf, base); err != nil {
		// Leave the partial write for recovery to trim; nothing was acknowledged.
		fail(err)
		return
	}
	if err := fdatasync(seg.f); err != nil {
		fail(err)
		return
	}

	l.imu.Lock()
	seg.size = base + int64(len(l.buf))
	removed := 0
	if through > 0 {
		removed = l.truncateIndex(through)
		l.nextSeq = max(l.nextSeq, through+1)
	}
	for _, e := range entries {
		l.index = append(l.index, indexEntry{seq: e.seq, seg: seg, off: base + int64(e.off), n: e.n})
	}
	seg.live += added
	l.nextSeq = max(seq, through+1)
	if removed > 0 {
		l.dropEmptySegments()
	}
	l.imu.Unlock()
	l.depth.Add(int64(added - removed))
}

func (l *segmentLog) ReadFrom(seq uint64, limit int) ([]Entry, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.closed {
		return nil, ErrClosed
	}
	l.imu.RLock()
	start := sort.Search(len(l.index), func(i int) bool { return l.index[i].seq >= seq })
	span := l.index[start:]
	if limit > 0 && len(span) > limit {
		span = span[:limit]
	}
	locs := make([]indexEntry, len(span))
	copy(locs, span)
	l.imu.RUnlock()

	out := make([]Entry, 0, len(locs))
	for _, e := range locs {
		data := make([]byte, e.n)
		if _, err := e.seg.f.ReadAt(data, e.off); err != nil {
			if errors.Is(err, os.ErrClosed) {
				continue // truncated and its segment dropped between the index copy and the read
			}
			return out, fmt.Errorf("wal: read seq %d: %w", e.seq, err)
		}
		out = append(out, Entry{Seq: e.seq, Data: data})
	}
	return out, nil
}

func (l *segmentLog) Truncate(seq uint64) error {
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

func (l *segmentLog) Depth() int { return int(l.depth.Load()) }

func (l *segmentLog) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	l.imu.Lock()
	l.closeSegments()
	l.imu.Unlock()
	if l.lock != nil {
		return unlockDir(l.lock)
	}
	return nil
}

func (l *segmentLog) closeSegments() {
	for _, s := range l.segs {
		_ = s.f.Close()
	}
	l.segs = nil
}

// syncDir flushes directory metadata so a created or removed segment
// survives a crash.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("wal: open dir %s: %w", dir, err)
	}
	defer func() { _ = d.Close() }()
	if err := d.Sync(); err != nil && !errors.Is(err, syscall.EINVAL) && !errors.Is(err, syscall.ENOTSUP) {
		return fmt.Errorf("wal: sync dir %s: %w", dir, err)
	}
	return nil
}
