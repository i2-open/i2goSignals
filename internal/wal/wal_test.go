package wal

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	bolt "go.etcd.io/bbolt"
)

func TestParseMode(t *testing.T) {
	for in, want := range map[string]Mode{"": ModeMajority, "majority": ModeMajority, "MAJORITY": ModeMajority, "local": ModeLocal, " Local ": ModeLocal} {
		got, err := ParseMode(in)
		require.NoError(t, err, in)
		assert.Equal(t, want, got, in)
	}
	for _, bad := range []string{"lcoal", "none", "true"} {
		_, err := ParseMode(bad)
		assert.Error(t, err, bad)
		assert.Contains(t, err.Error(), EnvMode)
	}
}

func TestDirFromEnv(t *testing.T) {
	t.Setenv(EnvDir, "")
	assert.Equal(t, DefaultDir, DirFromEnv())
	t.Setenv(EnvDir, "/x/y")
	assert.Equal(t, "/x/y", DirFromEnv())
}

func TestParseDrainTimeout(t *testing.T) {
	for in, want := range map[string]time.Duration{"": DefaultDrainTimeout, "5s": 5 * time.Second, " 1m ": time.Minute, "2.5": 2500 * time.Millisecond} {
		got, err := ParseDrainTimeout(in)
		require.NoError(t, err, in)
		assert.Equal(t, want, got, in)
	}
	for _, bad := range []string{"soon", "0", "-3s"} {
		got, err := ParseDrainTimeout(bad)
		assert.Error(t, err, bad)
		assert.Contains(t, err.Error(), EnvDrainTimeout)
		assert.Equal(t, DefaultDrainTimeout, got, "a bad value falls back to the default")
	}
}

func TestParseRingFed(t *testing.T) {
	for in, want := range map[string]bool{"": false, "true": true, " TRUE ": true, "1": true, "false": false, "0": false} {
		got, err := ParseRingFed(in)
		require.NoError(t, err, in)
		assert.Equal(t, want, got, in)
	}
	for _, bad := range []string{"yes", "on", "local"} {
		got, err := ParseRingFed(bad)
		assert.Error(t, err, bad)
		assert.Contains(t, err.Error(), EnvRingFed)
		assert.False(t, got)
	}
}

func TestSegment_AppendReadTruncateReopen(t *testing.T) {
	dir := t.TempDir()
	l, err := Open(dir)
	require.NoError(t, err)

	seq, err := l.Append([][]byte{[]byte("a"), []byte("b")})
	require.NoError(t, err)
	assert.Equal(t, uint64(2), seq)
	seq, err = l.Append([][]byte{[]byte("c")})
	require.NoError(t, err)
	assert.Equal(t, uint64(3), seq)
	assert.Equal(t, 3, l.Depth())

	es, err := l.ReadFrom(0, 0)
	require.NoError(t, err)
	require.Len(t, es, 3)
	assert.Equal(t, "a", string(es[0].Data))
	assert.Equal(t, uint64(3), es[2].Seq)

	es, err = l.ReadFrom(2, 1)
	require.NoError(t, err)
	require.Len(t, es, 1)
	assert.Equal(t, "b", string(es[0].Data))

	require.NoError(t, l.Truncate(2))
	assert.Equal(t, 1, l.Depth())
	require.NoError(t, l.Close())

	l, err = Open(dir)
	require.NoError(t, err)
	defer func() { _ = l.Close() }()
	assert.Equal(t, 1, l.Depth())
	es, err = l.ReadFrom(0, 0)
	require.NoError(t, err)
	require.Len(t, es, 1)
	assert.Equal(t, "c", string(es[0].Data))
	// Sequence numbers keep increasing across reopen and truncate.
	seq, err = l.Append([][]byte{[]byte("d")})
	require.NoError(t, err)
	assert.Equal(t, uint64(4), seq)
}

func TestSegment_ClosedErrors(t *testing.T) {
	l, err := Open(t.TempDir())
	require.NoError(t, err)
	require.NoError(t, l.Close())
	require.NoError(t, l.Close())
	_, err = l.Append([][]byte{[]byte("x")})
	assert.ErrorIs(t, err, ErrClosed)
	_, err = l.ReadFrom(0, 0)
	assert.ErrorIs(t, err, ErrClosed)
	assert.ErrorIs(t, l.Truncate(1), ErrClosed)
}

// A second process (here a second Open) on the same directory is refused
// while the first holds it, and admitted once it closes.
func TestSegment_DirectoryLock(t *testing.T) {
	dir := t.TempDir()
	l, err := Open(dir)
	require.NoError(t, err)
	_, err = Open(dir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "locked")
	require.NoError(t, l.Close())
	l2, err := Open(dir)
	require.NoError(t, err)
	require.NoError(t, l2.Close())
}

func TestSegment_ConcurrentAppendsGroupCommit(t *testing.T) {
	l, err := Open(t.TempDir())
	require.NoError(t, err)
	defer func() { _ = l.Close() }()
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := l.Append([][]byte{[]byte(strconv.Itoa(i))})
			assert.NoError(t, err)
		}(i)
	}
	wg.Wait()
	es, err := l.ReadFrom(0, 0)
	require.NoError(t, err)
	assert.Len(t, es, 32)
	assert.Equal(t, 32, l.Depth())
}

// Concurrent appends, reads and truncates never observe a record that is
// not durable, and the final state is consistent (run with -race).
func TestSegment_ConcurrentReadersAndDrain(t *testing.T) {
	l, err := Open(t.TempDir())
	require.NoError(t, err)
	defer func() { _ = l.Close() }()
	const writers, per = 8, 50
	var writersWg sync.WaitGroup
	for w := 0; w < writers; w++ {
		writersWg.Add(1)
		go func() {
			defer writersWg.Done()
			for i := 0; i < per; i++ {
				_, err := l.Append([][]byte{[]byte("x")})
				assert.NoError(t, err)
			}
		}()
	}
	stop := make(chan struct{})
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		for {
			select {
			case <-stop:
				return
			default:
			}
			es, err := l.ReadFrom(0, 16)
			if !assert.NoError(t, err) {
				return
			}
			if len(es) > 0 {
				assert.NoError(t, l.Truncate(es[len(es)-1].Seq))
			}
		}
	}()
	writersWg.Wait()
	close(stop)
	<-drained
	es, err := l.ReadFrom(0, 0)
	require.NoError(t, err)
	assert.Equal(t, len(es), l.Depth())
	if len(es) > 0 {
		require.NoError(t, l.Truncate(es[len(es)-1].Seq))
	}
	assert.Equal(t, 0, l.Depth())
}

// A short tail (crash mid-write) is cut off on open; the records before it
// are intact and the next append continues at a clean boundary.
func TestSegment_TornTailTrimmed(t *testing.T) {
	dir := t.TempDir()
	l, err := Open(dir)
	require.NoError(t, err)
	_, err = l.Append([][]byte{[]byte("good")})
	require.NoError(t, err)
	require.NoError(t, l.Close())

	path := segmentPath(dir, 1)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	require.NoError(t, err)
	// A record header claiming 100 bytes of payload with only two present.
	short := binary.BigEndian.AppendUint32(nil, 100)
	short = append(short, 0, 0, 0, 0, recEntry)
	short = binary.BigEndian.AppendUint64(short, 2)
	short = append(short, 1, 2)
	_, err = f.Write(short)
	require.NoError(t, err)
	require.NoError(t, f.Close())

	l, err = Open(dir)
	require.NoError(t, err)
	defer func() { _ = l.Close() }()
	es, err := l.ReadFrom(0, 0)
	require.NoError(t, err)
	require.Len(t, es, 1)
	assert.Equal(t, "good", string(es[0].Data))
	seq, err := l.Append([][]byte{[]byte("next")})
	require.NoError(t, err)
	assert.Equal(t, uint64(2), seq)
	require.NoError(t, l.Close())

	l, err = Open(dir)
	require.NoError(t, err)
	defer func() { _ = l.Close() }()
	es, err = l.ReadFrom(0, 0)
	require.NoError(t, err)
	require.Len(t, es, 2)
	assert.Equal(t, "next", string(es[1].Data))
	// Truncate past everything clears the log.
	require.NoError(t, l.Truncate(3))
	assert.Equal(t, 0, l.Depth())
}

// A checksum failure ends the readable prefix: the record and anything
// after it are not returned.
func TestSegment_CorruptRecordEndsPrefix(t *testing.T) {
	dir := t.TempDir()
	l, err := Open(dir)
	require.NoError(t, err)
	_, err = l.Append([][]byte{[]byte("one"), []byte("two"), []byte("three")})
	require.NoError(t, err)
	require.NoError(t, l.Close())

	// Flip a payload byte of the second record.
	path := segmentPath(dir, 1)
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	second := segmentHeader + recordHeader + len("one") + recordHeader
	data[second] ^= 0xff
	require.NoError(t, os.WriteFile(path, data, 0o600))

	l, err = Open(dir)
	require.NoError(t, err)
	defer func() { _ = l.Close() }()
	es, err := l.ReadFrom(0, 0)
	require.NoError(t, err)
	require.Len(t, es, 1)
	assert.Equal(t, "one", string(es[0].Data))
	assert.Equal(t, 1, l.Depth())
}

// Segments roll over at maxSegmentBytes and are deleted once every entry in
// them is truncated; entries stay readable across the boundary and reopen.
func TestSegment_RolloverAndDelete(t *testing.T) {
	old := maxSegmentBytes
	maxSegmentBytes = 4096
	defer func() { maxSegmentBytes = old }()

	dir := t.TempDir()
	l, err := Open(dir)
	require.NoError(t, err)
	payload := make([]byte, 1024)
	for i := 0; i < 12; i++ {
		_, err := l.Append([][]byte{payload})
		require.NoError(t, err)
	}
	segs, _ := filepath.Glob(filepath.Join(dir, segmentPrefix+"*"+segmentSuffix))
	assert.Greater(t, len(segs), 2, "expected rollovers")

	es, err := l.ReadFrom(0, 0)
	require.NoError(t, err)
	require.Len(t, es, 12)

	require.NoError(t, l.Truncate(8))
	assert.Equal(t, 4, l.Depth())
	after, _ := filepath.Glob(filepath.Join(dir, segmentPrefix+"*"+segmentSuffix))
	assert.Less(t, len(after), len(segs), "fully drained segments are removed")
	require.NoError(t, l.Close())

	l, err = Open(dir)
	require.NoError(t, err)
	defer func() { _ = l.Close() }()
	assert.Equal(t, 4, l.Depth())
	es, err = l.ReadFrom(0, 0)
	require.NoError(t, err)
	require.Len(t, es, 4)
	assert.Equal(t, uint64(9), es[0].Seq)
	seq, err := l.Append([][]byte{payload})
	require.NoError(t, err)
	assert.Equal(t, uint64(13), seq)
}

// An ingest.wal from the bbolt backend is carried into the segment log on
// open, its sequence counter continues, and the file is removed.
func TestSegment_MigratesBoltFile(t *testing.T) {
	dir := t.TempDir()
	db, err := bolt.Open(filepath.Join(dir, FileName), 0o600, nil)
	require.NoError(t, err)
	require.NoError(t, db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(bucketName)
		if err != nil {
			return err
		}
		for _, s := range []string{"a", "b", "c"} {
			seq, err := b.NextSequence()
			if err != nil {
				return err
			}
			k := binary.BigEndian.AppendUint64(nil, seq)
			v := binary.BigEndian.AppendUint32(nil, crc32.Checksum([]byte(s), crcTable))
			if err := b.Put(k, append(v, s...)); err != nil {
				return err
			}
		}
		// Seq 1 was drained by the old backend.
		return b.Delete(binary.BigEndian.AppendUint64(nil, 1))
	}))
	require.NoError(t, db.Close())

	l, err := Open(dir)
	require.NoError(t, err)
	defer func() { _ = l.Close() }()
	es, err := l.ReadFrom(0, 0)
	require.NoError(t, err)
	require.Len(t, es, 2)
	assert.Equal(t, "b", string(es[0].Data))
	assert.Equal(t, uint64(4), es[0].Seq, "migrated entries continue after the bbolt counter")
	assert.Equal(t, 2, l.Depth())
	_, err = os.Stat(filepath.Join(dir, FileName))
	assert.True(t, os.IsNotExist(err), "legacy file removed")
	seq, err := l.Append([][]byte{[]byte("d")})
	require.NoError(t, err)
	assert.Equal(t, uint64(6), seq)
}

const envCrashChild = "I2SIG_WAL_CRASH_CHILD_DIR"

// TestCrashChild is the subprocess body for TestSegment_KillDuringAppend.
func TestCrashChild(t *testing.T) {
	dir := os.Getenv(envCrashChild)
	if dir == "" {
		t.Skip("subprocess helper")
	}
	l, err := Open(dir)
	if err != nil {
		fmt.Println("ERR", err)
		os.Exit(2)
	}
	out := bufio.NewWriter(os.Stdout)
	for i := 0; ; i++ {
		seq, err := l.Append([][]byte{[]byte("payload-" + strconv.Itoa(i))})
		if err != nil {
			os.Exit(3)
		}
		_, _ = fmt.Fprintf(out, "ACK %d\n", seq)
		_ = out.Flush()
	}
}

// Every append acknowledged before a SIGKILL is present and valid after
// reopening; nothing half-written is returned.
func TestSegment_KillDuringAppend(t *testing.T) {
	if testing.Short() {
		t.Skip("subprocess crash test")
	}
	dir := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=^TestCrashChild$")
	cmd.Env = append(os.Environ(), envCrashChild+"="+dir)
	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, cmd.Start())

	acked := make(chan uint64, 1<<16)
	go func() {
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			if s, ok := strings.CutPrefix(sc.Text(), "ACK "); ok {
				if n, err := strconv.ParseUint(s, 10, 64); err == nil {
					acked <- n
				}
			}
		}
		close(acked)
	}()

	deadline := time.After(10 * time.Second)
	var count int
	var maxAck uint64
wait:
	for count < 200 {
		select {
		case s, ok := <-acked:
			if !ok {
				break wait
			}
			count++
			maxAck = max(maxAck, s)
		case <-deadline:
			break wait
		}
	}
	require.NoError(t, cmd.Process.Signal(syscall.SIGKILL))
	_ = cmd.Wait()
	for s := range acked {
		count++
		maxAck = max(maxAck, s)
	}
	require.Greater(t, count, 0, "child acknowledged nothing")

	l, err := Open(dir)
	require.NoError(t, err)
	defer func() { _ = l.Close() }()
	es, err := l.ReadFrom(0, 0)
	require.NoError(t, err)
	seen := map[uint64]bool{}
	for _, e := range es {
		seen[e.Seq] = true
		assert.Equal(t, "payload-"+strconv.FormatUint(e.Seq-1, 10), string(e.Data))
	}
	for s := uint64(1); s <= maxAck; s++ {
		assert.True(t, seen[s], "acked seq %d lost", s)
	}
}
