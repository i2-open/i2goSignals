package wal

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
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

func TestBolt_AppendReadTruncateReopen(t *testing.T) {
	dir := t.TempDir()
	l, err := OpenBolt(dir)
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

	l, err = OpenBolt(dir)
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

func TestBolt_ClosedErrors(t *testing.T) {
	l, err := OpenBolt(t.TempDir())
	require.NoError(t, err)
	require.NoError(t, l.Close())
	require.NoError(t, l.Close())
	_, err = l.Append([][]byte{[]byte("x")})
	assert.ErrorIs(t, err, ErrClosed)
	_, err = l.ReadFrom(0, 0)
	assert.ErrorIs(t, err, ErrClosed)
	assert.ErrorIs(t, l.Truncate(1), ErrClosed)
}

func TestBolt_ConcurrentAppendsGroupCommit(t *testing.T) {
	l, err := OpenBolt(t.TempDir())
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

// A torn/partial record (bad or short checksum) is ignored on read.
func TestBolt_PartialRecordIgnored(t *testing.T) {
	dir := t.TempDir()
	l, err := OpenBolt(dir)
	require.NoError(t, err)
	_, err = l.Append([][]byte{[]byte("good")})
	require.NoError(t, err)
	require.NoError(t, l.Close())

	db, err := bolt.Open(dir+"/"+FileName, 0o600, nil)
	require.NoError(t, err)
	require.NoError(t, db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketName)
		if err := b.Put(seqKey(2), []byte{1, 2}); err != nil {
			return err
		}
		v := encode([]byte("corrupted"))
		v[len(v)-1] ^= 0xff
		return b.Put(seqKey(3), v)
	}))
	require.NoError(t, db.Close())

	l, err = OpenBolt(dir)
	require.NoError(t, err)
	defer func() { _ = l.Close() }()
	es, err := l.ReadFrom(0, 0)
	require.NoError(t, err)
	require.Len(t, es, 1)
	assert.Equal(t, "good", string(es[0].Data))
	// Truncate past the bad records clears them.
	require.NoError(t, l.Truncate(3))
	assert.Equal(t, 0, l.Depth())
}

const envCrashChild = "I2SIG_WAL_CRASH_CHILD_DIR"

// TestCrashChild is the subprocess body for TestBolt_KillDuringAppend.
func TestCrashChild(t *testing.T) {
	dir := os.Getenv(envCrashChild)
	if dir == "" {
		t.Skip("subprocess helper")
	}
	l, err := OpenBolt(dir)
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
func TestBolt_KillDuringAppend(t *testing.T) {
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

	l, err := OpenBolt(dir)
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
