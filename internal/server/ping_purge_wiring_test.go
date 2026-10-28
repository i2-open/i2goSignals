package server

import (
	"runtime"
	"strings"
	"testing"

	"github.com/i2-open/i2goSignals/internal/providers/dbProviders"
	"github.com/i2-open/i2goSignals/internal/providers/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const pingPurgeLoopFrame = "services.(*PingPurger).loop"

// purgeLoops counts the running ping-purge loops; other tests' applications
// may hold some, so the tests compare against a baseline.
func purgeLoops() int {
	buf := make([]byte, 8<<20)
	return strings.Count(string(buf[:runtime.Stack(buf, true)]), pingPurgeLoopFrame)
}

// closeProbe records whether the ping-purge loop was still running when
// storage closed.
type closeProbe struct {
	storage.Storage
	loopsAtClose *int
}

func (c closeProbe) Close() error {
	*c.loopsAtClose = purgeLoops()
	return c.Storage.Close()
}

// Caller pin (ADR 0048, #388): NewApplication builds and starts the ping
// purger and logs its posture; Shutdown stops it before storage closes.
func TestNewApplication_WiresPingPurger(t *testing.T) {
	t.Setenv("I2SIG_STORE_MEM_DIRECTORY", t.TempDir())
	t.Setenv("I2SIG_SHUTDOWN_DRAIN", "0")
	t.Setenv("I2SIG_PING_RETENTION", "")
	logs := captureLogs(t)
	base := purgeLoops()
	persistence, err := dbProviders.OpenPersistence("memorydb:", "test_ping_purge_wiring")
	require.NoError(t, err)

	sa := NewApplication(persistence, "")
	require.NotNil(t, sa.PingPurger, "NewApplication builds the ping purger")
	assert.Contains(t, logs.String(), "ping retention 24h; purge every 6h, one node per cluster")
	assert.Equal(t, base+1, purgeLoops(), "the purge loop runs")

	loopsAtClose := -1
	sa.Storage = closeProbe{Storage: sa.Storage, loopsAtClose: &loopsAtClose}
	sa.Shutdown()
	assert.Equal(t, base, loopsAtClose, "the purge loop stopped before storage closed")
}

// With I2SIG_PING_RETENTION=0 the purger is built but never starts.
func TestNewApplication_PingPurgeOff(t *testing.T) {
	t.Setenv("I2SIG_STORE_MEM_DIRECTORY", t.TempDir())
	t.Setenv("I2SIG_SHUTDOWN_DRAIN", "0")
	t.Setenv("I2SIG_PING_RETENTION", "0")
	logs := captureLogs(t)
	base := purgeLoops()
	persistence, err := dbProviders.OpenPersistence("memorydb:", "test_ping_purge_off")
	require.NoError(t, err)

	sa := NewApplication(persistence, "")
	defer sa.Shutdown()
	assert.Contains(t, logs.String(), "ping purge off (I2SIG_PING_RETENTION=0)")
	assert.Equal(t, base, purgeLoops(), "no purge loop starts")
}
