package dbProviders

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/i2-open/i2goSignals/internal/providers/cluster"
	"github.com/i2-open/i2goSignals/internal/providers/dbProviders/memory_provider"
	"github.com/i2-open/i2goSignals/internal/wal"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// nodesCoordinator stubs GetActiveNodes for the single-node guard.
type nodesCoordinator struct {
	cluster.ClusterCoordinator
	nodes []model.ClusterNode
	err   error
}

func (c *nodesCoordinator) GetActiveNodes() ([]model.ClusterNode, error) { return c.nodes, c.err }

func TestOpenPersistence_WalModeUnknownRefused(t *testing.T) {
	t.Setenv("I2SIG_STORE_MEM_DIRECTORY", t.TempDir())
	t.Setenv(wal.EnvMode, "sometimes")
	p, err := OpenPersistence("memorydb:", "test_wal_unknown")
	require.Error(t, err)
	assert.Contains(t, err.Error(), wal.EnvMode)
	assert.Nil(t, p)
}

func TestOpenPersistence_WalModeMajorityIsDefault(t *testing.T) {
	for _, v := range []string{"", "majority", " MAJORITY "} {
		t.Setenv("I2SIG_STORE_MEM_DIRECTORY", t.TempDir())
		t.Setenv(wal.EnvMode, v)
		p, err := OpenPersistence("memorydb:", "test_wal_majority")
		require.NoError(t, err, "mode %q", v)
		assert.Nil(t, p.WAL, "mode %q must not open a WAL", v)
		_ = p.Storage.Close()
	}
}

func TestOpenPersistence_WalModeLocalOpensWal(t *testing.T) {
	t.Setenv("I2SIG_STORE_MEM_DIRECTORY", t.TempDir())
	t.Setenv(wal.EnvMode, "local")
	t.Setenv(wal.EnvDir, t.TempDir())
	p, err := OpenPersistence("memorydb:", "test_wal_local")
	require.NoError(t, err)
	require.NotNil(t, p.WAL)
	assert.Equal(t, 0, p.WAL.Depth())
	assert.NoError(t, p.WAL.Close())
	_ = p.Storage.Close()
}

func TestAttachLocalWal_RefusesMultiNodeClusterWithoutRingFed(t *testing.T) {
	p := &Persistence{Coordinator: &nodesCoordinator{nodes: []model.ClusterNode{{Id: "self"}, {Id: "peer"}}}}
	err := attachLocalWal(p, "self", t.TempDir(), false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "2 active cluster nodes")
	assert.Contains(t, err.Error(), "peer")
	assert.Contains(t, err.Error(), wal.EnvRingFed+"=true")
	assert.Contains(t, err.Error(), "majority mode")
	assert.Nil(t, p.WAL)
}

func TestAttachLocalWal_RefusesWhenMembershipUnknown(t *testing.T) {
	p := &Persistence{Coordinator: &nodesCoordinator{err: errors.New("lease store down")}}
	err := attachLocalWal(p, "self", t.TempDir(), false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot confirm the active cluster node count")
	assert.Contains(t, err.Error(), wal.EnvRingFed+"=true")
	assert.Nil(t, p.WAL)
}

func TestAttachLocalWal_AllowsSelfOnly(t *testing.T) {
	p := &Persistence{Coordinator: &nodesCoordinator{nodes: []model.ClusterNode{{Id: "self"}}}}
	require.NoError(t, attachLocalWal(p, "self", t.TempDir(), false))
	require.NotNil(t, p.WAL)
	assert.NoError(t, p.WAL.Close())
}

func TestAttachLocalWal_RingFedAllowsMultiNodeCluster(t *testing.T) {
	p := &Persistence{Coordinator: &nodesCoordinator{nodes: []model.ClusterNode{{Id: "self"}, {Id: "peer"}}}}
	require.NoError(t, attachLocalWal(p, "self", t.TempDir(), true))
	require.NotNil(t, p.WAL)
	assert.NoError(t, p.WAL.Close())
}

// TestCheckLocalModeCluster_MemoryCoordinatorTwoNodes is the issue #343
// guard: with a real (memory) coordinator holding two active nodes, a
// local-mode node refuses to start without ring-fed and starts with it.
func TestCheckLocalModeCluster_MemoryCoordinatorTwoNodes(t *testing.T) {
	coord := memory_provider.NewMemoryCoordinator()
	now := time.Now().UTC()
	require.NoError(t, coord.RegisterNode(model.ClusterNode{Id: "node-a", StartedAt: now, LastSeenAt: now}))
	require.NoError(t, coord.RegisterNode(model.ClusterNode{Id: "node-b", StartedAt: now, LastSeenAt: now}))

	err := CheckLocalModeCluster(coord, "node-b", false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "node-a")
	assert.Contains(t, err.Error(), wal.EnvRingFed)

	assert.NoError(t, CheckLocalModeCluster(coord, "node-b", true))

	single := memory_provider.NewMemoryCoordinator()
	require.NoError(t, single.RegisterNode(model.ClusterNode{Id: "node-a", StartedAt: now, LastSeenAt: now}))
	assert.NoError(t, CheckLocalModeCluster(single, "node-a", false))
}

func TestOpenPersistence_RingFedMalformedRefused(t *testing.T) {
	t.Setenv("I2SIG_STORE_MEM_DIRECTORY", t.TempDir())
	t.Setenv(wal.EnvMode, "local")
	t.Setenv(wal.EnvDir, t.TempDir())
	t.Setenv(wal.EnvRingFed, "sometimes")
	p, err := OpenPersistence("memorydb:", "test_wal_ringfed_bad")
	require.Error(t, err)
	assert.Contains(t, err.Error(), wal.EnvRingFed)
	assert.Nil(t, p)
}

func TestOpenPersistence_RingFedOnlyInLocalMode(t *testing.T) {
	t.Setenv("I2SIG_STORE_MEM_DIRECTORY", t.TempDir())
	t.Setenv(wal.EnvRingFed, "true")
	t.Setenv(wal.EnvMode, "majority")
	p, err := OpenPersistence("memorydb:", "test_wal_ringfed_majority")
	require.NoError(t, err)
	assert.False(t, p.WALRingFed, "ignored in majority mode")
	_ = p.Storage.Close()

	t.Setenv("I2SIG_STORE_MEM_DIRECTORY", t.TempDir())
	t.Setenv(wal.EnvMode, "local")
	t.Setenv(wal.EnvDir, t.TempDir())
	p, err = OpenPersistence("memorydb:", "test_wal_ringfed_local")
	require.NoError(t, err)
	require.NotNil(t, p.WAL)
	assert.True(t, p.WALRingFed)
	assert.NoError(t, p.WAL.Close())
	_ = p.Storage.Close()
}
