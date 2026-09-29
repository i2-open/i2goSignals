package dbProviders

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/i2-open/i2goSignals/internal/providers/cluster"
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

func TestAttachLocalWal_RefusesMultiNodeCluster(t *testing.T) {
	p := &Persistence{Coordinator: &nodesCoordinator{nodes: []model.ClusterNode{{Id: "self"}, {Id: "peer"}}}}
	err := attachLocalWal(p, "self", t.TempDir())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "single-node only")
	assert.Contains(t, err.Error(), "peer")
	assert.Nil(t, p.WAL)
}

func TestAttachLocalWal_RefusesWhenMembershipUnknown(t *testing.T) {
	p := &Persistence{Coordinator: &nodesCoordinator{err: errors.New("lease store down")}}
	err := attachLocalWal(p, "self", t.TempDir())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot confirm single-node")
	assert.Nil(t, p.WAL)
}

func TestAttachLocalWal_AllowsSelfOnly(t *testing.T) {
	p := &Persistence{Coordinator: &nodesCoordinator{nodes: []model.ClusterNode{{Id: "self"}}}}
	require.NoError(t, attachLocalWal(p, "self", t.TempDir()))
	require.NotNil(t, p.WAL)
	assert.NoError(t, p.WAL.Close())
}
