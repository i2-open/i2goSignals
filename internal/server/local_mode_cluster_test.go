package server

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/i2-open/i2goSignals/internal/eventRouter"
	"github.com/i2-open/i2goSignals/internal/providers/cluster"
	"github.com/i2-open/i2goSignals/internal/providers/dbProviders"
	"github.com/i2-open/i2goSignals/internal/providers/dbProviders/memory_provider"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// suspendingRouter records the #343 step-down call.
type suspendingRouter struct {
	eventRouter.EventRouter
	suspended int
}

func (r *suspendingRouter) SuspendLocalIngest() { r.suspended++ }

// failingNodesCoordinator fails the membership read.
type failingNodesCoordinator struct {
	cluster.ClusterCoordinator
}

func (failingNodesCoordinator) GetActiveNodes() ([]model.ClusterNode, error) {
	return nil, errors.New("coordinator down")
}

func newLocalModeApp(t *testing.T) (*SignalsApplication, *suspendingRouter, *memory_provider.MemoryCoordinator) {
	t.Helper()
	t.Setenv("I2SIG_STORE_MEM_DIRECTORY", t.TempDir())
	p, err := dbProviders.OpenPersistence("memorydb:", "local_mode_cluster_test")
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Storage.Close() })
	coord := memory_provider.NewMemoryCoordinator()
	sa := newTestApplication(p)
	sa.Coordinator = coord
	sa.NodeID = "node-a"
	sa.localModeUnfenced = true
	sa.StreamService.SetDeploymentDurabilityLocal(true)
	r := &suspendingRouter{}
	sa.EventRouter = r
	now := time.Now().UTC()
	require.NoError(t, coord.RegisterNode(model.ClusterNode{Id: "node-a", StartedAt: now, LastSeenAt: now}))
	return sa, r, coord
}

func localResolved(sa *SignalsApplication) model.DurabilityMode {
	return sa.StreamService.ResolveDurability(&model.StreamStateRecord{Durability: model.DurabilityLocal})
}

// TestEnforceLocalModeCluster_SuspendsWhenPeerJoins: a running local-mode node
// without ring-fed steps down once, the first heartbeat that sees a peer (#343),
// and stays down when the peer later leaves.
func TestEnforceLocalModeCluster_SuspendsWhenPeerJoins(t *testing.T) {
	sa, r, coord := newLocalModeApp(t)

	sa.enforceLocalModeCluster()
	assert.Equal(t, 0, r.suspended, "alone: nothing happens")
	assert.Equal(t, model.DurabilityLocal, localResolved(sa))

	now := time.Now().UTC()
	require.NoError(t, coord.RegisterNode(model.ClusterNode{Id: "node-b", StartedAt: now, LastSeenAt: now}))
	sa.enforceLocalModeCluster()
	assert.Equal(t, 1, r.suspended, "a peer joined: local ingest is suspended")
	assert.True(t, sa.localIngestSuspended)
	assert.Equal(t, model.DurabilityMajority, localResolved(sa), "durability=local now resolves to majority")

	sa.enforceLocalModeCluster()
	assert.Equal(t, 1, r.suspended, "suspension fires once")

	// The peer ageing out does not re-arm local ingest.
	require.NoError(t, coord.RegisterNode(model.ClusterNode{Id: "node-b", StartedAt: now, LastSeenAt: now.Add(-2 * time.Minute)}))
	sa.enforceLocalModeCluster()
	assert.True(t, sa.localIngestSuspended)
	assert.Equal(t, model.DurabilityMajority, localResolved(sa))
}

// TestEnforceLocalModeCluster_NotApplicable: majority mode and ring-fed local
// mode never step down, and a failed membership read is retried, not acted on.
func TestEnforceLocalModeCluster_NotApplicable(t *testing.T) {
	sa, r, coord := newLocalModeApp(t)
	now := time.Now().UTC()
	require.NoError(t, coord.RegisterNode(model.ClusterNode{Id: "node-b", StartedAt: now, LastSeenAt: now}))

	sa.localModeUnfenced = false // majority, or local with ring-fed on
	sa.enforceLocalModeCluster()
	assert.Equal(t, 0, r.suspended)
	assert.Equal(t, model.DurabilityLocal, localResolved(sa))

	sa.localModeUnfenced = true
	sa.Coordinator = failingNodesCoordinator{}
	sa.enforceLocalModeCluster()
	assert.Equal(t, 0, r.suspended, "a failed read is not a peer")
	assert.False(t, sa.localIngestSuspended)

	sa.Coordinator = coord
	sa.enforceLocalModeCluster()
	assert.Equal(t, 1, r.suspended, "the next good read enforces")
}
