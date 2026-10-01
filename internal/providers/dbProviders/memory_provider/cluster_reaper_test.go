package memory_provider

import (
	"strings"
	"testing"
	"time"

	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A node that stopped heartbeating before the cutoff is purged from the
// registry; a node seen since is kept (#350).
func TestMemoryCoordinator_PurgeStaleNodes(t *testing.T) {
	c := NewMemoryCoordinator()
	now := time.Now().UTC()
	require.NoError(t, c.RegisterNode(model.ClusterNode{Id: "gone", LastSeenAt: now.Add(-5 * time.Minute)}))
	require.NoError(t, c.RegisterNode(model.ClusterNode{Id: "live", LastSeenAt: now}))

	n, err := c.PurgeStaleNodes(now.Add(-90 * time.Second))
	require.NoError(t, err)
	assert.Equal(t, 1, n)

	gone, _ := c.GetNode("gone")
	assert.Nil(t, gone)
	live, _ := c.GetNode("live")
	assert.NotNil(t, live)
}

// A lease row expired before the cutoff is purged unless keep says its
// resource is still wanted; a live lease is never purged. A purged row is
// gone: the next acquirer starts again at fencing token 1 (#350).
func TestMemoryCoordinator_PurgeExpiredLeases(t *testing.T) {
	c := NewMemoryCoordinator()
	clock := time.Now().UTC()
	c.SetClock(func() time.Time { return clock })

	for _, res := range []string{"push-transmitter:deleted", "push-transmitter:kept", "push-transmitter:live"} {
		for i := 0; i < 3; i++ { // three tenures, so the token is 3
			ok, _, err := c.TryAcquireOrRenewLease(res, "node-A", time.Second)
			require.NoError(t, err)
			require.True(t, ok)
			require.NoError(t, c.ReleaseLeaseIfOwned(res, "node-A"))
		}
	}
	clock = clock.Add(5 * time.Minute)
	_, _, err := c.TryAcquireOrRenewLease("push-transmitter:live", "node-A", 30*time.Second)
	require.NoError(t, err)

	keep := func(resource string) bool { return strings.HasSuffix(resource, ":kept") }
	n, err := c.PurgeExpiredLeases(clock.Add(-90*time.Second), keep)
	require.NoError(t, err)
	assert.Equal(t, 1, n, "only the expired, unwanted row is purged")

	_, token, _ := c.TryAcquireOrRenewLease("push-transmitter:deleted", "node-B", time.Second)
	assert.Equal(t, int64(1), token, "the purged row is gone")
	_, token, _ = c.TryAcquireOrRenewLease("push-transmitter:kept", "node-B", time.Second)
	assert.Equal(t, int64(4), token, "a kept row keeps its fencing history")
	owner, _, _, _ := c.GetLeaseOwner("push-transmitter:live")
	assert.Equal(t, "node-A", owner, "a live lease is untouched")
}
