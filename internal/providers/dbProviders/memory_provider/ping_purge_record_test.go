package memory_provider

import (
	"testing"
	"time"

	"github.com/i2-open/i2goSignals/internal/providers/cluster"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RecordPingPurge stores lastPurgeAt on the ping-purge lease row while the
// caller's fencing token is current; a stale token records nothing (ADR 0048).
func TestMemoryCoordinator_RecordPingPurge(t *testing.T) {
	c := NewMemoryCoordinator()
	at, err := c.LastPingPurge()
	require.NoError(t, err)
	assert.True(t, at.IsZero(), "no row yet")

	ok, token, _, err := c.TryAcquireOrRenewLease(cluster.PingPurgeResource, "node-A", time.Minute)
	require.NoError(t, err)
	require.True(t, ok)
	when := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	recorded, err := c.RecordPingPurge(when, token)
	require.NoError(t, err)
	assert.True(t, recorded)
	at, _ = c.LastPingPurge()
	assert.True(t, at.Equal(when))

	recorded, err = c.RecordPingPurge(when.Add(time.Hour), token+1)
	require.NoError(t, err)
	assert.False(t, recorded, "a stale token records nothing")
	at, _ = c.LastPingPurge()
	assert.True(t, at.Equal(when))

	require.NoError(t, c.ReleaseLeaseIfOwned(cluster.PingPurgeResource, "node-A"))
	at, _ = c.LastPingPurge()
	assert.True(t, at.Equal(when), "a released lease keeps lastPurgeAt")
}
