package server

import (
	"log/slog"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/i2-open/i2goSignals/internal/providers/dbProviders/memory_provider"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// newAdvertiseApp builds a node "node-a" on a fresh memory coordinator with
// the given BASE_URL.
func newAdvertiseApp(t *testing.T, baseUrl string) (*SignalsApplication, *memory_provider.MemoryCoordinator) {
	t.Helper()
	u, err := url.Parse(baseUrl)
	require.NoError(t, err)
	coord := memory_provider.NewMemoryCoordinator()
	sa := &SignalsApplication{Coordinator: coord, NodeID: "node-a", BaseUrl: u, StartedAt: time.Now().UTC()}
	return sa, coord
}

func advertisedAddressOf(t *testing.T, coord *memory_provider.MemoryCoordinator, id string) string {
	t.Helper()
	nodes, err := coord.GetActiveNodes()
	require.NoError(t, err)
	for _, n := range nodes {
		if n.Id == id {
			return n.Address
		}
	}
	t.Fatalf("node %s not registered", id)
	return ""
}

// captureLogs routes slog.Default (which every logger.Sub logger defers to)
// into a buffer for the rest of the test.
func captureLogs(t *testing.T) *safeBuffer {
	t.Helper()
	buf := &safeBuffer{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return buf
}

const dupAddrMsg = "another live cluster node advertises the same wake-up address"

func countLines(s, substr string) int {
	n := 0
	for _, line := range strings.Split(s, "\n") {
		if strings.Contains(line, substr) {
			n++
		}
	}
	return n
}

// TestRegisterNode_AdvertiseURLStoredVerbatim: I2SIG_CLUSTER_ADVERTISE_URL is
// stored in cluster_nodes exactly as given, ignoring BASE_URL and the
// internal port (#348).
func TestRegisterNode_AdvertiseURLStoredVerbatim(t *testing.T) {
	t.Setenv("I2SIG_CLUSTER_ADVERTISE_URL", "http://goSignals1b:8898")
	t.Setenv("I2SIG_CLUSTER_INTERNAL_PORT", "9999")
	sa, coord := newAdvertiseApp(t, "https://gosignals1:8888/")

	sa.registerNode()

	assert.Equal(t, "http://goSignals1b:8898", advertisedAddressOf(t, coord, "node-a"))
}

// TestRegisterNode_DerivedAddressWhenAdvertiseURLUnset: with no override the
// address is derived exactly as before #348 — BASE_URL host, the internal
// port if set else the BASE_URL port, always http.
func TestRegisterNode_DerivedAddressWhenAdvertiseURLUnset(t *testing.T) {
	t.Setenv("I2SIG_CLUSTER_ADVERTISE_URL", "")

	t.Run("main port", func(t *testing.T) {
		t.Setenv("I2SIG_CLUSTER_INTERNAL_PORT", "")
		sa, coord := newAdvertiseApp(t, "https://gosignals1:8888/")
		sa.registerNode()
		assert.Equal(t, "http://gosignals1:8888", advertisedAddressOf(t, coord, "node-a"))
	})

	t.Run("internal port", func(t *testing.T) {
		t.Setenv("I2SIG_CLUSTER_INTERNAL_PORT", "8898")
		sa, coord := newAdvertiseApp(t, "https://gosignals1:8888/")
		sa.registerNode()
		assert.Equal(t, "http://gosignals1:8898", advertisedAddressOf(t, coord, "node-a"))
	})
}

// TestRegisterNode_WarnsOnceWhenPeerAdvertisesSameAddress: a live peer with
// the same advertised address (host compared case-insensitively) produces
// one WARN naming both node ids, not one per heartbeat (#348).
func TestRegisterNode_WarnsOnceWhenPeerAdvertisesSameAddress(t *testing.T) {
	t.Setenv("I2SIG_CLUSTER_ADVERTISE_URL", "")
	t.Setenv("I2SIG_CLUSTER_INTERNAL_PORT", "")
	logs := captureLogs(t)
	sa, coord := newAdvertiseApp(t, "https://gosignals1:8888/")
	now := time.Now().UTC()
	require.NoError(t, coord.RegisterNode(model.ClusterNode{Id: "node-b", Address: "http://goSignals1:8888", StartedAt: now, LastSeenAt: now}))

	sa.registerNode() // registration
	sa.registerNode() // heartbeat
	sa.registerNode() // heartbeat

	out := logs.String()
	require.Equal(t, 1, countLines(out, dupAddrMsg), out)
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, dupAddrMsg) {
			assert.Contains(t, line, "level=WARN")
			assert.Contains(t, line, "node-a")
			assert.Contains(t, line, "node-b")
		}
	}
}

// TestRegisterNode_NoWarningForDistinctAddresses: peers with their own
// addresses are the healthy case and log nothing.
func TestRegisterNode_NoWarningForDistinctAddresses(t *testing.T) {
	t.Setenv("I2SIG_CLUSTER_ADVERTISE_URL", "http://goSignals1:8898")
	logs := captureLogs(t)
	sa, coord := newAdvertiseApp(t, "https://gosignals1:8888/")
	now := time.Now().UTC()
	require.NoError(t, coord.RegisterNode(model.ClusterNode{Id: "node-b", Address: "http://goSignals1b:8898", StartedAt: now, LastSeenAt: now}))

	sa.registerNode()
	sa.registerNode()

	assert.Equal(t, 0, countLines(logs.String(), dupAddrMsg))
}
