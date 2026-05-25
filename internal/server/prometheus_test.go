package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/i2-open/i2goSignals/internal/providers/dbProviders"
	"github.com/i2-open/i2goSignals/internal/providers/dbProviders/memory_provider"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClusterMetrics(t *testing.T) {
	// 1. Setup Memory Provider
	t.Setenv("I2SIG_STORE_MEM_DIRECTORY", t.TempDir())
	provider, err := memory_provider.Open("memorydb://localhost", "test_metrics")
	require.NoError(t, err)

	persistence := &dbProviders.Persistence{
		StreamService: provider.GetStreamService(),
		KeyService:    provider.GetKeyService(),
		EventService:  provider.GetEventService(),
		ClientService: provider.GetClientService(),
		ServerService: provider.GetServerService(),
		TokenService:  provider.GetTokenService(),
		Coordinator:   provider.Coordinator(),
		Storage:       memory_provider.NewMemoryStorage(provider),
	}

	// 2. Setup Signals Application
	sa := NewApplication(persistence, "http://localhost:8080")
	defer sa.Shutdown()

	// 2.1 Use a fresh registry for testing to avoid conflicts with global registry
	registry := prometheus.NewRegistry()
	sa.InitializePrometheusWithRegisterer(registry)

	// 2.2 Wait for backgroundSync's initial node registration so the metrics
	// check below sees all 3 expected nodes (sa.NodeID + 2 test nodes). Without
	// this, the test races against the goroutine started in NewApplication.
	require.Eventually(t, func() bool {
		nodes, _ := provider.GetActiveNodes()
		for _, n := range nodes {
			if n.Id == sa.NodeID {
				return true
			}
		}
		return false
	}, 2*time.Second, 10*time.Millisecond, "app's own node should self-register via backgroundSync")

	// 3. Register a node (this node is already registered by backgroundSync, but we can overwrite or add more)
	node := model.ClusterNode{
		Id:         "test-node-1",
		Address:    "http://test-node-1:8080",
		Version:    "1.2.3",
		StartedAt:  time.Now().UTC().Add(-10 * time.Minute),
		LastSeenAt: time.Now().UTC(),
	}
	err = provider.RegisterNode(node)
	require.NoError(t, err)

	// 4. Register another node
	node2 := model.ClusterNode{
		Id:         "test-node-2",
		Address:    "http://test-node-2:8080",
		Version:    "1.2.4",
		StartedAt:  time.Now().UTC().Add(-5 * time.Minute),
		LastSeenAt: time.Now().UTC(),
	}
	err = provider.RegisterNode(node2)
	require.NoError(t, err)

	// 5. Collect metrics
	req := httptest.NewRequest("GET", "/metrics", nil)
	rr := httptest.NewRecorder()
	promhttp.HandlerFor(registry, promhttp.HandlerOpts{}).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	body, err := io.ReadAll(rr.Body)
	require.NoError(t, err)
	metrics := string(body)

	// 6. Verify node info metrics
	assert.Contains(t, metrics, `goSignals_cluster_node_info{address="http://test-node-1:8080",node_id="test-node-1",version="1.2.3"} 1`)
	assert.Contains(t, metrics, `goSignals_cluster_node_info{address="http://test-node-2:8080",node_id="test-node-2",version="1.2.4"} 1`)

	// 7. Verify uptime metrics
	assert.Contains(t, metrics, `goSignals_cluster_node_uptime_seconds{node_id="test-node-1"}`)
	assert.Contains(t, metrics, `goSignals_cluster_node_uptime_seconds{node_id="test-node-2"}`)

	// 8. Verify last seen metrics
	assert.Contains(t, metrics, `goSignals_cluster_node_last_seen_seconds{node_id="test-node-1"}`)
	assert.Contains(t, metrics, `goSignals_cluster_node_last_seen_seconds{node_id="test-node-2"}`)

	// 9. Verify nodes count metric (existing one)
	// There should be 3 nodes: sa.NodeID (from NewApplication), test-node-1, test-node-2
	assert.Contains(t, metrics, `goSignals_cluster_nodes_count 3`)
}
