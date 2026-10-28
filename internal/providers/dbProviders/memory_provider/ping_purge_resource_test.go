package memory_provider_test

import (
	"testing"

	"github.com/i2-open/i2goSignals/internal/providers/cluster"
	"github.com/i2-open/i2goSignals/pkg/services"
)

// The runner's lease resource is the one the coordinators store lastPurgeAt on.
func TestPingPurgeResourceMatchesRunner(t *testing.T) {
	if cluster.PingPurgeResource != services.PingPurgeLeaseResource {
		t.Fatalf("cluster.PingPurgeResource = %q, services.PingPurgeLeaseResource = %q", cluster.PingPurgeResource, services.PingPurgeLeaseResource)
	}
}
