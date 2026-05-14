package nodeid

import "testing"

// TestResolve_NewNameWinsOverOld asserts the v0.11.0 rename precedence:
// I2SIG_CLUSTER_NODE_ID beats the deprecated NODE_ID when both are set.
func TestResolve_NewNameWinsOverOld(t *testing.T) {
    t.Setenv("I2SIG_CLUSTER_NODE_ID", "new-node-1")
    t.Setenv("NODE_ID", "old-node-1")
    if got := Resolve(); got != "new-node-1" {
        t.Fatalf("Resolve() = %q, want %q (new I2SIG_CLUSTER_NODE_ID must win)", got, "new-node-1")
    }
}

// TestResolve_OldNameStillRead proves backwards compatibility: a deployment
// that has not yet renamed NODE_ID continues to work.
func TestResolve_OldNameStillRead(t *testing.T) {
    t.Setenv("I2SIG_CLUSTER_NODE_ID", "")
    t.Setenv("NODE_ID", "legacy-node")
    if got := Resolve(); got != "legacy-node" {
        t.Fatalf("Resolve() = %q, want %q (deprecated NODE_ID must still resolve)", got, "legacy-node")
    }
}
