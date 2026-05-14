package nodeid

import (
    "os"
    "regexp"
    "strings"
    "testing"
)

func TestResolve_NodeIDWins(t *testing.T) {
    t.Setenv("NODE_ID", "explicit-node-1")
    t.Setenv("POD_NAME", "should-not-be-used")
    if got := Resolve(); got != "explicit-node-1" {
        t.Fatalf("Resolve() = %q, want %q", got, "explicit-node-1")
    }
}

func TestResolve_PodNameFallback(t *testing.T) {
    t.Setenv("NODE_ID", "")
    t.Setenv("POD_NAME", "k8s-pod-7")
    if got := Resolve(); got != "k8s-pod-7" {
        t.Fatalf("Resolve() = %q, want %q", got, "k8s-pod-7")
    }
}

func TestResolve_HostnameTimestampFallback(t *testing.T) {
    t.Setenv("NODE_ID", "")
    t.Setenv("POD_NAME", "")
    got := Resolve()
    host, _ := os.Hostname()
    prefix := host + "-"
    if !strings.HasPrefix(got, prefix) {
        t.Fatalf("Resolve() = %q, want prefix %q", got, prefix)
    }
    // Suffix should be a positive integer (unix seconds).
    suffix := strings.TrimPrefix(got, prefix)
    matched, _ := regexp.MatchString(`^[0-9]+$`, suffix)
    if !matched {
        t.Fatalf("Resolve() suffix = %q, want all digits", suffix)
    }
}
