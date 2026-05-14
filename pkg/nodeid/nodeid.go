// Package nodeid resolves a stable identifier for the running process,
// used in cluster lease ownership, log default attributes, and metrics labels.
//
// Resolution order:
//  1. NODE_ID environment variable
//  2. POD_NAME environment variable (Kubernetes downward-API convention)
//  3. <hostname>-<unix-seconds> fallback
package nodeid

import (
    "fmt"
    "os"
    "time"
)

// Resolve returns the node identifier for this process.
func Resolve() string {
    if id := os.Getenv("NODE_ID"); id != "" {
        return id
    }
    if id := os.Getenv("POD_NAME"); id != "" {
        return id
    }
    hostname, _ := os.Hostname()
    return fmt.Sprintf("%s-%d", hostname, time.Now().Unix())
}