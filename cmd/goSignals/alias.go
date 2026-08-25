package main

import "github.com/i2-open/i2goSignals/pkg/authSupport"

// generateAlias delegates to the shared crypto/rand-backed helper so the CLI
// and server mint aliases the same way.
func generateAlias(n int) string {
	return authSupport.GenerateAlias(n)
}
