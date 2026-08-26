// Package goroutineleak turns Go 1.27's goroutine-leak profile into a test gate.
//
// Go 1.27 GA'd goroutine leak detection as a runtime/pprof profile named
// "goroutineleak": writing it runs a GC cycle with leak detection enabled and
// then reports the goroutines the runtime proved can never become runnable
// again — a goroutine blocked forever on a channel or mutex no live goroutine
// can ever signal. It is not the heuristic "count goroutines before and after"
// check the ecosystem used to hand-roll; a goroutine that is merely slow to
// finish is not reported, so there is nothing to tune and nothing to flake on.
//
// This package exists because the timer paths this project cares about — lease
// heartbeats, push recovery backoff, long-poll waits, the T3 idle keepalive —
// fail in exactly the shape the profile detects. A regression that abandons a
// goroutine on a timer channel nobody will ever send to costs nothing at the
// moment it is written and shows up in production as a slow leak. Run inside
// the test binary, the profile turns that into a failing package.
//
// Usage is one line in a package's TestMain:
//
//	func TestMain(m *testing.M) { os.Exit(goroutineleak.Run(m)) }
//
// The check only runs when the environment opts in (see EnvVar), so an ordinary
// `go test ./...` is unchanged and `make qa` is the thing that enforces it.
package goroutineleak

import (
	"bytes"
	"fmt"
	"os"
	"runtime/pprof"
	"testing"
)

// EnvVar opts a test binary into the leak check. `make qa` sets it for the
// suites listed in its goroutine-leak step; nothing else does.
//
// The check is opt-in rather than always-on for one reason: a leak is a
// property of the whole package run, so a failure names the package and not the
// test that caused it. Leaving it off by default keeps that blunt failure out of
// the tight edit/test loop, where a developer wants the failing *test*, and puts
// it in the gate, where "this package leaks" is exactly the right granularity.
const EnvVar = "I2SIG_GOROUTINE_LEAK_CHECK"

// Enabled reports whether the leak check is switched on for this process.
func Enabled() bool {
	v := os.Getenv(EnvVar)
	return v != "" && v != "0" && v != "false"
}

// Run runs the package's tests and returns the exit code the caller should pass
// to os.Exit. When the check is enabled and the tests otherwise passed, a
// non-empty leak profile turns a passing run into exit code 1 and prints the
// leaked goroutines' stacks to stderr.
//
// A failing run is reported as-is: a package whose tests already failed has no
// business also being blamed for the goroutines those failures abandoned.
func Run(m *testing.M) int {
	code := m.Run()
	if code != 0 || !Enabled() {
		return code
	}
	if report, leaked := Check(); leaked {
		fmt.Fprint(os.Stderr, report)
		return 1
	}
	return code
}

// Check writes the goroutineleak profile and reports whether it named anything.
// The returned string is a human-readable report including each leaked
// goroutine's stack, empty when there is no leak.
//
// It is exported separately from Run so a test can assert on the profile
// directly — the leak gate's own test does exactly that.
func Check() (report string, leaked bool) {
	p := pprof.Lookup("goroutineleak")
	if p == nil {
		// A toolchain without the profile cannot enforce the gate. Say so
		// rather than silently reporting "no leaks".
		return "", false
	}

	// debug=1 renders symbolised stacks rather than the binary pprof encoding,
	// which is what a CI log needs. Writing the profile is what triggers the
	// leak-detecting GC, so p.Count() is only meaningful afterwards.
	var buf bytes.Buffer
	if err := p.WriteTo(&buf, 1); err != nil {
		return fmt.Sprintf("goroutine leak check: writing profile failed: %v\n", err), false
	}
	n := p.Count()
	if n == 0 {
		return "", false
	}
	return fmt.Sprintf(
		"\nFAIL: %d leaked goroutine(s) after this package's tests "+
			"(Go 1.27 goroutineleak profile; %s=1).\n"+
			"A leaked goroutine is one the runtime proved can never run again — "+
			"typically a wait on a timer or channel whose only sender is gone.\n\n%s\n",
		n, EnvVar, buf.String()), true
}
