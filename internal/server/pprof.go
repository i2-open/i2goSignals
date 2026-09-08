package server

import (
	"errors"
	"net/http"
	"net/http/pprof"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// PprofAddrEnv names the environment variable that enables the pprof listener.
// When set (e.g. ":6060" or "127.0.0.1:6060") the server starts a separate
// plain-HTTP listener serving the standard net/http/pprof endpoints under
// /debug/pprof/. The listener is unauthenticated and unencrypted, so it must
// only be bound to a loopback/private address in development environments.
// Leave unset in production.
const PprofAddrEnv = "I2SIG_PPROF_ADDR"

// PprofMutexFractionEnv names the environment variable that turns on mutex
// profiling, so /debug/pprof/mutex reports contention instead of an empty
// profile. The value is the fraction passed to runtime.SetMutexProfileFraction:
// 1 samples every contention event, N samples roughly one in N. It is read only
// when PprofAddrEnv is set, and defaults to off, so a deployment that has not
// asked for profiling never pays the sampling cost.
const PprofMutexFractionEnv = "I2SIG_PPROF_MUTEX_FRACTION"

// PprofBlockRateEnv names the environment variable that turns on block
// profiling, so /debug/pprof/block shows where goroutines wait on channels and
// sync primitives. The value is the rate passed to runtime.SetBlockProfileRate,
// in nanoseconds of blocking per sample: 1 samples every blocking event, N
// samples roughly one event per N nanoseconds blocked. Like the mutex knob it
// is read only when PprofAddrEnv is set and defaults to off. Block profiling
// instruments every blocking operation and has measurable overhead — enable it
// for a diagnostic run, not permanently.
const PprofBlockRateEnv = "I2SIG_PPROF_BLOCK_RATE"

// newPprofMux returns a mux serving the net/http/pprof handlers. Kept separate
// from the main router so profiling never rides on the authenticated API
// surface and can be bound to its own address.
func newPprofMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	return mux
}

// startPprofServer starts the pprof listener when I2SIG_PPROF_ADDR is set.
// It is a no-op otherwise.
func (sa *SignalsApplication) startPprofServer() {
	addr := os.Getenv(PprofAddrEnv)
	if addr == "" {
		return
	}

	applyPprofSamplingRates()

	srv := &http.Server{
		Addr:    addr,
		Handler: newPprofMux(),
		// No WriteTimeout: /debug/pprof/profile and /trace stream for the
		// caller-supplied ?seconds= duration and would otherwise be cut short.
		ReadHeaderTimeout: 10 * time.Second,
	}
	sa.PprofServer = srv
	go func() {
		serverLog.Warn("pprof listener enabled (plain HTTP, unauthenticated) — development use only",
			"addr", addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverLog.Error("pprof listener failed", "error", err)
		}
	}()
}

// applyPprofSamplingRates turns on mutex and/or block profiling when the opt-in
// env vars ask for it. The runtime setters are called only for a positive rate,
// so leaving the variables unset costs exactly what it did before.
func applyPprofSamplingRates() {
	mutexFraction, blockRate := pprofSamplingRates()

	if mutexFraction > 0 {
		runtime.SetMutexProfileFraction(mutexFraction)
		serverLog.Warn("mutex profiling enabled — sampling adds overhead on contended locks",
			"env", PprofMutexFractionEnv, "fraction", mutexFraction)
	}

	if blockRate > 0 {
		runtime.SetBlockProfileRate(blockRate)
		serverLog.Warn("block profiling enabled — sampling adds measurable overhead on every blocking operation",
			"env", PprofBlockRateEnv, "rateNanos", blockRate)
	}
}

// pprofSamplingRates reads the mutex and block profiling knobs. Anything that
// is not a positive integer — unset, zero, negative, or unparseable — means
// "leave this profile off".
func pprofSamplingRates() (mutexFraction int, blockRate int) {
	return pprofSamplingRate(PprofMutexFractionEnv), pprofSamplingRate(PprofBlockRateEnv)
}

func pprofSamplingRate(env string) int {
	raw := strings.TrimSpace(os.Getenv(env))
	if raw == "" {
		return 0
	}

	rate, err := strconv.Atoi(raw)
	if err != nil || rate < 0 {
		serverLog.Warn("ignoring profiling rate that is not a non-negative integer; profile stays off",
			"env", env, "value", raw)
		return 0
	}
	return rate
}
