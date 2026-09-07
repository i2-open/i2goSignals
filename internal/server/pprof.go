package server

import (
	"errors"
	"net/http"
	"net/http/pprof"
	"os"
	"time"
)

// PprofAddrEnv names the environment variable that enables the pprof listener.
// When set (e.g. ":6060" or "127.0.0.1:6060") the server starts a separate
// plain-HTTP listener serving the standard net/http/pprof endpoints under
// /debug/pprof/. The listener is unauthenticated and unencrypted, so it must
// only be bound to a loopback/private address in development environments.
// Leave unset in production.
const PprofAddrEnv = "I2SIG_PPROF_ADDR"

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
