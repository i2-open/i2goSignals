package server

import (
	"encoding/json"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/i2-open/i2goSignals/pkg/authSupport"
)

type WakeRequest struct {
	Sid  string `json:"sid"`
	Mode string `json:"mode"`
}

var (
	recentWakes   = make(map[string]time.Time)
	recentWakesMu sync.Mutex
)

func (sa *SignalsApplication) WakeTransmitter(w http.ResponseWriter, r *http.Request) {
	var req WakeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if req.Sid == "" || (req.Mode != "push" && req.Mode != "poll") {
		http.Error(w, "invalid sid or mode", http.StatusBadRequest)
		return
	}

	// Validate HMAC
	secret := os.Getenv("I2SIG_CLUSTER_INTERNAL_TOKEN")
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || len(authHeader) < 7 || !authSupport.ValidateClusterToken(secret, authHeader[7:], req.Sid, req.Mode, 30*time.Second) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Rate limiting / Coalescing: check if we've seen this SID+Mode recently
	key := req.Sid + ":" + req.Mode
	recentWakesMu.Lock()
	lastWake, exists := recentWakes[key]
	if exists && time.Since(lastWake) < 250*time.Millisecond {
		recentWakesMu.Unlock()
		w.WriteHeader(http.StatusAccepted)
		return
	}
	recentWakes[key] = time.Now()
	recentWakesMu.Unlock()

	// Clean up recentWakes periodically (simplified here, in production use a TTL cache)
	go func() {
		time.Sleep(1 * time.Minute)
		recentWakesMu.Lock()
		if t, ok := recentWakes[key]; ok && time.Since(t) >= 1*time.Minute {
			delete(recentWakes, key)
		}
		recentWakesMu.Unlock()
	}()

	sa.EventRouter.WakeTransmitter(req.Sid, req.Mode)

	w.WriteHeader(http.StatusAccepted)
}

func (sa *SignalsApplication) startInternalServer() {
	port := os.Getenv("I2SIG_CLUSTER_INTERNAL_PORT")
	if port == "" {
		// Use main server port (default behavior)
		return
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/_cluster/wake-transmitter", sa.WakeTransmitter)

	sa.InternalServer = &http.Server{
		Addr:    ":" + port,
		Handler: mux,
	}

	go func() {
		serverLog.Info("Internal cluster server listening", "port", port)
		if err := sa.InternalServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serverLog.Error("Internal cluster server failed", "error", err)
		}
	}()
}
