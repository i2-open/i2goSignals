package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestPprofMux_ServesIndexAndProfiles(t *testing.T) {
	srv := httptest.NewServer(newPprofMux())
	defer srv.Close()

	for _, path := range []string{
		"/debug/pprof/",
		"/debug/pprof/heap",
		"/debug/pprof/goroutine",
		"/debug/pprof/cmdline",
		"/debug/pprof/mutex",
		"/debug/pprof/block",
	} {
		resp, err := http.Get(srv.URL + path)
		if assert.NoError(t, err, path) {
			assert.Equal(t, http.StatusOK, resp.StatusCode, path)
			_ = resp.Body.Close()
		}
	}
}

func TestStartPprofServer_NoopWhenUnset(t *testing.T) {
	t.Setenv(PprofAddrEnv, "")
	sa := &SignalsApplication{}
	sa.startPprofServer()
	assert.Nil(t, sa.PprofServer)
}

func TestPprofSamplingRates_OffByDefault(t *testing.T) {
	t.Setenv(PprofMutexFractionEnv, "")
	t.Setenv(PprofBlockRateEnv, "")

	mutexFraction, blockRate := pprofSamplingRates()
	assert.Equal(t, 0, mutexFraction, "mutex profiling must be off unless asked for")
	assert.Equal(t, 0, blockRate, "block profiling must be off unless asked for")
}

func TestPprofSamplingRates_Parsing(t *testing.T) {
	tests := []struct {
		name      string
		mutex     string
		block     string
		wantMutex int
		wantBlock int
	}{
		{name: "positive", mutex: "7", block: "1000", wantMutex: 7, wantBlock: 1000},
		{name: "explicit zero", mutex: "0", block: "0"},
		{name: "negative", mutex: "-1", block: "-5"},
		{name: "unparseable", mutex: "yes", block: "1e6"},
		{name: "surrounding whitespace", mutex: " 5 ", block: " 250 ", wantMutex: 5, wantBlock: 250},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv(PprofMutexFractionEnv, test.mutex)
			t.Setenv(PprofBlockRateEnv, test.block)

			mutexFraction, blockRate := pprofSamplingRates()
			assert.Equal(t, test.wantMutex, mutexFraction)
			assert.Equal(t, test.wantBlock, blockRate)
		})
	}
}

// TestApplyPprofSamplingRates_ProfilesReturnSamples is the acceptance check:
// with the knobs set, /debug/pprof/mutex and /debug/pprof/block report samples.
func TestApplyPprofSamplingRates_ProfilesReturnSamples(t *testing.T) {
	previousFraction := runtime.SetMutexProfileFraction(-1)
	t.Cleanup(func() {
		runtime.SetMutexProfileFraction(previousFraction)
		runtime.SetBlockProfileRate(0)
	})

	t.Setenv(PprofMutexFractionEnv, "1")
	t.Setenv(PprofBlockRateEnv, "1")
	applyPprofSamplingRates()

	assert.Equal(t, 1, runtime.SetMutexProfileFraction(-1), "mutex profile fraction should be applied")

	// Contend a mutex so both the mutex and the block profile have something
	// to report: the waiting goroutine blocks, and the holder's unlock records
	// the contention.
	var mu sync.Mutex
	var waiting sync.WaitGroup
	waiting.Add(1)
	mu.Lock()
	go func() {
		defer waiting.Done()
		mu.Lock()
		mu.Unlock() //nolint:staticcheck // contention is the point of the test
	}()
	time.Sleep(50 * time.Millisecond)
	mu.Unlock()
	waiting.Wait()

	srv := httptest.NewServer(newPprofMux())
	defer srv.Close()

	mutexProfile := getProfile(t, srv.URL+"/debug/pprof/mutex?debug=1")
	assert.Contains(t, mutexProfile, "sampling period=1", "mutex profile should report the configured fraction")
	assert.Contains(t, mutexProfile, "@", "mutex profile should carry at least one contention record")

	blockProfile := getProfile(t, srv.URL+"/debug/pprof/block?debug=1")
	assert.Contains(t, blockProfile, "@", "block profile should carry at least one blocking record")
}

// TestStartPprofServer_LeavesSamplingOffWhenAddrUnset proves the knobs are only
// read when the pprof listener itself is enabled, so a deployment that did not
// ask for profiling never pays the sampling overhead.
func TestStartPprofServer_LeavesSamplingOffWhenAddrUnset(t *testing.T) {
	previousFraction := runtime.SetMutexProfileFraction(-1)
	t.Cleanup(func() { runtime.SetMutexProfileFraction(previousFraction) })

	t.Setenv(PprofAddrEnv, "")
	t.Setenv(PprofMutexFractionEnv, "5")
	t.Setenv(PprofBlockRateEnv, "5")

	sa := &SignalsApplication{}
	sa.startPprofServer()

	assert.Nil(t, sa.PprofServer)
	assert.Equal(t, previousFraction, runtime.SetMutexProfileFraction(-1),
		"mutex profiling must stay untouched when the pprof listener is off")
}

func getProfile(t *testing.T, url string) string {
	t.Helper()

	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("fetching %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode, url)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading %s: %v", url, err)
	}
	return string(body)
}
