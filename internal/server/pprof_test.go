package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

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
