package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/i2-open/i2goSignals/internal/providers/dbProviders"
	"github.com/stretchr/testify/require"
)

func TestHealthEndpointMemoryProvider(t *testing.T) {
	t.Setenv("I2SIG_STORE_MEM_DIRECTORY", t.TempDir())
	persistence, err := dbProviders.OpenPersistence("memorydb:", "test_health_signals")
	require.NoError(t, err)

	sa := NewApplication(persistence, "")
	defer sa.Shutdown()

	ts := httptest.NewServer(sa.Handler)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/health")
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
}
