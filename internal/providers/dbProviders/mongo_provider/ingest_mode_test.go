package mongo_provider

import (
	"bytes"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSupportsOneTripIngest(t *testing.T) {
	cases := map[string]bool{
		"8.0.13":     true,
		"8.0.0-rc1":  true,
		"8.2.1":      true,
		"10.0.0":     true,
		"7.0.14":     false,
		"6.0.5":      false,
		"":           false,
		"garbage":    false,
		".8":         false,
		"v8.0.0":     false,
		"7.99.99-rc": false,
	}
	for v, want := range cases {
		assert.Equal(t, want, supportsOneTripIngest(v), "version %q", v)
	}
}

// TestSelectIngestMode_WarnsOnceBelow8 pins the operator signal: a pre-8.0 (or
// unknown) server logs exactly one WARN per process however often the
// provider reconnects, and an 8.0+ server logs none.
func TestSelectIngestMode_WarnsOnceBelow8(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	oneTripFallbackWarned = sync.Once{}
	t.Cleanup(func() { oneTripFallbackWarned = sync.Once{} })

	assert.True(t, selectIngestMode("8.0.13", log))
	assert.Empty(t, buf.String(), "8.0+ must not warn")

	assert.False(t, selectIngestMode("7.0.14", log))
	assert.False(t, selectIngestMode("7.0.14", log))
	assert.False(t, selectIngestMode("", log))
	assert.Equal(t, 1, strings.Count(buf.String(), "level=WARN"), "fallback must warn exactly once: %s", buf.String())
	assert.Contains(t, buf.String(), "7.0.14")
}

// TestConnect_SelectsOneTripOnLiveServer: against the dev stack (MongoDB 8.0)
// the provider records the server version and turns the one-trip ingest on.
func TestConnect_SelectsOneTripOnLiveServer(t *testing.T) {
	p := openEventIdxProvider(t)
	v := p.ServerVersion()
	require.NotEmpty(t, v, "buildInfo version must be captured on connect")
	assert.Equal(t, supportsOneTripIngest(v), p.eventDAO.OneTripIngest(), "server %s", v)
}
