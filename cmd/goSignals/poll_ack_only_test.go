package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The CLI's acknowledgement-only request puts an explicit "maxEvents": 0 on
// the wire, so the transmitter returns no SETs on it (#369).
func TestPollCmd_DoAckOnlySendsExplicitZeroMaxEvents(t *testing.T) {
	var raw []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"sets":{}}`))
	}))
	defer server.Close()

	p := &PollCmd{AutoAck: true, Acks: []string{"jti-1"}}
	p.DoAckOnly(context.Background(), server.Client(), server.URL, "Bearer t", make(chan struct{}))

	var wire map[string]any
	require.NoError(t, json.Unmarshal(raw, &wire))
	require.Contains(t, wire, "maxEvents")
	assert.EqualValues(t, 0, wire["maxEvents"])
	assert.Equal(t, true, wire["returnImmediately"])
	assert.Equal(t, []any{"jti-1"}, wire["ack"])
}
