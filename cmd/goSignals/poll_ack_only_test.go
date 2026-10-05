package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
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

// An ordinary poll carries its maxEvents and setErrs through the RFC 8936
// wire request; an unset maxEvents stays off the wire (#369).
func TestPollCmd_DoPollRequestWireBody(t *testing.T) {
	var raw []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"sets":{}}`))
	}))
	defer server.Close()

	p := &PollCmd{}
	_, err := p.DoPollRequest(context.Background(), server.Client(), model.PollParameters{
		MaxEvents: 5,
		SetErrs:   map[string]model.SetErrorType{"jti-2": {Error: "invalid_request", Description: "bad"}},
	}, server.URL, "Bearer t", make(chan struct{}))
	require.NoError(t, err)
	var wire map[string]any
	require.NoError(t, json.Unmarshal(raw, &wire))
	assert.EqualValues(t, 5, wire["maxEvents"])
	assert.Equal(t, map[string]any{"jti-2": map[string]any{"err": "invalid_request", "description": "bad"}}, wire["setErrs"])

	_, err = p.DoPollRequest(context.Background(), server.Client(), model.PollParameters{ReturnImmediately: true}, server.URL, "Bearer t", make(chan struct{}))
	require.NoError(t, err)
	wire = nil
	require.NoError(t, json.Unmarshal(raw, &wire))
	assert.NotContains(t, wire, "maxEvents")
}
