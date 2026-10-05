package goSetPoll

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// An acknowledgement-only request (RFC 8936 §2.4) carries an explicit
// "maxEvents": 0; a request that leaves maxEvents out takes the
// transmitter's default (#369). The two must survive a round trip.

func TestPollRequest_AckOnlySendsExplicitZeroMaxEvents(t *testing.T) {
	body, err := json.Marshal(PollRequest{AckOnly: true, ReturnImmediately: true, Acks: []string{"jti-1"}})
	require.NoError(t, err)
	assert.JSONEq(t, `{"maxEvents":0,"returnImmediately":true,"ack":["jti-1"]}`, string(body))

	body, err = json.Marshal(PollRequest{ReturnImmediately: true})
	require.NoError(t, err)
	assert.NotContains(t, string(body), "maxEvents", "an unset maxEvents stays off the wire")
}

func TestParsePollRequest_DistinguishesExplicitZeroFromAbsent(t *testing.T) {
	parse := func(body string) *PollRequest {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/poll", bytes.NewBufferString(body))
		pr, err := ParsePollRequest(req)
		require.NoError(t, err)
		return pr
	}

	explicit := parse(`{"maxEvents":0,"returnImmediately":true,"ack":["a"]}`)
	assert.True(t, explicit.AckOnly, "an explicit maxEvents 0 is acknowledgement-only")
	assert.Zero(t, explicit.MaxEvents)
	assert.Equal(t, []string{"a"}, explicit.Acks)
	assert.True(t, explicit.ReturnImmediately)

	absent := parse(`{"returnImmediately":true}`)
	assert.False(t, absent.AckOnly, "an absent maxEvents takes the default")
	assert.Zero(t, absent.MaxEvents)

	null := parse(`{"maxEvents":null}`)
	assert.False(t, null.AckOnly, "a null maxEvents is treated as absent")

	five := parse(`{"maxEvents":5}`)
	assert.False(t, five.AckOnly)
	assert.Equal(t, int32(5), five.MaxEvents)
}

// The Go poll client puts the explicit 0 on the wire, and the transmitter's
// parser reads it back as acknowledgement-only.
func TestPollRaw_AckOnlyRoundTrip(t *testing.T) {
	var raw []byte
	var parsed *PollRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error
		raw, err = io.ReadAll(r.Body)
		require.NoError(t, err)
		r.Body = io.NopCloser(bytes.NewReader(raw))
		parsed, err = ParsePollRequest(r)
		require.NoError(t, err)
		WritePollResponse(w, PollResponse{})
	}))
	defer server.Close()

	_, status, err := PollRaw(context.Background(), PollRequest{
		AckOnly: true, ReturnImmediately: true, Acks: []string{"prev-1"},
	}, ReceiverConfig{AllowPlaintext: true, EndpointURL: server.URL})
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, status)

	var wire map[string]any
	require.NoError(t, json.Unmarshal(raw, &wire))
	require.Contains(t, wire, "maxEvents", "the ack-only request must put maxEvents on the wire")
	assert.EqualValues(t, 0, wire["maxEvents"])
	require.NotNil(t, parsed)
	assert.True(t, parsed.AckOnly)
	assert.Equal(t, []string{"prev-1"}, parsed.Acks)
}
