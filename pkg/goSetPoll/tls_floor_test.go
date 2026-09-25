package goSetPoll

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mustNotDialRT fails the test if PollRaw ever reaches the wire, proving the
// TLS floor is enforced inside PollRaw ahead of any request, regardless of an
// injected HTTPClient.
type mustNotDialRT struct{ t *testing.T }

func (m mustNotDialRT) RoundTrip(r *http.Request) (*http.Response, error) {
	m.t.Errorf("unexpected HTTP request to %s: TLS floor must reject before dialing", r.URL)
	return nil, errors.New("must not dial")
}

func TestPollRaw_PlaintextRefusedByDefault(t *testing.T) {
	for _, ep := range []string{"http://transmitter.example/poll", "HTTP://transmitter.example/poll"} {
		t.Run(ep, func(t *testing.T) {
			resp, status, err := PollRaw(context.Background(), PollRequest{ReturnImmediately: true}, ReceiverConfig{
				EndpointURL: ep,
				HTTPClient:  &http.Client{Transport: mustNotDialRT{t}},
			})
			require.Error(t, err)
			assert.True(t, errors.Is(err, ErrPlaintextNotAllowed), "want ErrPlaintextNotAllowed, got %v", err)
			assert.Contains(t, err.Error(), ep)
			assert.Nil(t, resp)
			assert.Equal(t, 0, status)
		})
	}
}

// Poll goes through PollRaw, so the floor covers the validating entry point
// too.
func TestPoll_PlaintextRefusedByDefault(t *testing.T) {
	_, _, err := Poll(context.Background(), PollRequest{ReturnImmediately: true}, ReceiverConfig{
		EndpointURL: "http://transmitter.example/poll",
		HTTPClient:  &http.Client{Transport: mustNotDialRT{t}},
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrPlaintextNotAllowed), "want ErrPlaintextNotAllowed, got %v", err)
}

func TestPollRaw_PlaintextAllowedWhenOptedIn(t *testing.T) {
	hits := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"sets":{}}`))
	}))
	defer server.Close()

	resp, status, err := PollRaw(context.Background(), PollRequest{ReturnImmediately: true}, ReceiverConfig{
		EndpointURL:    server.URL,
		AllowPlaintext: true,
	})
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, status)
	require.NotNil(t, resp)
	assert.Equal(t, 1, hits)
}

func TestPollRaw_HTTPSPassesFloorWithoutOptIn(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"sets":{}}`))
	}))
	defer server.Close()

	_, status, err := PollRaw(context.Background(), PollRequest{ReturnImmediately: true}, ReceiverConfig{
		EndpointURL: server.URL,
		HTTPClient:  server.Client(),
	})
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, status)
}
