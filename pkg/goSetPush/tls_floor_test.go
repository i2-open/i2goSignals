package goSetPush

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mustNotDialRT fails the test if PushSET ever reaches the wire, proving the
// TLS floor is enforced inside PushSET ahead of any request, regardless of an
// injected HTTPClient.
type mustNotDialRT struct{ t *testing.T }

func (m mustNotDialRT) RoundTrip(r *http.Request) (*http.Response, error) {
	m.t.Errorf("unexpected HTTP request to %s: TLS floor must reject before dialing", r.URL)
	return nil, errors.New("must not dial")
}

func TestPushSET_PlaintextRefusedByDefault(t *testing.T) {
	for _, ep := range []string{"http://receiver.example/events", "HTTP://receiver.example/events"} {
		t.Run(ep, func(t *testing.T) {
			res := PushSET(context.Background(), "token", TransmitterConfig{
				EndpointURL: ep,
				HTTPClient:  &http.Client{Transport: mustNotDialRT{t}},
			})
			require.Error(t, res.Err)
			assert.True(t, errors.Is(res.Err, ErrPlaintextNotAllowed), "want ErrPlaintextNotAllowed, got %v", res.Err)
			assert.Contains(t, res.Err.Error(), ep)
			assert.Equal(t, 0, res.StatusCode)
			assert.False(t, res.Accepted)
			assert.Equal(t, ClassTransport, ClassifyResult(res).Class)
		})
	}
}

func TestPushSET_PlaintextAllowedWhenOptedIn(t *testing.T) {
	hits := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	res := PushSET(context.Background(), "token", TransmitterConfig{
		EndpointURL:    server.URL,
		AllowPlaintext: true,
	})
	require.NoError(t, res.Err)
	assert.Equal(t, http.StatusAccepted, res.StatusCode)
	assert.True(t, res.Accepted)
	assert.Equal(t, 1, hits)
}

// TestPushSET_HTTPSPassesFloorWithoutOptIn: https passes the floor with
// AllowPlaintext=false. InsecureSkipVerify is orthogonal — the injected
// server client trusts the test cert, so it is not needed here.
func TestPushSET_HTTPSPassesFloorWithoutOptIn(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	res := PushSET(context.Background(), "token", TransmitterConfig{
		EndpointURL: server.URL,
		HTTPClient:  server.Client(),
	})
	require.NoError(t, res.Err)
	assert.True(t, res.Accepted)
}
