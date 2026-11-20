package goSetSstp_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/i2-open/i2goSignals/pkg/goSetSstp"
)

// mustNotDialRT is an injected transport that fails the test if Exchange
// ever reaches the wire. It proves the TLS floor is enforced inside Exchange,
// ahead of any HTTP request, regardless of an injected HTTPClient.
type mustNotDialRT struct{ t *testing.T }

func (m mustNotDialRT) RoundTrip(r *http.Request) (*http.Response, error) {
	m.t.Errorf("unexpected HTTP request to %s: TLS floor must reject before dialing", r.URL)
	return nil, errors.New("must not dial")
}

// TestExchange_PlaintextRefusedByDefault: an http:// endpoint with
// AllowPlaintext=false is refused with ErrPlaintextNotAllowed, no request is
// made, and the Result classifies as ClassTransport (StatusCode 0 + Err).
func TestExchange_PlaintextRefusedByDefault(t *testing.T) {
	for _, ep := range []string{"http://peer.example/sstp", "HTTP://peer.example/sstp", "ftp://peer.example/x"} {
		t.Run(ep, func(t *testing.T) {
			res := goSetSstp.Exchange(context.Background(), goSetSstp.Message{}, goSetSstp.DialerConfig{
				EndpointURL: ep,
				HTTPClient:  &http.Client{Transport: mustNotDialRT{t}},
			})
			if !errors.Is(res.Err, goSetSstp.ErrPlaintextNotAllowed) {
				t.Fatalf("Err = %v, want ErrPlaintextNotAllowed", res.Err)
			}
			if res.StatusCode != 0 || res.Message != nil {
				t.Errorf("Result = %+v; want StatusCode 0 and nil Message", res)
			}
			if got := goSetSstp.ClassifyResult(res).Class; got != goSetSstp.ClassTransport {
				t.Errorf("ClassifyResult = %v, want ClassTransport", got)
			}
		})
	}
}

// TestExchange_PlaintextAllowedWhenOptedIn: AllowPlaintext=true lets an
// http:// endpoint through to the wire (the per-stream tx_allow_plaintext
// opt-out).
func TestExchange_PlaintextAllowedWhenOptedIn(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	res := goSetSstp.Exchange(context.Background(), goSetSstp.Message{}, goSetSstp.DialerConfig{
		EndpointURL:    srv.URL,
		AllowPlaintext: true,
	})
	if res.Err != nil || res.StatusCode != http.StatusAccepted {
		t.Fatalf("Exchange = %+v; want 202, nil Err", res)
	}
	if hits != 1 {
		t.Errorf("server hits = %d, want 1", hits)
	}
}

// TestExchange_HTTPSPassesFloorWithoutOptIn: an https:// endpoint is dialed
// with AllowPlaintext=false. InsecureSkipVerify stays orthogonal: the
// injected server client trusts the test cert, so no skip-verify is needed.
func TestExchange_HTTPSPassesFloorWithoutOptIn(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	res := goSetSstp.Exchange(context.Background(), goSetSstp.Message{}, goSetSstp.DialerConfig{
		EndpointURL: srv.URL,
		HTTPClient:  srv.Client(),
	})
	if res.Err != nil || res.StatusCode != http.StatusAccepted {
		t.Fatalf("Exchange = %+v; want 202, nil Err", res)
	}
}
