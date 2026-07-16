package goSetSstp_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/i2-open/i2goSignals/pkg/goSetSstp"
)

// TestExchange_200SuccessWithBody verifies a happy-path cycle: the request
// carries the marshaled Message body, the peer echoes a Message back, and
// the returned Result is StatusCode=200 + parsed Message + no error. This
// pins the OK-with-detail path ClassifyResult routes to ClassOK.
func TestExchange_200SuccessWithBody(t *testing.T) {
	respBody := goSetSstp.Message{Ack: []string{"jti-1"}}
	var reqBody goSetSstp.Message
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != goSetSstp.Method {
			t.Errorf("method = %q, want %q", r.Method, goSetSstp.Method)
		}
		if got := r.Header.Get("Content-Type"); got != goSetSstp.ContentType {
			t.Errorf("Content-Type = %q, want %q", got, goSetSstp.ContentType)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-tok" {
			t.Errorf("Authorization = %q, want %q", got, "Bearer test-tok")
		}
		if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
			t.Fatalf("decode: %v", err)
		}
		w.Header().Set("Content-Type", goSetSstp.ContentType)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(respBody)
	}))
	defer srv.Close()

	msg := goSetSstp.Message{Sets: map[string]string{"jti-1": "raw-set"}}
	res := goSetSstp.Exchange(context.Background(), msg, goSetSstp.DialerConfig{
		EndpointURL:   srv.URL,
		Authorization: "Bearer test-tok",
	})
	if res.StatusCode != http.StatusOK || res.Err != nil {
		t.Fatalf("Exchange = %+v; want StatusCode=200, Err=nil", res)
	}
	if res.Message == nil || len(res.Message.Ack) != 1 || res.Message.Ack[0] != "jti-1" {
		t.Errorf("Message = %+v; want Ack=[jti-1]", res.Message)
	}
	if reqBody.Sets["jti-1"] != "raw-set" {
		t.Errorf("request Sets not carried; got %+v", reqBody.Sets)
	}
	if got := goSetSstp.ClassifyResult(res).Class; got != goSetSstp.ClassOK {
		t.Errorf("ClassifyResult = %v, want ClassOK", got)
	}
}

// TestExchange_200EmptyBody pins the success-without-detail path: 200 with
// an empty body ⇒ StatusCode=200, Message=nil, Err=nil (ClassOK), NOT
// unparseable-200.
func TestExchange_200EmptyBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", goSetSstp.ContentType)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	res := goSetSstp.Exchange(context.Background(), goSetSstp.Message{}, goSetSstp.DialerConfig{EndpointURL: srv.URL})
	if res.StatusCode != http.StatusOK || res.Message != nil || res.Err != nil {
		t.Fatalf("Exchange = %+v; want 200/nil/nil", res)
	}
	if got := goSetSstp.ClassifyResult(res).Class; got != goSetSstp.ClassOK {
		t.Errorf("ClassifyResult = %v, want ClassOK", got)
	}
}

// TestExchange_200UnparseableBody pins that a 200 whose body cannot be
// parsed as JSON is treated as transient (never ClassOK) so callers do
// NOT ack SETs the real peer may not have received.
func TestExchange_200UnparseableBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", goSetSstp.ContentType)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not-valid-json{"))
	}))
	defer srv.Close()

	res := goSetSstp.Exchange(context.Background(), goSetSstp.Message{}, goSetSstp.DialerConfig{EndpointURL: srv.URL})
	if res.StatusCode != http.StatusOK || res.Err == nil || res.Message != nil {
		t.Fatalf("Exchange = %+v; want 200/Err!=nil/Message==nil", res)
	}
	if got := goSetSstp.ClassifyResult(res).Class; got != goSetSstp.ClassTransient {
		t.Errorf("ClassifyResult = %v, want ClassTransient", got)
	}
}

// TestExchange_HTTPStatusPassthrough verifies non-200 statuses reach the
// classifier via Result.StatusCode with no body reading requirements.
func TestExchange_HTTPStatusPassthrough(t *testing.T) {
	cases := []struct {
		name       string
		status     int
		wantClass  goSetSstp.FailureClass
		retryAfter string
	}{
		{"404 request-error", http.StatusNotFound, goSetSstp.ClassRequestError, ""},
		{"401 request-error", http.StatusUnauthorized, goSetSstp.ClassRequestError, ""},
		{"503 transient", http.StatusServiceUnavailable, goSetSstp.ClassTransient, "17"},
		{"500 transient", http.StatusInternalServerError, goSetSstp.ClassTransient, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.retryAfter != "" {
					w.Header().Set("Retry-After", tc.retryAfter)
				}
				w.WriteHeader(tc.status)
			}))
			defer srv.Close()
			res := goSetSstp.Exchange(context.Background(), goSetSstp.Message{}, goSetSstp.DialerConfig{EndpointURL: srv.URL})
			if res.StatusCode != tc.status {
				t.Errorf("StatusCode = %d, want %d", res.StatusCode, tc.status)
			}
			if got := goSetSstp.ClassifyResult(res).Class; got != tc.wantClass {
				t.Errorf("Class = %v, want %v", got, tc.wantClass)
			}
			if tc.retryAfter == "17" && res.RetryAfter != 17*time.Second {
				t.Errorf("RetryAfter = %v, want 17s", res.RetryAfter)
			}
		})
	}
}

// TestExchange_TransportError pins that a connect failure surfaces as
// StatusCode == 0 + Err (ClassTransport), never a 5xx.
func TestExchange_TransportError(t *testing.T) {
	// A URL that will fail immediately: unreachable localhost port.
	res := goSetSstp.Exchange(context.Background(), goSetSstp.Message{}, goSetSstp.DialerConfig{
		EndpointURL: "http://127.0.0.1:1", // port 1 is reserved and won't bind
	})
	if res.StatusCode != 0 || res.Err == nil {
		t.Fatalf("Exchange = %+v; want StatusCode=0, Err!=nil", res)
	}
	if got := goSetSstp.ClassifyResult(res).Class; got != goSetSstp.ClassTransport {
		t.Errorf("Class = %v, want ClassTransport", got)
	}
}

// TestExchange_NoAuthorizationHeader pins that an empty Authorization
// config value results in NO Authorization header sent (business SSTP's
// signing-only + no-bearer path).
func TestExchange_NoAuthorizationHeader(t *testing.T) {
	var seen string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", goSetSstp.ContentType)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	_ = goSetSstp.Exchange(context.Background(), goSetSstp.Message{}, goSetSstp.DialerConfig{EndpointURL: srv.URL})
	if seen != "" {
		t.Errorf("Authorization header = %q, want empty", seen)
	}
}

// TestExchange_ContextCancellation verifies a canceled ctx aborts the
// cycle (no request body ever reaches the server after cancel).
func TestExchange_ContextCancellation(t *testing.T) {
	// Handler that reads the whole body — used as a guard so a canceled
	// ctx that lets the request through would produce a non-zero body
	// read on the server; but with the deadline set BEFORE Do(), the
	// client transport aborts before any bytes leave.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		time.Sleep(50 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res := goSetSstp.Exchange(ctx, goSetSstp.Message{}, goSetSstp.DialerConfig{
		EndpointURL: srv.URL,
		HTTPClient:  srv.Client(),
	})
	if res.Err == nil || !strings.Contains(res.Err.Error(), "context canceled") {
		t.Errorf("Err = %v, want context-canceled error", res.Err)
	}
}
