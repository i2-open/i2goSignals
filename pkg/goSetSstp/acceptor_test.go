package goSetSstp_test

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/i2-open/i2goSignals/pkg/goSetSstp"
)

// --- CheckExchangeRequest --------------------------------------------------

// TestCheckExchangeRequest_MethodNotAllowed pins the 405 path (no body read).
func TestCheckExchangeRequest_MethodNotAllowed(t *testing.T) {
	body := strings.NewReader(`{"ack":["jti-should-never-be-read"]}`)
	r := httptest.NewRequest(http.MethodGet, "/sstp/x", body)
	r.Header.Set("Content-Type", goSetSstp.ContentType)

	rerr := goSetSstp.CheckExchangeRequest(r)
	if rerr == nil || rerr.Status != http.StatusMethodNotAllowed {
		t.Fatalf("CheckExchangeRequest = %v; want 405", rerr)
	}
	// Body must be untouched by the pre-auth gate — the whole
	// point of the split from Parse is "no pre-auth body read".
	if body.Len() != len(`{"ack":["jti-should-never-be-read"]}`) {
		t.Errorf("body length = %d, want unchanged (CheckExchangeRequest read the body)", body.Len())
	}
}

// TestCheckExchangeRequest_UnsupportedMediaType pins the 415 path — both
// missing Content-Type and wrong base type.
func TestCheckExchangeRequest_UnsupportedMediaType(t *testing.T) {
	cases := []struct {
		name        string
		contentType string
	}{
		{"missing", ""},
		{"wrong base type", "application/json"},
		{"almost-right", "application/sstp"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/sstp/x", strings.NewReader(""))
			if tc.contentType != "" {
				r.Header.Set("Content-Type", tc.contentType)
			}
			rerr := goSetSstp.CheckExchangeRequest(r)
			if rerr == nil || rerr.Status != http.StatusUnsupportedMediaType {
				t.Fatalf("CheckExchangeRequest = %v; want 415", rerr)
			}
		})
	}
}

// TestCheckExchangeRequest_MediaTypeParameterTolerance pins the pinned
// "Content-Type parameters are ignored" behavior — admin's TestHTTPShape
// depends on this. `application/sstp+json; charset=utf-8` MUST pass.
func TestCheckExchangeRequest_MediaTypeParameterTolerance(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/sstp/x", strings.NewReader(""))
	r.Header.Set("Content-Type", goSetSstp.ContentType+"; charset=utf-8")
	if rerr := goSetSstp.CheckExchangeRequest(r); rerr != nil {
		t.Errorf("CheckExchangeRequest with charset param = %v; want nil", rerr)
	}
}

// TestCheckExchangeRequest_Ok pins the happy path — no ReqError returned.
func TestCheckExchangeRequest_Ok(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/sstp/x", strings.NewReader(""))
	r.Header.Set("Content-Type", goSetSstp.ContentType)
	if rerr := goSetSstp.CheckExchangeRequest(r); rerr != nil {
		t.Errorf("CheckExchangeRequest = %v; want nil", rerr)
	}
}

// --- ParseExchangeRequest --------------------------------------------------

// TestParseExchangeRequest_UnlimitedByDefault pins ParseOptions{MaxBodyBytes:0}
// ⇒ NO default cap: a 10 MiB body is accepted (community stays uncapped).
func TestParseExchangeRequest_UnlimitedByDefault(t *testing.T) {
	// 10 MiB of raw-SET bytes under one jti so the body is huge but valid.
	huge := strings.Repeat("x", 10<<20)
	msg := goSetSstp.Message{Sets: map[string]string{"jti-1": huge}}
	body, _ := json.Marshal(msg)
	r := httptest.NewRequest(http.MethodPost, "/sstp/x", strings.NewReader(string(body)))
	r.Header.Set("Content-Type", goSetSstp.ContentType)

	got, rerr := goSetSstp.ParseExchangeRequest(r, goSetSstp.ParseOptions{})
	if rerr != nil {
		t.Fatalf("ParseExchangeRequest with 10MiB body = %v; want accepted (uncapped)", rerr)
	}
	if got == nil || len(got.Sets["jti-1"]) != len(huge) {
		t.Errorf("parsed Sets truncated: got len=%d, want %d", len(got.Sets["jti-1"]), len(huge))
	}
}

// TestParseExchangeRequest_413WhenCapExceeded pins the 413 path — only
// active when a cap is configured (admin will hardcode 4 MiB).
func TestParseExchangeRequest_413WhenCapExceeded(t *testing.T) {
	body := strings.Repeat("x", 2048)
	r := httptest.NewRequest(http.MethodPost, "/sstp/x", strings.NewReader(body))
	r.Header.Set("Content-Type", goSetSstp.ContentType)
	_, rerr := goSetSstp.ParseExchangeRequest(r, goSetSstp.ParseOptions{MaxBodyBytes: 1024})
	if rerr == nil || rerr.Status != http.StatusRequestEntityTooLarge {
		t.Fatalf("ParseExchangeRequest cap=1024 body=2048 = %v; want 413", rerr)
	}
	if rerr.Err != goSetSstp.ErrCodePayloadTooLarge {
		t.Errorf("Err code = %q, want %q", rerr.Err, goSetSstp.ErrCodePayloadTooLarge)
	}
}

// TestParseExchangeRequest_EmptyBodyIsZeroMessage pins the "empty body is
// valid" contract — a zero-value Message with §2.1-default semantics.
func TestParseExchangeRequest_EmptyBodyIsZeroMessage(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/sstp/x", strings.NewReader(""))
	r.Header.Set("Content-Type", goSetSstp.ContentType)
	msg, rerr := goSetSstp.ParseExchangeRequest(r, goSetSstp.ParseOptions{})
	if rerr != nil {
		t.Fatalf("ParseExchangeRequest empty = %v; want nil", rerr)
	}
	if msg == nil || !msg.ReturnEventsResolved() || msg.ReturnImmediatelyResolved() {
		t.Errorf("empty ⇒ Message = %+v; want ReturnEvents=true(default), ReturnImmediately=false(default)", msg)
	}
}

// TestParseExchangeRequest_InvalidJSON400 pins the 400 path — malformed
// application/sstp+json body.
func TestParseExchangeRequest_InvalidJSON400(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/sstp/x", strings.NewReader("not-json{"))
	r.Header.Set("Content-Type", goSetSstp.ContentType)
	_, rerr := goSetSstp.ParseExchangeRequest(r, goSetSstp.ParseOptions{})
	if rerr == nil || rerr.Status != http.StatusBadRequest {
		t.Fatalf("ParseExchangeRequest invalid = %v; want 400", rerr)
	}
}

// TestReqError_ImplementsError verifies *ReqError satisfies the error
// interface so callers can propagate it via errors.As if desired.
func TestReqError_ImplementsError(t *testing.T) {
	rerr := &goSetSstp.ReqError{Status: 415, Err: goSetSstp.ErrCodeUnsupportedMediaType, Description: "bad ct"}
	var e error = rerr
	if e.Error() == "" {
		t.Errorf("ReqError.Error() empty")
	}
	// A nil *ReqError must not panic; the acceptor helpers can return nil
	// which callers may propagate.
	var nilErr *goSetSstp.ReqError
	if got := nilErr.Error(); got != "" {
		t.Errorf("nil ReqError.Error() = %q, want empty", got)
	}
	// Sanity: errors.As
	var target *goSetSstp.ReqError
	if !errors.As(e, &target) {
		t.Errorf("errors.As failed on *ReqError")
	}
}

// --- WriteExchangeResponse -------------------------------------------------

// TestWriteExchangeResponse_HappyPath pins the success writer: 200,
// application/sstp+json, JSON body matching the input Message.
func TestWriteExchangeResponse_HappyPath(t *testing.T) {
	rec := httptest.NewRecorder()
	msg := goSetSstp.Message{Ack: []string{"jti-1"}}
	if err := goSetSstp.WriteExchangeResponse(rec, msg); err != nil {
		t.Fatalf("WriteExchangeResponse: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("Code = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != goSetSstp.ContentType {
		t.Errorf("Content-Type = %q, want %q", got, goSetSstp.ContentType)
	}
	var back goSetSstp.Message
	if err := json.Unmarshal(rec.Body.Bytes(), &back); err != nil {
		t.Fatalf("body: %v", err)
	}
	if len(back.Ack) != 1 || back.Ack[0] != "jti-1" {
		t.Errorf("round-trip Ack = %v", back.Ack)
	}
}

// TestWriteExchangeResponse_WriteError pins the error path — a
// ResponseWriter whose Write always fails surfaces a non-nil error so
// callers can log the drop.
func TestWriteExchangeResponse_WriteError(t *testing.T) {
	w := &failingResponseWriter{header: http.Header{}}
	err := goSetSstp.WriteExchangeResponse(w, goSetSstp.Message{Ack: []string{"jti-1"}})
	if err == nil {
		t.Errorf("WriteExchangeResponse on failing writer = nil, want non-nil")
	}
}

type failingResponseWriter struct {
	header http.Header
	status int
}

func (f *failingResponseWriter) Header() http.Header    { return f.header }
func (f *failingResponseWriter) WriteHeader(status int) { f.status = status }
func (f *failingResponseWriter) Write(_ []byte) (int, error) {
	return 0, io.ErrClosedPipe
}
