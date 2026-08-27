package goSetPoll

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// Golden-JSON conformance tests for the RFC 8936 poll wire format (issue #273).
//
// These files pin the EXACT bytes json.Marshal produces for a poll request and
// a poll response. RFC 8936 §2.1/§2.2 fix the member names, and receivers in
// the wild key off exactly which members are present; a struct-tag change, a Go
// release, or a future encoding/json v2 migration must not move a byte here
// without someone deciding it should.
//
// Each type gets three fixtures — zero-value, fully populated, and a realistic
// mixed case whose bool/numeric fields sit at their zero values, which is the
// case an `omitempty` -> `omitzero` retag would move if the two ever disagreed.
//
// Regenerate with `UPDATE_GOLDEN=1 go test ./pkg/goSetPoll/...` and then READ
// the diff. An unexplained diff is a wire-format change, not a test to bless.

// assertPollGolden compares got against the recorded wire bytes for name.
//
// The file on disk holds the marshalled bytes plus one trailing newline, so the
// goldens stay ordinary newline-terminated text while the comparison remains
// byte-for-byte against what actually goes on the wire.
func assertPollGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name+".golden.json")

	if os.Getenv("UPDATE_GOLDEN") != "" {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatalf("creating testdata: %v", err)
		}
		if err := os.WriteFile(path, append(bytes.Clone(got), '\n'), 0o644); err != nil {
			t.Fatalf("writing golden %s: %v", path, err)
		}
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading golden %s (regenerate with UPDATE_GOLDEN=1): %v", path, err)
	}
	want := bytes.TrimSuffix(raw, []byte("\n"))
	if !bytes.Equal(want, got) {
		t.Errorf("wire bytes changed for %s\n want: %s\n  got: %s", name, want, got)
	}
}

// TestGoldenPollJSON pins the RFC 8936 poll request/response wire bytes.
func TestGoldenPollJSON(t *testing.T) {
	cases := []struct {
		name  string
		value any
	}{
		{"poll_request_zero", PollRequest{}},
		{"poll_request_populated", PollRequest{
			MaxEvents:         25,
			ReturnImmediately: true,
			Acks:              []string{"jti-1", "jti-2"},
			SetErrs: map[string]SetErrType{
				"jti-3": {Error: "invalid_key", Description: "unknown kid"},
			},
			TimeoutSecs: 30,
		}},
		// Every bool/numeric field deliberately left at its zero value: this is
		// the fixture that proves an omitempty -> omitzero retag is
		// byte-identical.
		{"poll_request_mixed", PollRequest{Acks: []string{"jti-1"}}},

		{"poll_response_zero", PollResponse{}},
		{"poll_response_populated", PollResponse{
			Sets:          map[string]string{"jti-1": "eyJhbGciOiJSUzI1NiJ9.e30.sig"},
			MoreAvailable: true,
		}},
		{"poll_response_mixed", PollResponse{Sets: map[string]string{}}},

		{"set_err_type_zero", SetErrType{}},
		{"set_err_type_populated", SetErrType{Error: "invalid_key", Description: "unknown kid"}},
		{"set_err_type_mixed", SetErrType{Error: "invalid_key"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := json.Marshal(tc.value)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			assertPollGolden(t, tc.name, got)
		})
	}
}

// TestPollWireIsCompact pins the bytes the two HTTP paths actually put on the
// wire, not just what json.Marshal produces for the structs.
//
// Both sides used to pretty-print with json.MarshalIndent. That ran on every
// poll return and every poll request — the hot path of RFC 8936 delivery — to
// produce whitespace no machine reads. This test fails if the indentation ever
// comes back, and it fails if the encoder starts appending anything (a trailing
// newline, say) that the golden does not carry.
func TestPollWireIsCompact(t *testing.T) {
	populated := PollResponse{
		Sets:          map[string]string{"jti-1": "eyJhbGciOiJSUzI1NiJ9.e30.sig"},
		MoreAvailable: true,
	}

	t.Run("transmitter response body", func(t *testing.T) {
		w := httptest.NewRecorder()
		WritePollResponse(w, populated)
		if got := w.Code; got != http.StatusOK {
			t.Fatalf("status = %d, want %d", got, http.StatusOK)
		}
		assertPollGolden(t, "poll_response_populated", w.Body.Bytes())
	})

	t.Run("receiver request body", func(t *testing.T) {
		var sent []byte
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Errorf("reading request body: %v", err)
			}
			sent = body
			WritePollResponse(w, PollResponse{})
		}))
		defer server.Close()

		request := PollRequest{
			MaxEvents:         25,
			ReturnImmediately: true,
			Acks:              []string{"jti-1", "jti-2"},
			SetErrs: map[string]SetErrType{
				"jti-3": {Error: "invalid_key", Description: "unknown kid"},
			},
			TimeoutSecs: 30,
		}
		if _, _, err := PollRaw(context.Background(), request, ReceiverConfig{EndpointURL: server.URL}); err != nil {
			t.Fatalf("PollRaw: %v", err)
		}
		assertPollGolden(t, "poll_request_populated", sent)
	})
}
