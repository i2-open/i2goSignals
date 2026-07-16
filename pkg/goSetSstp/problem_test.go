package goSetSstp_test

import (
	"testing"

	"github.com/i2-open/i2goSignals/pkg/goSetSstp"
)

// TestClassifySetErr_TotalCoverage_URIHalf pins the verdict for every one
// of the eight promoted v1 Problem* URIs. Total coverage: any change to
// the pkg's registry MUST update this table.
func TestClassifySetErr_TotalCoverage_URIHalf(t *testing.T) {
	cases := []struct {
		uri  string
		want goSetSstp.SetErrClass
	}{
		// Retryable — JWKS rotation / kid propagation can heal.
		{goSetSstp.ProblemSignatureInvalid, goSetSstp.ClassSetErrRetryable},
		{goSetSstp.ProblemUnknownKID, goSetSstp.ClassSetErrRetryable},
		// Stream-fatal — stream is dead.
		{goSetSstp.ProblemBindingRevoked, goSetSstp.ClassSetErrStreamFatal},
		// Non-retryable — retry cannot heal.
		{goSetSstp.ProblemUnknownEventType, goSetSstp.ClassSetErrNonRetryable},
		{goSetSstp.ProblemTxnJTIMismatch, goSetSstp.ClassSetErrNonRetryable},
		{goSetSstp.ProblemEventsNotAllowedForPurpose, goSetSstp.ClassSetErrNonRetryable},
		{goSetSstp.ProblemObjectNotFound, goSetSstp.ClassSetErrNonRetryable},
		{goSetSstp.ProblemPreconditionFailed, goSetSstp.ClassSetErrNonRetryable},
	}
	for _, tc := range cases {
		t.Run(tc.uri, func(t *testing.T) {
			got := goSetSstp.ClassifySetErr(goSetSstp.SetErr{Err: tc.uri})
			if got != tc.want {
				t.Errorf("ClassifySetErr(%q) = %v, want %v", tc.uri, got, tc.want)
			}
			// LookupSetErrClass must ALSO recognize this URI as registered.
			class, ok := goSetSstp.LookupSetErrClass(tc.uri)
			if !ok {
				t.Errorf("LookupSetErrClass(%q).ok = false, want true", tc.uri)
			}
			if class != tc.want {
				t.Errorf("LookupSetErrClass(%q).class = %v, want %v", tc.uri, class, tc.want)
			}
		})
	}
}

// TestClassifySetErr_TotalCoverage_KeywordHalf pins the verdict for every
// SSTP §2.3 keyword — all 12 constants from errcode.go. Total coverage.
func TestClassifySetErr_TotalCoverage_KeywordHalf(t *testing.T) {
	cases := []struct {
		keyword string
		want    goSetSstp.SetErrClass
	}{
		// Retryable — key/JWKS rotation can heal (keyword-space
		// equivalent of SignatureInvalid + UnknownKID).
		{goSetSstp.ErrJwtCrypto, goSetSstp.ClassSetErrRetryable},
		// Non-retryable — retransmitting the same bytes cannot become
		// valid; directional = pair misconfig, parks per ADR-0040.
		{goSetSstp.ErrJson, goSetSstp.ClassSetErrNonRetryable},
		{goSetSstp.ErrJwtParse, goSetSstp.ClassSetErrNonRetryable},
		{goSetSstp.ErrJwtHdr, goSetSstp.ClassSetErrNonRetryable},
		{goSetSstp.ErrJws, goSetSstp.ClassSetErrNonRetryable},
		{goSetSstp.ErrJwe, goSetSstp.ClassSetErrNonRetryable},
		{goSetSstp.ErrJwtAud, goSetSstp.ClassSetErrNonRetryable},
		{goSetSstp.ErrJwtIss, goSetSstp.ClassSetErrNonRetryable},
		{goSetSstp.ErrSetType, goSetSstp.ClassSetErrNonRetryable},
		{goSetSstp.ErrSetParse, goSetSstp.ClassSetErrNonRetryable},
		{goSetSstp.ErrSetData, goSetSstp.ClassSetErrNonRetryable},
		{goSetSstp.ErrDirectional, goSetSstp.ClassSetErrNonRetryable},
	}
	for _, tc := range cases {
		t.Run(tc.keyword, func(t *testing.T) {
			got := goSetSstp.ClassifySetErr(goSetSstp.SetErr{Err: tc.keyword})
			if got != tc.want {
				t.Errorf("ClassifySetErr(%q) = %v, want %v", tc.keyword, got, tc.want)
			}
			class, ok := goSetSstp.LookupSetErrClass(tc.keyword)
			if !ok {
				t.Errorf("LookupSetErrClass(%q).ok = false, want true", tc.keyword)
			}
			if class != tc.want {
				t.Errorf("LookupSetErrClass(%q).class = %v, want %v", tc.keyword, class, tc.want)
			}
		})
	}
}

// TestClassifySetErr_UnknownParks pins the default-deny (ADR-0040) verdict:
// unknown err strings ⇒ ClassSetErrNonRetryable (park; never terminal,
// never hot-retried).
func TestClassifySetErr_UnknownParks(t *testing.T) {
	unknowns := []string{
		"",                                    // empty
		"unknown-keyword",                     // bare word (not a URI, not a §2.3 keyword)
		"https://example.com/some/other/uri",  // URI outside our namespace
		"https://schemas.independentid.com/secevent/i2sig/problem/v1/future-slug",
	}
	for _, u := range unknowns {
		t.Run(u, func(t *testing.T) {
			if got := goSetSstp.ClassifySetErr(goSetSstp.SetErr{Err: u}); got != goSetSstp.ClassSetErrNonRetryable {
				t.Errorf("ClassifySetErr(%q) = %v, want NonRetryable (park default)", u, got)
			}
			// LookupSetErrClass must report unregistered so callers can
			// preserve annotation omission on the wire (enterprise
			// NewCommandError parity).
			class, ok := goSetSstp.LookupSetErrClass(u)
			if ok {
				t.Errorf("LookupSetErrClass(%q).ok = true, want false (unregistered)", u)
			}
			if class != goSetSstp.ClassSetErrNonRetryable {
				t.Errorf("LookupSetErrClass(%q).class = %v, want NonRetryable", u, class)
			}
		})
	}
}

// TestSetErrClass_String pins the label vocabulary (log / metric stability).
func TestSetErrClass_String(t *testing.T) {
	cases := []struct {
		c    goSetSstp.SetErrClass
		want string
	}{
		{goSetSstp.ClassSetErrRetryable, "Retryable"},
		{goSetSstp.ClassSetErrNonRetryable, "NonRetryable"},
		{goSetSstp.ClassSetErrStreamFatal, "StreamFatal"},
		{goSetSstp.SetErrClass(0), "Unknown"},
	}
	for _, tc := range cases {
		if got := tc.c.String(); got != tc.want {
			t.Errorf("(%d).String() = %q, want %q", tc.c, got, tc.want)
		}
	}
}
