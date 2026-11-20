package goSetSstp

import "net/http"

// HTTP-shape constants for the SSTP endpoint (draft-hunt-secevent-sstp-00 §2.1, §2.3).
// The runner and the HTTP route (later slices) key off these so the wire shape lives in
// exactly one place. The path is unversioned and POST-only with strict Content-Type, matching
// the existing /poll/{id} and /events/{id} conventions.
const (
	// PathTemplate is the net/http ServeMux pattern for the SSTP endpoint; {id} is the PairId.
	PathTemplate = "/sstp/{id}"

	// Method is the only HTTP method SSTP uses; anything else is a 405.
	Method = http.MethodPost

	// ContentType is the strict base media type for SSTP message bodies. Servers match on the
	// base type and ignore parameters (e.g. "; charset=utf-8"); a mismatch is a 415.
	ContentType = "application/sstp+json"
)
