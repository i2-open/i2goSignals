package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// TestEnsureSigningAlgKey_CreatesTheKeyBeforeStreams: a stream never creates a
// signing key (i2goSignals#314), so --signing-alg ES256 or ML-DSA-65 must ask
// goSignals1 for that algorithm's issuer key first. A 409 is a key that already
// exists from an earlier run; RS256 is the issuer key ensureIssuerKey makes.
func TestEnsureSigningAlgKey_CreatesTheKeyBeforeStreams(t *testing.T) {
	const issuer = "https://bench.example.com"
	cases := []struct {
		alg      string
		status   int
		wantCall bool
		wantErr  bool
	}{
		{"", 0, false, false},
		{"RS256", 0, false, false},
		{"ES256", http.StatusCreated, true, false},
		{"ML-DSA-65", http.StatusCreated, true, false},
		{"ES256", http.StatusConflict, true, false},
		{"ES256", http.StatusForbidden, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.alg+"/"+http.StatusText(tc.status), func(t *testing.T) {
			var calls int
			var gotPath, gotAlg, gotAuth string
			stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				gotPath = r.URL.EscapedPath()
				gotAlg = r.URL.Query().Get("alg")
				gotAuth = r.Header.Get("Authorization")
				w.WriteHeader(tc.status)
			}))
			defer stub.Close()
			gs1 := &node{name: "goSignals1", hostBase: stub.URL, http: stub.Client()}
			o := &options{issuer: issuer, signingAlg: tc.alg, bootstrapToken: "boot"}

			err := ensureSigningAlgKey(gs1, o)

			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if !tc.wantCall {
				if calls != 0 {
					t.Fatalf("RS256 needs no extra key request, got %d", calls)
				}
				return
			}
			if calls != 1 {
				t.Fatalf("want one key request, got %d", calls)
			}
			if gotPath != "/key/"+url.QueryEscape(issuer) {
				t.Errorf("path = %s", gotPath)
			}
			if gotAlg != tc.alg {
				t.Errorf("alg = %q, want %q", gotAlg, tc.alg)
			}
			if gotAuth != "Bearer boot" {
				t.Errorf("Authorization = %q", gotAuth)
			}
		})
	}
}
