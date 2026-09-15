package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCreateKey_AlgFlagSendsAlgQuery proves `create key --alg` rides as ?alg=
// on POST /key/{keyName} (i2goSignals#314), alongside --force for rotate and
// replace, and that no alg is sent when the flag is absent (the server then
// uses RS256).
func TestCreateKey_AlgFlagSendsAlgQuery(t *testing.T) {
	cases := []struct {
		alg, force string
		want       url.Values
	}{
		{"", "", url.Values{}},
		{"ES256", "", url.Values{"alg": {"ES256"}}},
		{"ML-DSA-65", "rotate", url.Values{"alg": {"ML-DSA-65"}, "force": {"rotate"}}},
		{"ES256", "replace", url.Values{"alg": {"ES256"}, "force": {"replace"}}},
	}
	for _, tc := range cases {
		t.Run(tc.alg+"/"+tc.force, func(t *testing.T) {
			var got url.Values
			stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got = r.URL.Query()
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write([]byte("pem"))
			}))
			defer stub.Close()

			cli := newTestCLI(t)
			cli.Data.Servers["node"] = SsfServer{Alias: "node", Host: stub.URL, ClientToken: "tok"}
			cmd := &CreateKeyCmd{
				Alias:    "node",
				IssuerId: "example.com",
				File:     filepath.Join(t.TempDir(), "issuer.pem"),
				Alg:      tc.alg,
				Force:    tc.force,
			}
			cli.Data.Pems = map[string][]byte{"example.com": []byte("rsa-pem")}
			require.NoError(t, cmd.Run(&cli.Globals))
			assert.Equal(t, tc.want, got)

			// generate event signs RS256 with the PEM stored for the issuer, so
			// only an RS256 key replaces it.
			if tc.alg == "" {
				assert.Equal(t, "pem", string(cli.Data.Pems["example.com"]))
			} else {
				assert.Equal(t, "rsa-pem", string(cli.Data.Pems["example.com"]))
			}
		})
	}
}
