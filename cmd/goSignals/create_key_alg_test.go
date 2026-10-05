package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCreateKey_AlgFlagSendsAlgQuery proves `create key --alg` rides as ?alg=
// on POST /key/{keyName} (i2goSignals#314), alongside --force for rotate and
// replace, and that no alg is sent when the flag is absent (the server then
// uses its I2SIG_KEY_ALG default).
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

			// generate event signs with the key's own type, so the newest
			// created key of any type replaces the stored PEM (spec #114).
			assert.Equal(t, "pem", string(cli.Data.Pems["example.com"]))
		})
	}
}

// TestCreateKey_SavesKidSidecar proves `create key` writes the Key-Id the
// server returns to <file>.kid (kid only, trailing newline) and keeps no kid in
// the CLI config (spec #114 S-KID). A server that sends no Key-Id leaves no
// sidecar, removing a stale one from an earlier key.
func TestCreateKey_SavesKidSidecar(t *testing.T) {
	kid := "kid-es256-1"
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if kid != "" {
			w.Header().Set("Key-Id", kid)
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("pem"))
	}))
	defer stub.Close()

	cli := newTestCLI(t)
	cli.Data.Servers["node"] = SsfServer{Alias: "node", Host: stub.URL, ClientToken: "tok"}
	pemFile := filepath.Join(t.TempDir(), "issuer.pem")
	cmd := &CreateKeyCmd{Alias: "node", IssuerId: "example.com", File: pemFile}
	require.NoError(t, cmd.Run(&cli.Globals))

	got, err := os.ReadFile(pemFile + ".kid")
	require.NoError(t, err)
	assert.Equal(t, "kid-es256-1\n", string(got))
	saved, err := json.Marshal(cli.Data)
	require.NoError(t, err)
	assert.NotContains(t, string(saved), "kid-es256-1", "the CLI config keeps no copy of the kid")

	kid = ""
	require.NoError(t, cmd.Run(&cli.Globals))
	_, err = os.Stat(pemFile + ".kid")
	assert.True(t, os.IsNotExist(err), "no Key-Id leaves no sidecar")
}

// TestNewestActiveKid proves generate event's kid is the issuer's last active
// keyStates[] entry of the loaded key's alg (summaries are oldest-first), and
// that no match (an older server without alg) yields "".
func TestNewestActiveKid(t *testing.T) {
	summaries := []dao.KeySummary{
		{KeyName: "other.example.com", KeyStates: []dao.KeyState{{Kid: "other", Alg: "ES256", Status: "active"}}},
		{KeyName: "example.com", KeyStates: []dao.KeyState{
			{Kid: "example.com", Alg: "RS256", Status: "active"},
			{Kid: "es-old", Alg: "ES256", Status: "active"},
			{Kid: "es-new", Alg: "ES256", Status: "active"},
			{Kid: "es-revoked", Alg: "ES256", Status: "revoked"},
		}},
	}
	assert.Equal(t, "es-new", newestActiveKid(summaries, "example.com", "ES256"))
	assert.Equal(t, "example.com", newestActiveKid(summaries, "example.com", "RS256"))
	assert.Equal(t, "", newestActiveKid(summaries, "example.com", "ML-DSA-65"))

	legacy := []dao.KeySummary{{KeyName: "example.com", KeyStates: []dao.KeyState{{Kid: "example.com", Status: "active"}}}}
	assert.Equal(t, "", newestActiveKid(legacy, "example.com", "RS256"))
}
