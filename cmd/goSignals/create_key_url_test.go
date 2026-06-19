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

// TestCreateKey_EncodesUrlIssuerId proves `create key` percent-encodes a
// URL-shaped issuer id so the whole value rides in a single /key/{keyName} path
// segment. A path-bearing local issuer (ADR 0023 / GH #188) is stored under its
// full URL; url.JoinPath would leave the slashes literal (and collapse "//"), so
// the /key route would capture only the first segment. The server runs with
// UseEncodedPath() and url.QueryUnescape's the captured var, so url.QueryEscape
// is the matching pair.
func TestCreateKey_EncodesUrlIssuerId(t *testing.T) {
    var gotURI string
    stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        gotURI = r.URL.EscapedPath()
        w.WriteHeader(http.StatusCreated)
        _, _ = w.Write([]byte("-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----\n"))
    }))
    defer stub.Close()

    cli := newTestCLI(t)
    cli.Data.Servers["node"] = SsfServer{Alias: "node", Host: stub.URL, ClientToken: "tok"}

    issuer := stub.URL + "/issuer1" // a path-bearing full-URL issuer id
    cmd := &CreateKeyCmd{
        Alias:    "node",
        IssuerId: issuer,
        File:     filepath.Join(t.TempDir(), "issuer.pem"),
    }
    require.NoError(t, cmd.Run(&cli.Globals))

    assert.Equal(t, "/key/"+url.QueryEscape(issuer), gotURI,
        "create key must percent-encode a URL-shaped issuer id into one path segment")
}

// TestCreateKey_SlashFreeIssuerUnchanged proves the common case (a slash-free
// issuer id such as example.com) is unaffected by the encoding.
func TestCreateKey_SlashFreeIssuerUnchanged(t *testing.T) {
    var gotURI string
    stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        gotURI = r.URL.EscapedPath()
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
    }
    require.NoError(t, cmd.Run(&cli.Globals))

    assert.Equal(t, "/key/example.com", gotURI,
        "a slash-free issuer id must be unchanged by the encoding")
}
