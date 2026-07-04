package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestSetKeyStatusGrammar validates that the `set key status` verb is wired into
// the kong grammar and binds its args/flags (community ADR 0028). It parses only
// (no server round trip).
func TestSetKeyStatusGrammar(t *testing.T) {
	cli := &CLI{}
	pd, err := initParser(cli)
	require.NoError(t, err)

	_, err = pd.parser.Parse([]string{
		"set", "key", "status", "srv1", "issuer.example.com",
		"--status", "suspended", "--kid", "issuer.example.com-2",
	})
	require.NoError(t, err)
	require.Equal(t, "srv1", cli.Set.Key.Status.Alias)
	require.Equal(t, "issuer.example.com", cli.Set.Key.Status.KeyName)
	require.Equal(t, "suspended", cli.Set.Key.Status.Status)
	require.Equal(t, "issuer.example.com-2", cli.Set.Key.Status.Kid)
}

// TestSetKeyStatusGrammar_InvalidStatusRejected confirms the enum guard rejects
// an unknown status at parse time.
func TestSetKeyStatusGrammar_InvalidStatusRejected(t *testing.T) {
	cli := &CLI{}
	pd, err := initParser(cli)
	require.NoError(t, err)

	_, err = pd.parser.Parse([]string{
		"set", "key", "status", "srv1", "issuer.example.com", "--status", "frozen",
	})
	require.Error(t, err)
}
