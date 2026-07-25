package server

import (
	"testing"

	"github.com/i2-open/i2goSignals/pkg/goSetSstp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A SET the peer rejects deterministically must clear from the outbound buffer
// exactly like an ack. Outbound bookkeeping is literal-ack, so without this a
// rejected SET is claimed, signed, POSTed, rejected, released and re-claimed on
// every cycle forever (code-review finding on spec #247 #254).
func TestClearedOutbound_SetErrsClearAlongsideAcks(t *testing.T) {
	acked := []string{"jti-accepted"}
	setErrs := map[string]goSetSstp.SetErr{
		"jti-rejected": {Err: goSetSstp.ErrCodeInvalidRequest, Description: "payload not conformant"},
	}

	cleared, fatal := clearedOutbound("pair-1", acked, setErrs)

	assert.ElementsMatch(t, []string{"jti-accepted", "jti-rejected"}, cleared,
		"a deterministically setErr'd JTI must clear alongside the acked ones")
	assert.Nil(t, fatal)
}

// No setErrs must be the identity, so the pre-#247 ack path is untouched.
func TestClearedOutbound_NoSetErrsIsIdentity(t *testing.T) {
	acked := []string{"a", "b"}

	cleared, fatal := clearedOutbound("pair-1", acked, nil)
	assert.Equal(t, acked, cleared)
	assert.Nil(t, fatal)

	cleared, fatal = clearedOutbound("pair-1", acked, map[string]goSetSstp.SetErr{})
	assert.Equal(t, acked, cleared)
	assert.Nil(t, fatal)
}

// A peer that both acks and setErrs one JTI is malformed; the JTI must appear
// once so the ack count stays an accurate "did we dispose of everything we sent".
func TestClearedOutbound_DeduplicatesAckAndSetErr(t *testing.T) {
	cleared, fatal := clearedOutbound("pair-1", []string{"jti-dup"}, map[string]goSetSstp.SetErr{
		"jti-dup": {Err: goSetSstp.ErrCodeInvalidRequest},
	})

	assert.Equal(t, []string{"jti-dup"}, cleared, "a duplicated JTI must clear exactly once")
	assert.Nil(t, fatal)
}

// Clearing is permanent, so a RETRYABLE rejection must not clear. Our own
// acceptor answers a stale JWKS or a mid-rotation signing key with
// ProblemSignatureInvalid / ProblemUnknownKID (classifyVerifyErrorForAcceptor);
// clearing those deleted real events, silently, with the pair still enabled.
// Leaving them pending re-sends the very same SET once the key material settles.
func TestClearedOutbound_RetryableCodesAreHeldNotCleared(t *testing.T) {
	setErrs := map[string]goSetSstp.SetErr{
		"jti-sig":    {Err: goSetSstp.ProblemSignatureInvalid},
		"jti-kid":    {Err: goSetSstp.ProblemUnknownKID},
		"jti-crypto": {Err: goSetSstp.ErrJwtCrypto},
		"jti-parse":  {Err: goSetSstp.ErrSetParse},
	}

	cleared, fatal := clearedOutbound("pair-1", nil, setErrs)

	assert.Equal(t, []string{"jti-parse"}, cleared,
		"only the deterministic rejection clears; the key/JWKS ones stay pending")
	assert.Nil(t, fatal)
}

// binding-revoked says the stream itself is dead: every subsequent send is
// rejected the same way. The JTI stays pending (a resume replays it) and the
// caller is handed the setErr so it can stop the direction with the peer's own
// reason instead of draining the queue into a dead stream.
func TestClearedOutbound_StreamFatalIsReportedNotCleared(t *testing.T) {
	setErrs := map[string]goSetSstp.SetErr{
		"jti-revoked":  {Err: goSetSstp.ProblemBindingRevoked, Description: "stream is revoked"},
		"jti-rejected": {Err: goSetSstp.ErrCodeInvalidRequest},
	}

	cleared, fatal := clearedOutbound("pair-1", []string{"jti-accepted"}, setErrs)

	assert.ElementsMatch(t, []string{"jti-accepted", "jti-rejected"}, cleared,
		"a stream-fatal JTI must not be cleared")
	require.NotNil(t, fatal, "the caller must learn the stream is dead")
	assert.Equal(t, goSetSstp.ProblemBindingRevoked, fatal.Err)
	assert.Equal(t, "stream is revoked", fatal.Description)
}
