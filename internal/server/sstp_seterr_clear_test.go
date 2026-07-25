package server

import (
	"testing"

	"github.com/i2-open/i2goSignals/pkg/goSetSstp"
	"github.com/stretchr/testify/assert"
)

// A SET the peer rejects with a per-JTI setErr must clear from the outbound
// buffer exactly like an ack. Outbound bookkeeping is literal-ack, so without
// this a rejected SET is claimed, signed, POSTed, rejected, released and
// re-claimed on every cycle forever (code-review finding on spec #247 #254).
// Follows the RFC8936 poll transmitter, which acks setErr'd JTIs on the same
// path as params.Acks and does not discriminate by error code.
func TestClearedOutbound_SetErrsClearAlongsideAcks(t *testing.T) {
	acked := []string{"jti-accepted"}
	setErrs := map[string]goSetSstp.SetErr{
		"jti-rejected": {Err: goSetSstp.ErrCodeInvalidRequest, Description: "payload not conformant"},
	}

	cleared := clearedOutbound("pair-1", acked, setErrs)

	assert.ElementsMatch(t, []string{"jti-accepted", "jti-rejected"}, cleared,
		"a setErr'd JTI must clear alongside the acked ones")
}

// No setErrs must be the identity, so the pre-#247 ack path is untouched.
func TestClearedOutbound_NoSetErrsIsIdentity(t *testing.T) {
	acked := []string{"a", "b"}

	assert.Equal(t, acked, clearedOutbound("pair-1", acked, nil))
	assert.Equal(t, acked, clearedOutbound("pair-1", acked, map[string]goSetSstp.SetErr{}))
}

// A peer that both acks and setErrs one JTI is malformed; the JTI must appear
// once so the ack count stays an accurate "did we dispose of everything we sent".
func TestClearedOutbound_DeduplicatesAckAndSetErr(t *testing.T) {
	cleared := clearedOutbound("pair-1", []string{"jti-dup"}, map[string]goSetSstp.SetErr{
		"jti-dup": {Err: goSetSstp.ErrCodeInvalidRequest},
	})

	assert.Equal(t, []string{"jti-dup"}, cleared, "a duplicated JTI must clear exactly once")
}

// Every setErr clears regardless of error code — the poll precedent. The
// transient signature case is absorbed upstream by goSetPush's rotate-and-retry
// for jws_signature_failed (ADR 0028), not discriminated here.
func TestClearedOutbound_ClearsRegardlessOfErrorCode(t *testing.T) {
	setErrs := map[string]goSetSstp.SetErr{
		"jti-invalid": {Err: goSetSstp.ErrCodeInvalidRequest},
		"jti-sig":     {Err: goSetSstp.ProblemSignatureInvalid},
		"jti-kid":     {Err: goSetSstp.ProblemUnknownKID},
		"jti-parse":   {Err: goSetSstp.ErrSetParse},
	}

	cleared := clearedOutbound("pair-1", nil, setErrs)

	assert.ElementsMatch(t,
		[]string{"jti-invalid", "jti-sig", "jti-kid", "jti-parse"}, cleared,
		"no error code is exempt from clearing")
}
