package goSetSstp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// The three verdicts must land in three different buckets. Clearing a retryable
// rejection is permanent event loss (outbound bookkeeping is literal-ack), and
// clearing a stream-fatal one drains the whole queue into a dead stream.
func TestPartitionSetErrs_SplitsByVerdict(t *testing.T) {
	d := PartitionSetErrs(map[string]SetErr{
		"jti-validation": {Err: ErrCodeInvalidRequest, Description: "payload not conformant"},
		"jti-parse":      {Err: ErrSetParse},
		"jti-sig":        {Err: ProblemSignatureInvalid},
		"jti-kid":        {Err: ProblemUnknownKID},
		"jti-crypto":     {Err: ErrJwtCrypto},
		"jti-revoked":    {Err: ProblemBindingRevoked, Description: "stream is revoked"},
	})

	assert.Equal(t, []string{"jti-parse", "jti-validation"}, d.Clear,
		"non-retryable rejections clear — the same bytes can never become valid")
	assert.Equal(t, []string{"jti-crypto", "jti-kid", "jti-sig"}, d.Retry,
		"key/JWKS rejections stay pending so a refresh can heal them")
	assert.Equal(t, []string{"jti-revoked"}, d.Fatal)
	assert.Equal(t, "stream is revoked", d.FatalErr.Description,
		"the fatal setErr is carried so the operator sees the peer's own reason")
}

// An err value from neither half of the registry must default-deny to park
// (ADR-0040): cleared, never hot-retried, never terminal.
func TestPartitionSetErrs_UnknownCodeParks(t *testing.T) {
	d := PartitionSetErrs(map[string]SetErr{
		"jti-future": {Err: "https://example.com/some/future/problem"},
	})

	assert.Equal(t, []string{"jti-future"}, d.Clear)
	assert.Empty(t, d.Retry)
	assert.Empty(t, d.Fatal)
}

func TestPartitionSetErrs_EmptyIsZero(t *testing.T) {
	assert.Equal(t, SetErrDisposition{}, PartitionSetErrs(nil))
	assert.Equal(t, SetErrDisposition{}, PartitionSetErrs(map[string]SetErr{}))
}

// Map iteration is randomized; the buckets must not be. A caller's ack list and
// its chosen fatal reason have to be the same on every run.
func TestPartitionSetErrs_IsOrderStable(t *testing.T) {
	in := map[string]SetErr{
		"jti-c": {Err: ErrSetParse},
		"jti-a": {Err: ErrSetData},
		"jti-b": {Err: ErrJson},
		"jti-z": {Err: ProblemBindingRevoked, Description: "first"},
		"jti-y": {Err: ProblemBindingRevoked, Description: "second"},
	}
	for i := 0; i < 20; i++ {
		d := PartitionSetErrs(in)
		assert.Equal(t, []string{"jti-a", "jti-b", "jti-c"}, d.Clear)
		assert.Equal(t, []string{"jti-y", "jti-z"}, d.Fatal)
		assert.Equal(t, "second", d.FatalErr.Description)
	}
}
