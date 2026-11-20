package goSetSstp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestErrCode_VerbatimFromSpec asserts every §2.3 Table 1 keyword is present with its exact
// on-wire spelling. If the spec table changes, this test is the canary.
func TestErrCode_VerbatimFromSpec(t *testing.T) {
	want := map[ErrCode]string{
		ErrJson:        "json",
		ErrJwtParse:    "jwtParse",
		ErrJwtHdr:      "jwtHdr",
		ErrJwtCrypto:   "jwtCrypto",
		ErrJws:         "jws",
		ErrJwe:         "jwe",
		ErrJwtAud:      "jwtAud",
		ErrJwtIss:      "jwtIss",
		ErrSetType:     "setType",
		ErrSetParse:    "setParse",
		ErrSetData:     "setData",
		ErrDirectional: "directional",
	}
	// The map is keyed by the constant's value, so a typo collapsing two constants would
	// shrink the map and fail this length check.
	assert.Len(t, want, 12, "SSTP §2.3 Table 1 defines exactly 12 SET error codes")
	for code, spelling := range want {
		assert.Equal(t, spelling, string(code))
	}
}
