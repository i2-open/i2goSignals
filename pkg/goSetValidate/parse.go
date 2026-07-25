package goSetValidate

import (
	"github.com/MicahParks/keyfunc/v2"

	"github.com/i2-open/i2goSignals/pkg/goSet"
)

// ParseAndValidate composes signature verification and payload validation in one
// call. It mirrors goSet.Parse's parameter shape, so a caller that already does a
// verified parse can adopt validation by threading one extra argument through.
//
// Verification happens first: on a parse/signature failure the error is returned
// unchanged, with a nil token and a zero SetResult — validation never masks or
// reshapes a trust-path failure. Per ADR-0066 §D3 this composes over the VERIFIED
// parse, never over Peek, so a disposition is only ever computed for a token
// whose signature already checked out.
//
// A nil vs degrades to exactly goSet.Parse(tokenString, issuerPublicJwks) plus a
// zero SetResult: (*ValidatorSet)(nil).Validate reports Valid with no per-URI
// results, which is the zero SetResult.
//
// A validation failure is REPORTED, never returned as an error — this package
// computes dispositions and never rejects. Mode policy (NONE / WARN / ENFORCE /
// STRICT) and wire-error mapping belong to the server wiring.
func ParseAndValidate(tokenString string, issuerPublicJwks *keyfunc.JWKS, vs *ValidatorSet) (*goSet.SecurityEventToken, SetResult, error) {
	set, err := goSet.Parse(tokenString, issuerPublicJwks)
	if err != nil {
		return nil, SetResult{}, err
	}
	return set, vs.Validate(set), nil
}
