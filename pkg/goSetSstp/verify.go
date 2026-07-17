package goSetSstp

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/MicahParks/keyfunc/v2"
	"github.com/golang-jwt/jwt/v5"

	"github.com/i2-open/i2goSignals/pkg/goSet"
)

// Verification sentinels — every verify failure (VerifySET and VerifySETX5C
// alike) wraps EXACTLY ONE of these, errors.Is-compatible. Promoted from
// enterprise internal/controlset (verify.go + verify_x5c.go) into the pkg
// so consumers across community, enterprise, and admin share one trust
// vocabulary. The sentinel identities are load-bearing: alias-hosting
// consumer packages (`var ErrBadSignature = goSetSstp.ErrBadSignature`)
// preserve errors.Is equivalence.
//
// The `Cert` in ErrIssuerCertMismatch reflects its x5c origin: it is the
// "issuer identity does not match the trust root" sentinel and is used
// BOTH for the x5c-path leaf-URI-SAN-URN mismatch AND for the JWKS-path
// ExpectedIssuer mismatch. The two failure modes are the same class from
// a trust-decision standpoint — the SET's declared iss is not the identity
// this trust configuration is prepared to accept.
var (
	// ErrBadSignature: the JWS is malformed, uses a rejected algorithm,
	// or its signature does not verify under the key selected by the
	// trust config (JWKS entry or x5c-chained leaf).
	ErrBadSignature = errors.New("sstp-bad-signature")
	// ErrUnknownKey: the signature's kid is absent from the configured
	// JWKS (or, on the x5c path, the leaf chain does not validate to any
	// deployment CA root, or the leaf is outside its validity window).
	ErrUnknownKey = errors.New("sstp-unknown-signing-key")
	// ErrWrongAudience: the token's aud is not one of the accepted
	// audiences (or ExpectedAudiences is empty on the x5c path, which is
	// treated as a misconfiguration that would otherwise accept any aud).
	ErrWrongAudience = errors.New("sstp-wrong-audience")
	// ErrIssuerCertMismatch: the SET's iss does not match the trust
	// root's declared issuer identity. On the x5c path this is the
	// leaf URI-SAN URN != iss binding (ADR-0064 D1). On the JWKS path
	// this is the caller-supplied ExpectedIssuer mismatch — the same
	// class of failure ("iss is not what this trust root expects").
	ErrIssuerCertMismatch = errors.New("sstp-issuer-mismatch")
)

// defaultVerifyAlgs is the AllowedAlgs default when VerifyConfig.AllowedAlgs
// is empty: RS256 (community business SETs), ES256, EdDSA. Enterprise's
// control-channel verifier restricted to ES256 + EdDSA; the pkg widens to
// include RS256 because business SETs are RS256-signed (goSet.CreateSet +
// RSA JWKS is the community norm).
var defaultVerifyAlgs = []string{"RS256", "ES256", "EdDSA"}

// VerifyConfig configures a JWKS-based SET verification. It is a flat
// value type so callers construct one per stream, per call, from that
// stream's resolved trust state — no per-stream builder or long-lived
// verifier object.
type VerifyConfig struct {
	// JWKS is the keyfunc-backed JWKS the token's signature is verified
	// against. When nil, verification is impossible: a call with
	// RequireSignature=true (or with any signature-bearing token, i.e.
	// always under ADR-0066) returns ErrBadSignature.
	JWKS *keyfunc.JWKS

	// ExpectedIssuer, when non-empty, is compared exactly to the token's
	// "iss" claim; mismatch ⇒ ErrIssuerCertMismatch. Empty ⇒ iss is not
	// gated (the consumer relies on JWKS routing alone).
	ExpectedIssuer string

	// ExpectedAudiences, when non-empty, is the accepted-aud set; the
	// token's "aud" must contain at least one match. Empty ⇒ aud is not
	// gated.
	ExpectedAudiences []string

	// AllowedAlgs, when non-empty, restricts the JWS "alg" header to this
	// closed set (values are the JWA alg names — "RS256", "ES256",
	// "EdDSA", …). Empty ⇒ defaultVerifyAlgs (RS256 + ES256 + EdDSA).
	// A token whose alg is outside the allow-list is rejected as
	// ErrBadSignature — the alg check is part of the signature trust
	// decision, not a separate class.
	AllowedAlgs []string

	// RequireSignature forces the signature-verification path even when
	// no JWKS is supplied: nil JWKS ⇒ ErrBadSignature. Under ADR-0066
	// this should generally be true for every trusted stream; the flag
	// is preserved so the pkg can serve future non-trust-path callers
	// without changing shape.
	RequireSignature bool
}

// VerifiedSET is the successful VerifySET / VerifySETX5C return. It carries
// the parsed SET (so downstream router.HandleEvent gets it without a second
// parse), the compact raw string (for ingest/audit), the pre-extracted
// iss/jti (the two claims every consumer inspects), and a generic Claims
// map for consumers that need extra claims without re-parsing.
type VerifiedSET struct {
	Issuer string
	JTI    string
	Claims map[string]any
	Token  *goSet.SecurityEventToken
	Raw    string
}

// VerifySET verifies a compact SET token against the JWKS-backed trust
// config. Success returns VerifiedSET; every failure wraps EXACTLY ONE of
// ErrBadSignature / ErrUnknownKey / ErrWrongAudience / ErrIssuerCertMismatch
// (errors.Is-compatible), so consumers can classify uniformly regardless
// of which verify primitive they called.
//
// Ordering: alg allow-list → iss pre-check (Peek) → aud pre-check (Peek) →
// signature verification. The pre-checks let consumers distinguish
// wrong-issuer / wrong-aud from bad-signature without inspecting a
// signature-verified token first. Per ADR-0066 §D3 the peek result is
// consumed only for iss/aud pre-check; the accepted VerifiedSET.Token is
// always the signature-verified token.
func VerifySET(token string, config VerifyConfig) (VerifiedSET, error) {
	if strings.TrimSpace(token) == "" {
		return VerifiedSET{}, fmt.Errorf("%w: empty token", ErrBadSignature)
	}
	// Alg pre-check: parse the JOSE header without verification so a
	// rejected alg fails fast, before any signature work. Also gives the
	// alg-outside-allow-list a distinct short reason.
	parser := jwt.NewParser()
	unverified, _, err := parser.ParseUnverified(token, &goSet.SecurityEventToken{})
	if err != nil {
		return VerifiedSET{}, fmt.Errorf("%w: parse JWS: %v", ErrBadSignature, err)
	}
	if unverified.Header["typ"] != "secevent+jwt" {
		return VerifiedSET{}, fmt.Errorf("%w: typ header != secevent+jwt", ErrBadSignature)
	}
	alg, _ := unverified.Header["alg"].(string)
	allowed := config.AllowedAlgs
	if len(allowed) == 0 {
		allowed = defaultVerifyAlgs
	}
	if alg == "" || !slices.Contains(allowed, alg) {
		return VerifiedSET{}, fmt.Errorf("%w: alg %q not in allowed set %v", ErrBadSignature, alg, allowed)
	}
	unverifiedSet, ok := unverified.Claims.(*goSet.SecurityEventToken)
	if !ok {
		return VerifiedSET{}, fmt.Errorf("%w: unexpected claims type", ErrBadSignature)
	}
	// Issuer pre-check.
	if config.ExpectedIssuer != "" && unverifiedSet.Issuer != config.ExpectedIssuer {
		return VerifiedSET{}, fmt.Errorf("%w: iss %q, want %q", ErrIssuerCertMismatch, unverifiedSet.Issuer, config.ExpectedIssuer)
	}
	// Audience pre-check.
	if len(config.ExpectedAudiences) > 0 {
		if !hasAudience(unverifiedSet.Audience, config.ExpectedAudiences) {
			return VerifiedSET{}, fmt.Errorf("%w: aud %v, want any of %v", ErrWrongAudience, []string(unverifiedSet.Audience), config.ExpectedAudiences)
		}
	}
	// Signature verification. Under ADR-0066 a nil JWKS is never a trust
	// path — the RequireSignature flag is kept for API stability; the
	// effective behavior is: nil JWKS ⇒ ErrBadSignature always.
	if config.JWKS == nil {
		return VerifiedSET{}, fmt.Errorf("%w: no JWKS configured", ErrBadSignature)
	}
	verified, err := goSet.Parse(token, config.JWKS)
	if err != nil {
		// goSet.Parse routes "kid not found" through keyfunc.JWKS.Keyfunc
		// as a jwt.ErrTokenSignatureInvalid-wrapped error; the pkg does
		// not have a stable errors.Is API to distinguish "unknown kid"
		// vs "bad sig" here, so we surface the more common case
		// (bad signature) and let the caller inspect .Error() for a
		// kid mismatch if needed. The alternative — sniffing the error
		// string — is brittle; kid-vs-sig granularity is not required
		// by any consumer today.
		return VerifiedSET{}, fmt.Errorf("%w: %v", ErrBadSignature, err)
	}
	claims := setToClaimsMap(verified)
	return VerifiedSET{
		Issuer: verified.Issuer,
		JTI:    verified.ID,
		Claims: claims,
		Token:  verified,
		Raw:    token,
	}, nil
}

// hasAudience reports whether any expected audience is present in the
// token's aud claim. Empty expected ⇒ false (caller handled that case).
func hasAudience(tokenAud jwt.ClaimStrings, expected []string) bool {
	for _, e := range expected {
		if slices.Contains([]string(tokenAud), e) {
			return true
		}
	}
	return false
}

// setToClaimsMap projects a parsed SET into a generic claims map for
// consumers that need extra claims without re-marshaling. It intentionally
// includes only the RFC7519 registered claims plus SET-specific fields;
// event bodies remain in Token.Events so map access does not double the
// footprint.
func setToClaimsMap(set *goSet.SecurityEventToken) map[string]any {
	if set == nil {
		return nil
	}
	c := map[string]any{}
	if set.Issuer != "" {
		c["iss"] = set.Issuer
	}
	if set.Subject != "" {
		c["sub"] = set.Subject
	}
	if len(set.Audience) > 0 {
		c["aud"] = []string(set.Audience)
	}
	if set.ID != "" {
		c["jti"] = set.ID
	}
	if set.IssuedAt != nil {
		c["iat"] = set.IssuedAt.Time.Unix()
	}
	if set.ExpiresAt != nil {
		c["exp"] = set.ExpiresAt.Time.Unix()
	}
	if set.NotBefore != nil {
		c["nbf"] = set.NotBefore.Time.Unix()
	}
	if set.TimeOfEvent != nil {
		c["toe"] = set.TimeOfEvent.Time.Unix()
	}
	if set.TransactionId != "" {
		c["txn"] = set.TransactionId
	}
	if set.Kid != "" {
		c["kid"] = set.Kid
	}
	return c
}
