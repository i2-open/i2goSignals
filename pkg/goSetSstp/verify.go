package goSetSstp

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/MicahParks/keyfunc/v2"
	"github.com/golang-jwt/jwt/v5"

	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/goSetValidate"
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

	// Validators optionally engages event-payload validation for this SSTP
	// pair's INBOUND leg (spec #247). When nil — the default, and the value
	// every pre-#247 caller supplies — no validation runs and
	// VerifiedSET.Validation is left zero, so behavior is byte-for-byte what
	// it was before the field existed. When set, dispositions are computed
	// and reported on VerifiedSET.Validation; this package NEVER rejects a
	// SET because of one and never maps one to an SSTP §2.3 setErr.
	// event_validation mode policy (NONE/WARN/ENFORCE/STRICT), the wire
	// mapping, and the metrics belong to the caller — the acceptor
	// (internal/server/api_sstp.go) and the dialer's inbound half
	// (internal/server/sstp_dialer.go) on the community server.
	//
	// The field is additive by construction: pkg/goSetSstp has live
	// out-of-tree consumers (enterprise, admin) that construct VerifyConfig
	// as a literal, and a nil-safe zero value means they recompile unchanged.
	Validators *goSetValidate.ValidatorSet
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

	// Validation reports the event-payload dispositions computed by
	// VerifyConfig.Validators, so the caller that owns event_validation mode
	// policy can act on them and count them. It is the ZERO SetResult
	// (Disposition == goSetValidate.Valid, no Results) when no validator set
	// was configured — including on the VerifySETX5C control-stream path,
	// which carries no validator hook.
	Validation goSetValidate.SetResult
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
	// Event-payload validation (spec #247). Runs only once the SET is fully
	// trusted — alg, iss, aud and signature are all settled above — so a trust
	// failure can never be reported as a payload defect. A nil Validators
	// leaves Validation zero, and a non-Valid disposition is never turned into
	// an error here: mapping a disposition onto the pair's event_validation
	// mode and onto a per-JTI setErr is the caller's job.
	return VerifiedSET{
		Issuer:     verified.Issuer,
		JTI:        verified.ID,
		Claims:     claims,
		Token:      verified,
		Raw:        token,
		Validation: config.Validators.Validate(verified),
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
