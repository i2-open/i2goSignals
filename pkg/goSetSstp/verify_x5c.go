package goSetSstp

// X5C-based SET verification, promoted verbatim in semantics from enterprise
// internal/controlset/verify_x5c.go (ADR-0064):
//
//   - the JWS x5c protected-header chain is validated against the caller's
//     deployment CA root pool with the current time as the reference,
//   - the leaf certificate MUST carry exactly one URI SAN and that URI's
//     string form is the SET's authoritative issuer identity (ADR-0064 D1),
//   - the leaf's public key verifies the JWS,
//   - the token's aud must include at least one of ExpectedAudiences (empty
//     ExpectedAudiences ⇒ ErrWrongAudience — accepting-any-aud would be a
//     misconfiguration, promoted-verifier semantics verbatim).
//
// No network calls: the bundle carries the CA root set and every trust
// decision is local. Every failure wraps EXACTLY ONE of ErrBadSignature /
// ErrUnknownKey / ErrWrongAudience / ErrIssuerCertMismatch.

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/i2-open/i2goSignals/pkg/goSet"
)

// x5cAllowedAlgs is the closed set of JWS algorithms accepted on the x5c
// verify path — ES256 (admin per-instance ECDSA P-256) and EdDSA
// (enterprise per-instance Ed25519). Same allow-list as enterprise
// verify_x5c.go x5cVerifyAlgorithms; RS256 is deliberately excluded from
// the x5c path (business RS256 SETs go through VerifySET / JWKS).
var x5cAllowedAlgs = []jose.SignatureAlgorithm{jose.ES256, jose.EdDSA}

// X5CConfig configures one x5c-chain verification. Callers construct one
// per SET (or reuse when the roots + expected-aud tuple is stable) — no
// long-lived verifier object, mirroring the single-cycle house pattern.
type X5CConfig struct {
	// Roots is the deployment CA root pool; the leaf's chain MUST validate
	// against at least one of these. Nil ⇒ ErrUnknownKey.
	Roots *x509.CertPool

	// ExpectedAudiences is the accepted-aud set; the token's aud must
	// include at least one match. Empty ⇒ ErrWrongAudience (accepting
	// any aud is treated as misconfiguration, promoted-verifier semantics).
	ExpectedAudiences []string
}

// VerifySETX5C parses the compact JWS, validates the x5c chain to the
// deployment CA roots, requires the leaf's URI-SAN URN to equal the SET's
// outer iss, verifies the signature with the certified public key, and
// returns the parsed SET on success. See the file doc for the failure
// vocabulary.
func VerifySETX5C(token string, config X5CConfig) (VerifiedSET, error) {
	if config.Roots == nil {
		return VerifiedSET{}, fmt.Errorf("%w: X5CConfig.Roots is nil (no CA pool)", ErrUnknownKey)
	}
	if len(config.ExpectedAudiences) == 0 {
		return VerifiedSET{}, fmt.Errorf("%w: X5CConfig.ExpectedAudiences is empty (would accept any aud)", ErrWrongAudience)
	}
	sig, err := jose.ParseSigned(token, x5cAllowedAlgs)
	if err != nil {
		return VerifiedSET{}, fmt.Errorf("%w: parse JWS: %v", ErrBadSignature, err)
	}
	if len(sig.Signatures) != 1 {
		return VerifiedSET{}, fmt.Errorf("%w: expected exactly one signature, got %d", ErrBadSignature, len(sig.Signatures))
	}
	hdr := sig.Signatures[0].Protected
	if typ, ok := hdr.ExtraHeaders[jose.HeaderType]; ok {
		if typStr, ok := typ.(string); ok && typStr != "secevent+jwt" {
			return VerifiedSET{}, fmt.Errorf("%w: typ header %q != secevent+jwt", ErrBadSignature, typStr)
		}
	}

	// Chain validation via jose.Header.Certificates: walks the leaf's
	// Verify() against x509.VerifyOptions we supply (Roots = deployment
	// CA pool, CurrentTime = time.Now, KeyUsageAny — the SET signing
	// cert binds a URN, not a WWW client/server role). Missing x5c ⇒
	// ErrBadSignature (a SET without x5c is unverifiable under
	// ADR-0064).
	chains, err := hdr.Certificates(x509.VerifyOptions{
		Roots:       config.Roots,
		CurrentTime: time.Now(),
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		if errors.Is(err, jose.ErrMissingX5cHeader) {
			return VerifiedSET{}, fmt.Errorf("%w: JWS x5c protected header is missing (ADR-0064: control-stream SETs must carry a cert chain)", ErrBadSignature)
		}
		return VerifiedSET{}, fmt.Errorf("%w: leaf chain does not validate to the deployment CA: %v", ErrUnknownKey, err)
	}
	if len(chains) == 0 || len(chains[0]) == 0 {
		return VerifiedSET{}, fmt.Errorf("%w: no verified chain returned", ErrUnknownKey)
	}
	leaf := chains[0][0]

	// Extract the URI-SAN URN — exactly one URI SAN, and that URI is the
	// SET's authoritative issuer identity (ADR-0064 D1).
	if len(leaf.URIs) != 1 {
		return VerifiedSET{}, fmt.Errorf("%w: leaf certificate must carry exactly one URI SAN (got %d)", ErrIssuerCertMismatch, len(leaf.URIs))
	}
	certURN := leaf.URIs[0].String()

	// Peek at the SET's iss so we can compare cert-URN vs iss before
	// paying for signature verification.
	peeked, err := goSet.Peek(token)
	if err != nil {
		return VerifiedSET{}, fmt.Errorf("%w: peek SET: %v", ErrBadSignature, err)
	}
	if peeked.Issuer == "" {
		return VerifiedSET{}, fmt.Errorf("%w: SET missing iss", ErrBadSignature)
	}
	if peeked.Issuer != certURN {
		return VerifiedSET{}, fmt.Errorf("%w: SET iss %q does not match leaf URI-SAN %q", ErrIssuerCertMismatch, peeked.Issuer, certURN)
	}

	// Signature verify with the certified public key.
	payload, err := sig.Verify(leaf.PublicKey)
	if err != nil {
		return VerifiedSET{}, fmt.Errorf("%w: %v", ErrBadSignature, err)
	}

	// Parse the payload as a SET (byte-identical to an RFC8935 SET body).
	var set goSet.SecurityEventToken
	if err := json.Unmarshal(payload, &set); err != nil {
		return VerifiedSET{}, fmt.Errorf("%w: decode SET: %v", ErrBadSignature, err)
	}

	// Audience check on the verified payload.
	if !x5cAudMatch([]string(set.Audience), config.ExpectedAudiences) {
		return VerifiedSET{}, fmt.Errorf("%w: aud %v, want any of %v", ErrWrongAudience, []string(set.Audience), config.ExpectedAudiences)
	}

	return VerifiedSET{
		Issuer: set.Issuer,
		JTI:    set.ID,
		Claims: setToClaimsMap(&set),
		Token:  &set,
		Raw:    token,
	}, nil
}

// x5cAudMatch is the aud-membership helper for the x5c path. It exists so
// tests can pin the "at least one match" semantics distinctly from the
// JWKS path's hasAudience (both are identical today; kept as separate
// helpers so a future path-specific tweak stays scoped).
func x5cAudMatch(tokenAud []string, expected []string) bool {
	for _, e := range expected {
		if slices.Contains(tokenAud, e) {
			return true
		}
	}
	return false
}
