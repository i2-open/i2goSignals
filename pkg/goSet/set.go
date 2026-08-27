package goSet

import (
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/MicahParks/keyfunc/v2"
	"github.com/golang-jwt/jwt/v5"

	"github.com/i2-open/i2goSignals/pkg/dao/ids"
	"github.com/i2-open/i2goSignals/pkg/goSet/mldsa"
)

type UsernameIdentifier struct {
	Username string `json:"username,omitempty"`
}

type ExternalIdentifier struct {
	ExternalId string `json:"externalId,omitempty"`
}

type EmailIdentifier struct {
	Email string `json:"email,omitempty"`
}

type IssuerSubjectIdentifier struct {
	Issuer string `json:"iss,omitempty"`
	Sub    string `json:"sub,omitempty"`
}

type OpaqueIdentifier struct {
	Id string `json:"id,omitempty"`
}

type PhoneNumberIdentifier struct {
	PhoneNumber string `json:"phone_number,omitempty"`
}

type DecentralizedIdentifier struct {
	Url string `json:"url,omitempty"`
}

type UniformResourceIdentifier struct {
	// Note: this may cause issues as "Uri" is the same JSON attribute as AccountIdentifier Uri
	Uri string `json:"uri,omitempty"`
}

type SubIdentifier struct {
	// This is here to allow top-level sub claim
	Sub string `json:"sub,omitempty"`
}

// AliasesIdentifier carries the RFC9493 §3.2.8 "aliases" format: a set of
// subject identifiers that all refer to the same principal.
type AliasesIdentifier struct {
	Identifiers []SubjectIdentifier `json:"identifiers,omitempty"`
}

// ComplexIdentifier carries the SSF §8.1.3 complex-subject members. Each member
// is itself a (simple) subject identifier; an absent member is a wildcard
// during §8.1.3.1 matching.
type ComplexIdentifier struct {
	User    *SubjectIdentifier `json:"user,omitempty"`
	Group   *SubjectIdentifier `json:"group,omitempty"`
	Device  *SubjectIdentifier `json:"device,omitempty"`
	Session *SubjectIdentifier `json:"session,omitempty"`
	Tenant  *SubjectIdentifier `json:"tenant,omitempty"`
	OrgUnit *SubjectIdentifier `json:"org_unit,omitempty"`
}

type EventSubject struct {
	SubIdentifier     // Supports top-level sub claim
	SubjectIdentifier // Used for draft-ietf-secevent-subject-identifier format
}

type SubjectIdentifier struct {
	Format string `json:"format,omitempty"`
	UsernameIdentifier
	EmailIdentifier
	IssuerSubjectIdentifier
	OpaqueIdentifier
	PhoneNumberIdentifier
	DecentralizedIdentifier
	UniformResourceIdentifier
	ExternalIdentifier
	AliasesIdentifier
	ComplexIdentifier
}

func (sid *SubjectIdentifier) AddUsername(username string) *SubjectIdentifier {
	sid.Username = username
	return sid
}

func (sid *SubjectIdentifier) AddEmail(email string) *SubjectIdentifier {
	sid.Email = email
	return sid
}

func (sid *SubjectIdentifier) AddExternalId(id string) *SubjectIdentifier {
	sid.ExternalId = id
	return sid
}

func (sid *SubjectIdentifier) AddScimId(id string) *SubjectIdentifier {
	sid.Id = id
	return sid
}

func NewScimSubjectIdentifier(path string) *SubjectIdentifier {
	return &SubjectIdentifier{
		Format:                    "scim",
		UniformResourceIdentifier: UniformResourceIdentifier{Uri: path},
	}
}

type SecurityEventToken struct {
	jwt.RegisteredClaims

	TimeOfEvent   *jwt.NumericDate   `json:"toe,omitempty"`
	TransactionId string             `json:"txn,omitempty"`
	SubjectId     *SubjectIdentifier `json:"sub_id,omitempty"`

	Events map[string]interface{} `json:"events"`
	Kid    string                 `json:"kid,omitempty"`
}

/*
CreateSet is used to create a SecurityEventToken object that can be used to generate a JWT or JWS token. 'subject'
allows the specification of a "sub" or "sub-id" top-level JWT claim. If 'subject' is nil, no top-level claim is created
which may be useful for OpenID RISC and CAEP events.
*/
func CreateSet(subject *EventSubject, issuer string, audience []string) SecurityEventToken {
	jti := GenerateJti()
	if subject == nil {
		// Assume subject is part of event payload and will
		return SecurityEventToken{
			Events: make(map[string]interface{}),
			RegisteredClaims: jwt.RegisteredClaims{
				ID:       jti,
				IssuedAt: jwt.NewNumericDate(time.Now()),
				Issuer:   issuer,
				Audience: audience,
			},
		}
	}
	if subject.Sub != "" {
		// Subject is to be specified using the "sub" claim
		return SecurityEventToken{
			Events: make(map[string]interface{}),
			RegisteredClaims: jwt.RegisteredClaims{
				ID:       jti,
				Subject:  subject.Sub,
				IssuedAt: jwt.NewNumericDate(time.Now()),
				Issuer:   issuer,
				Audience: audience,
			},
		}
	}

	// Subject is expressed using the Sub-ID claim
	return SecurityEventToken{
		Events: make(map[string]interface{}),
		RegisteredClaims: jwt.RegisteredClaims{
			ID:       jti,
			IssuedAt: jwt.NewNumericDate(time.Now()),
			Issuer:   issuer,
			Audience: audience,
		},
		SubjectId: &subject.SubjectIdentifier,
	}

}

func (set *SecurityEventToken) String() string {

	jsonByte, err := json.MarshalIndent(set, "", "  ")
	if err != nil {
		log.Printf("Error encoding token: %s", err.Error())
	}
	return string(jsonByte)
}

// JsonBytes returns the SET's compact JSON encoding — the bytes that become
// the JWS payload. json.Marshal rather than json.Encoder: an Encoder appends a
// trailing newline, which is a byte of payload that carries no meaning and that
// every receiver has to tolerate.
func (set *SecurityEventToken) JsonBytes() []byte {
	jsonBytes, err := json.Marshal(set)
	if err != nil {
		log.Printf("Error encoding token: %s", err.Error())
	}
	return jsonBytes
}

func (set *SecurityEventToken) AddEventPayload(eventUri string, eventClaims interface{}) {
	if set.Events == nil {
		set.Events = map[string]interface{}{}
	}
	set.Events[eventUri] = eventClaims
}

func (set *SecurityEventToken) GetEventIds() []string {
	if len(set.Events) == 0 {
		return []string{}
	}

	var keys []string
	for key := range set.Events {
		keys = append(keys, key)
	}
	return keys
}

// JWT returns a jwt.Token wrapper carrying this SET's claims with
// SigningMethodNone as the wrapper method.
//
// Deprecated: this returns an alg=none token wrapper. Under ADR-0066 §D3
// alg=none is never accepted on the trust path, and no production caller
// produces unsigned SETs. This wrapper survives only for test fixtures that
// need to inspect an unsigned token's header/claims; do not use it to emit
// wire tokens. New code MUST use JWS with a real signing method + key.
func (set *SecurityEventToken) JWT() *jwt.Token {
	token := jwt.NewWithClaims(jwt.SigningMethodNone, set)
	token.Header["typ"] = "secevent+jwt"
	return token
}

// JWS produces a signed SET wire string. signingMethod defaults to ES256 when
// nil; key MUST be non-nil.
//
// key is a crypto.Signer rather than a concrete *rsa.PrivateKey so that the
// choice of signature algorithm lives entirely with the caller's
// signingMethod. Every signing site in this project previously named
// *rsa.PrivateKey in its own signature, which meant adding an algorithm
// (RFC 9964 ML-DSA, or plain ES256 on a stored EC key) required editing each
// call site rather than passing a different key. crypto.Signer is the stdlib's
// name for "a private key you can sign with"; *rsa.PrivateKey,
// *ecdsa.PrivateKey and ed25519.PrivateKey all satisfy it, so RSA-2048/RS256
// remains the default with no behaviour change.
//
// The pairing of signingMethod to key is the caller's responsibility and is
// enforced by golang-jwt: SigningMethodRS256.Sign type-asserts its key back to
// *rsa.PrivateKey and returns ErrInvalidKey on a mismatch. On the verify side
// the acceptable algorithms are pinned separately by AllowedAlgs.
//
// key must be a non-nil interface holding a non-nil key. A typed-nil pointer
// boxed into the interface (a *rsa.PrivateKey(nil) assigned to a
// crypto.Signer) is not detectable here and will panic inside the signer, so
// key-lookup paths that can fail must return an untyped nil.
//
// Per ADR-0066 §D3 the unsigned (alg=none) production path has been removed:
// there is no legitimate production producer of unsigned SETs, and leaving
// the write-side capability increases the injection blast-radius if a
// verifier is ever misconfigured. Callers that previously passed nil to
// obtain an alg=none token must construct one directly via jwt.NewWithClaims
// (test fixtures only).
func (set *SecurityEventToken) JWS(signingMethod jwt.SigningMethod, key crypto.Signer) (string, error) {
	if key == nil {
		return "", errors.New("goSet.JWS: key is required; alg=none production removed (ADR-0066 §D3)")
	}
	if signingMethod == nil {
		signingMethod = jwt.SigningMethodES256
	}

	token := jwt.NewWithClaims(signingMethod, set)
	token.Header["typ"] = "secevent+jwt"

	if set.Kid != "" {
		token.Header["kid"] = set.Kid
	} else {
		token.Header["kid"] = set.Issuer
	}

	return token.SignedString(key)
}

// AllowedAlgs returns the JWS "alg" values that goSet.Parse will accept, as a
// fresh slice the caller is free to modify.
//
// The allow-list exists so the acceptable signature algorithms are stated once
// and enforced by the parser, instead of being whatever the JWKS happens to
// hold a key for. Without it a token carrying alg=none, or one HMAC-signed
// with a public RSA modulus as the shared secret, still reaches key lookup
// before anything rejects it — the classic JWT algorithm-confusion shape.
// Handing this list to jwt.WithValidMethods closes that by construction: the
// header alg is checked before the key is ever resolved.
//
// RS256 and ES256 are what this project signs with by default (see JWS).
// ML-DSA-65 (RFC 9964, FIPS 204) is accepted for streams that opt into
// post-quantum signatures via StreamConfiguration.signing_alg; it is listed
// unconditionally because the allow-list gates the *header*, and a receiver
// must be able to verify a PQ-signed SET whether or not this node transmits
// one. This function is the single place a new SET signature algorithm becomes
// acceptable.
func AllowedAlgs() []string {
	return []string{
		jwt.SigningMethodRS256.Alg(),
		jwt.SigningMethodES256.Alg(),
		mldsa.Alg,
	}
}

// SigningMethodFor maps a stream's configured signing_alg to the jwt.SigningMethod
// the transmitter signs with. An empty alg means "unset", which is RS256 — the
// behaviour every stream had before RFC 9964 ML-DSA became selectable, so an
// existing stream config keeps signing exactly as it did.
//
// It exists so the ~5 signing sites (poll response, push delivery, SSTP
// outbound both directions, CLI) each say `goSet.SigningMethodFor(cfg.SigningAlg)`
// instead of hard-coding jwt.SigningMethodRS256, and so an unknown alg is one
// error here rather than a silent fall-through to RSA at each of them. The
// accepted set is AllowedAlgs minus ES256: this node verifies ES256 tokens from
// peers but has no EC signing key of its own to select.
func SigningMethodFor(alg string) (jwt.SigningMethod, error) {
	switch alg {
	case "", jwt.SigningMethodRS256.Alg():
		return jwt.SigningMethodRS256, nil
	case mldsa.Alg:
		return mldsa.SigningMethodMLDSA65, nil
	default:
		return nil, fmt.Errorf("unsupported SET signing algorithm %q; want one of \"\", %q, %q",
			alg, jwt.SigningMethodRS256.Alg(), mldsa.Alg)
	}
}

// MustSigningMethodFor is SigningMethodFor for the signing sites, which have no
// error path worth adding for a value validated at stream create/update time.
// An unknown alg falls back to RS256 rather than signing with nothing; the
// stream-config validation is what prevents one from ever getting this far.
func MustSigningMethodFor(alg string) jwt.SigningMethod {
	method, err := SigningMethodFor(alg)
	if err != nil {
		log.Printf("goSet: %s; signing with %s", err, jwt.SigningMethodRS256.Alg())
		return jwt.SigningMethodRS256
	}
	return method
}

// Parse parses a SET wire string and verifies its signature against the
// supplied JWKS. It is a verify-only trust-path API: issuerPublicJwks MUST be
// non-nil; passing nil returns an error.
//
// Per ADR-0066 §D3 the previous silent ParseUnverified fallback has been
// removed — an accepted Parse result is always a signature-verified token,
// and alg=none is never accepted where a signature is expected. For
// explicit, unverified inspection (e.g. pre-verify routing on the push
// receiver, or CLI display), use Peek — its result is never the accepted
// token.
//
// The signature algorithm is checked against AllowedAlgs before key lookup, so
// an unexpected alg (HS256, none) is refused without the JWKS being consulted.
func Parse(tokenString string, issuerPublicJwks *keyfunc.JWKS) (*SecurityEventToken, error) {
	if issuerPublicJwks == nil {
		return nil, errors.New("goSet.Parse: JWKS is required for verified parsing; use Peek for explicit unverified inspection (ADR-0066 §D3)")
	}

	token, err := jwt.ParseWithClaims(tokenString, &SecurityEventToken{}, issuerPublicJwks.Keyfunc,
		jwt.WithValidMethods(AllowedAlgs()))
	if err != nil {
		log.Printf("Error validating token: %s", err.Error())
		return nil, err
	}
	if token.Header["typ"] != "secevent+jwt" {
		log.Printf("token is not a security event type(secevent+jwt)")
		return nil, errors.New("token type is not `secevent+jwt`")
	}

	return token.Claims.(*SecurityEventToken), nil
}

// Peek parses a SET wire string WITHOUT verifying its signature and returns
// the claims for routing, dispatch, or display purposes only. The result is
// UNTRUSTED — it MUST NOT be treated as an accepted token, forwarded as if
// verified, or used to make any authorization decision. It exists to
// support:
//
//   - RFC 8935 push receivers that need to inspect iss/aud before signature
//     verification so that a wrong-issuer failure returns the correct
//     invalid_issuer error code rather than a generic invalid_request from a
//     JWKS lookup miss.
//   - CLI display of an inbound token when the operator is only inspecting,
//     not accepting.
//
// Per ADR-0066 §D3 unverified parsing is never a trust path. This function
// is deliberately named so a reviewer or an agent cannot mistake it for
// Parse.
func Peek(tokenString string) (*SecurityEventToken, error) {
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, &SecurityEventToken{})
	if err != nil {
		return nil, err
	}
	if token.Header["typ"] != "secevent+jwt" {
		return nil, errors.New("token type is not `secevent+jwt`")
	}
	return token.Claims.(*SecurityEventToken), nil
}

// GenerateJti mints the RFC 8417 `jti` claim for a SET: an RFC 9562 UUIDv7 from
// pkg/dao/ids, the server's single non-Mongo id source.
//
// Version 7 is chosen over a purely random id because a jti doubles as the
// ordering key on the poll and buffer paths -- v7 embeds a millisecond timestamp
// in its leading bits, so jtis sort into issue order as plain strings and a
// receiver can group or bound an event window without decoding anything.
func GenerateJti() string {
	return ids.NewV7()
}
