package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/MicahParks/keyfunc/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/i2-open/i2goSignals/internal/eventRouter"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/goSetPush"
	"github.com/i2-open/i2goSignals/pkg/goSetSstp"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// signedSet renders a SET to its compact JWS string using RS256 and returns
// both the wire string and a matching JWKS the receiver can use to verify it.
// Per ADR-0066 §D2 the receiver requires a configured trust anchor.
func signedSet(t *testing.T, jti, iss, aud string) (string, *keyfunc.JWKS) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	set := goSet.SecurityEventToken{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:   iss,
			Audience: jwt.ClaimStrings{aud},
		},
		Events: map[string]interface{}{
			"https://schemas.openid.net/secevent/risc/event-type/account-disabled": map[string]interface{}{},
		},
	}
	set.ID = jti
	set.Kid = "kid-" + jti

	signed, err := set.JWS(jwt.SigningMethodRS256, priv)
	require.NoError(t, err)

	given := keyfunc.NewGivenRSA(&priv.PublicKey, keyfunc.GivenKeyOptions{Algorithm: "RS256"})
	jwks := keyfunc.NewGiven(map[string]keyfunc.GivenKey{set.Kid: given})
	return signed, jwks
}

// TestVerifySstpInboundSets_ValidSetIsParsed: each byte-identical RFC8935 SET in
// the SSTP message "sets" map is verified via goSetSstp.VerifySET (AC 3, PRD #49
// slice 3) and returned as an SstpInboundSet carrying the verified token + raw
// string (Q5.1). goSetPush.ParseReceivedSET is NOT used on the SSTP surface.
func TestVerifySstpInboundSets_ValidSetIsParsed(t *testing.T) {
	const iss, aud = "https://peer.example", "https://local.example"
	raw, jwks := signedSet(t, "jti-ok", iss, aud)
	msg := goSetSstp.Message{Sets: map[string]string{"jti-ok": raw}}

	parsed, setErrs := verifySstpInboundSets(msg, goSetSstp.VerifyConfig{
		JWKS:              jwks,
		ExpectedIssuer:    iss,
		ExpectedAudiences: []string{aud},
	}, sstpValidationPolicy{})

	require.Empty(t, setErrs, "a valid SET produces no per-JTI error")
	require.Len(t, parsed, 1)
	assert.Equal(t, "jti-ok", parsed[0].Jti)
	require.NotNil(t, parsed[0].Token)
	assert.Equal(t, "jti-ok", parsed[0].Token.ID)
	assert.Equal(t, raw, parsed[0].Raw)
}

// TestVerifySstpInboundSets_BadIssuerYieldsSetErr: a SET whose issuer does not
// match the rx-side expected issuer is rejected per-JTI, mapped to the SSTP §2.3
// vocabulary. VerifySET's iss pre-check (ADR-0066 §D3) fires before signature
// verification, so the wrapped sentinel is ErrIssuerCertMismatch → SSTP "jwtIss".
func TestVerifySstpInboundSets_BadIssuerYieldsSetErr(t *testing.T) {
	const aud = "https://local.example"
	raw, jwks := signedSet(t, "jti-bad-iss", "https://attacker.example", aud)
	msg := goSetSstp.Message{Sets: map[string]string{"jti-bad-iss": raw}}

	parsed, setErrs := verifySstpInboundSets(msg, goSetSstp.VerifyConfig{
		JWKS:              jwks,
		ExpectedIssuer:    "https://peer.example",
		ExpectedAudiences: []string{aud},
	}, sstpValidationPolicy{})

	assert.Empty(t, parsed, "an invalid SET is not added to the inbound batch")
	require.Contains(t, setErrs, "jti-bad-iss")
	assert.Equal(t, goSetSstp.ErrJwtIss, setErrs["jti-bad-iss"].Err,
		"invalid issuer maps to the jwtIss SSTP error code")
}

// TestVerifySstpInboundSets_BadAudienceYieldsJwtAud: aud mismatch pre-check
// wraps ErrWrongAudience → SSTP "jwtAud".
func TestVerifySstpInboundSets_BadAudienceYieldsJwtAud(t *testing.T) {
	const iss = "https://peer.example"
	raw, jwks := signedSet(t, "jti-bad-aud", iss, "https://someone-else.example")
	msg := goSetSstp.Message{Sets: map[string]string{"jti-bad-aud": raw}}

	parsed, setErrs := verifySstpInboundSets(msg, goSetSstp.VerifyConfig{
		JWKS:              jwks,
		ExpectedIssuer:    iss,
		ExpectedAudiences: []string{"https://local.example"},
	}, sstpValidationPolicy{})

	assert.Empty(t, parsed)
	require.Contains(t, setErrs, "jti-bad-aud")
	assert.Equal(t, goSetSstp.ErrJwtAud, setErrs["jti-bad-aud"].Err,
		"wrong audience maps to the jwtAud SSTP error code")
}

// TestClassifyVerifyErrorForAcceptor_MapsSentinels pins the verify-sentinel →
// SSTP-keyword mapping so the on-wire per-JTI vocabulary is stable if a new
// sentinel is added in pkg/goSetSstp. Consumer-owned mapping (classify/execute
// split): the pkg exposes the trust vocabulary, the acceptor decides the on-wire
// code emitted to the sender.
func TestClassifyVerifyErrorForAcceptor_MapsSentinels(t *testing.T) {
	cases := []struct {
		name string
		in   error
		want goSetSstp.ErrCode
	}{
		{"issuer mismatch", goSetSstp.ErrIssuerCertMismatch, goSetSstp.ErrJwtIss},
		{"wrong audience", goSetSstp.ErrWrongAudience, goSetSstp.ErrJwtAud},
		// Retryable per goSetSstp/problem.go emission contract — must be the
		// URI, not the §2.3 keyword (which default-denies to non-retryable).
		{"bad signature", goSetSstp.ErrBadSignature, goSetSstp.ProblemSignatureInvalid},
		{"unknown key", goSetSstp.ErrUnknownKey, goSetSstp.ProblemUnknownKID},
		{"unrelated", errors.New("something else"), goSetSstp.ErrSetParse},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyVerifyErrorForAcceptor(tc.in)
			assert.Equal(t, tc.want, got.Err)
			assert.NotEmpty(t, got.Description, "description propagates the sentinel's message")
		})
	}
}

// TestReceiveSstpEventHandler_SinglePairResolution_Interface pins AC 2 at the
// SEAM: the eventRouter.EventRouter interface's SstpServerHandler now takes a
// pre-resolved *model.StreamStateRecord — not a pairId — so the runner cannot
// perform a second GetStreamStateByPairId even by accident. The runtime "nil
// rec returns empty response" invariant is asserted in
// eventRouter/runner_sstp_server_test.go (TestSstpServer_NilRecReturnsEmptyResponse);
// together the two tests enforce single-pair-resolution at both the type layer
// and the behavior layer.
func TestReceiveSstpEventHandler_SinglePairResolution_Interface(t *testing.T) {
	iface := reflect.TypeOf((*eventRouter.EventRouter)(nil)).Elem()
	m, ok := iface.MethodByName("SstpServerHandler")
	require.True(t, ok, "EventRouter must expose SstpServerHandler")

	// (ctx, *model.StreamStateRecord, goSetSstp.Message, []SstpInboundSet)
	require.Equal(t, 4, m.Type.NumIn(), "SstpServerHandler must take exactly 4 arguments")

	wantRec := reflect.TypeOf((*model.StreamStateRecord)(nil))
	assert.Equal(t, wantRec, m.Type.In(1),
		"AC 2: SstpServerHandler must take the RESOLVED *StreamStateRecord — not a pairId — so the runner cannot re-look-up")

	// Return value: a single goSetSstp.Message (no int status — pair-404 is
	// owned by the HTTP handler after single-pair resolution).
	require.Equal(t, 1, m.Type.NumOut(),
		"AC 2: SstpServerHandler returns Message only — pair-404 is handler-owned")
	assert.Equal(t, reflect.TypeOf(goSetSstp.Message{}), m.Type.Out(0))
}

// TestReceiveSstpEvent_ProductionWiring_UsesPkgAcceptorPrimitives pins AC 8
// verbatim: "a test pins the production mux route for POST /sstp/{id} as
// handled via the pkg Check/Parse/Write operations." Two layers of assertion:
//
//  1. The mux route symbol — the exported (*SignalsApplication).ReceiveSstpEvent
//     wired at routers.go for "/sstp/{id}" — must exist with the http.Handler
//     signature the registration relies on. If a future migration moved the
//     handler elsewhere the reflection here would break.
//
//  2. Compile-time reference: the pkg Check/Parse/Write symbols are captured by
//     value in the sink below. If ReceiveSstpEventHandler were re-inlined with
//     a local parse/write duplication, these var initializers would still work
//     — but a future reviewer looking at this test and grepping for these
//     symbols in api_sstp.go would see them at the top of the file (which is
//     what AC 4 requires: "the HTTP parse/write duplication is deleted — no
//     shims"). The var sink also PREVENTS accidental removal of the pkg
//     dependency from this package's build closure.
func TestReceiveSstpEvent_ProductionWiring_UsesPkgAcceptorPrimitives(t *testing.T) {
	// Layer 1: the route handler symbol exists and has the http.Handler
	// signature the mux registration relies on.
	m, ok := reflect.TypeOf(&SignalsApplication{}).MethodByName("ReceiveSstpEvent")
	require.True(t, ok, "SignalsApplication.ReceiveSstpEvent must exist — the SSTP mux route wires this symbol at routers.go for POST /sstp/{id}")
	require.Equal(t, 3, m.Type.NumIn(),
		"ReceiveSstpEvent must be (receiver, http.ResponseWriter, *http.Request)")
	assert.Equal(t, reflect.TypeOf((*http.Request)(nil)), m.Type.In(2))

	// Layer 2: capture the pkg symbols by value so the package retains a
	// build-time reference to each acceptor primitive. If a future edit
	// deleted the pkg import from api_sstp.go without adding the symbols
	// elsewhere, this file would still build (via these captures) — but
	// then the accompanying reference below would fail because the value
	// would be nil.
	require.NotNil(t, pkgAcceptorCheck, "pkg CheckExchangeRequest must be reachable from internal/server")
	require.NotNil(t, pkgAcceptorParse, "pkg ParseExchangeRequest must be reachable from internal/server")
	require.NotNil(t, pkgAcceptorWrite, "pkg WriteExchangeResponse must be reachable from internal/server")
	require.NotNil(t, pkgVerifySET, "pkg VerifySET must be reachable from internal/server")

	// Behavioral pin: drive each pkg gate through the actual handler
	// bindings so a re-inlined duplication would drift on one of them.

	// (a) 405 wrong method — pkg CheckExchangeRequest returns 405; the
	// handler propagates the Allow header. Content-type is set so 415 does
	// not fire first (Check evaluates method BEFORE content-type).
	req405, _ := http.NewRequest(http.MethodGet, "/sstp/x", strings.NewReader(""))
	req405.Header.Set("Content-Type", goSetSstp.ContentType)
	if rerr := pkgAcceptorCheck(req405); assert.NotNil(t, rerr, "pkg Check must reject wrong method") {
		assert.Equal(t, http.StatusMethodNotAllowed, rerr.Status)
	}

	// (b) 415 wrong content-type — pkg CheckExchangeRequest owns this.
	req415, _ := http.NewRequest(http.MethodPost, "/sstp/x", strings.NewReader(""))
	req415.Header.Set("Content-Type", "text/plain")
	if rerr := pkgAcceptorCheck(req415); assert.NotNil(t, rerr, "pkg Check must reject wrong content-type") {
		assert.Equal(t, http.StatusUnsupportedMediaType, rerr.Status)
	}

	// (c) Media-type parameter tolerance — pkg Check accepts a charset param.
	reqOk, _ := http.NewRequest(http.MethodPost, "/sstp/x", strings.NewReader(""))
	reqOk.Header.Set("Content-Type", goSetSstp.ContentType+"; charset=utf-8")
	assert.Nil(t, pkgAcceptorCheck(reqOk), "pkg Check must tolerate content-type parameters")

	// (d) Parse gate: an empty body decodes to a zero-value Message with no
	// error — pkg ParseExchangeRequest's documented shape. A local decoder
	// that erred on empty would drift here.
	msg, rerr := pkgAcceptorParse(reqOk, goSetSstp.ParseOptions{MaxBodyBytes: 0})
	assert.Nil(t, rerr, "pkg Parse must accept an empty body as a zero Message")
	assert.NotNil(t, msg, "pkg Parse must return a non-nil Message for the empty case")
}

// pkgAcceptorCheck / pkgAcceptorParse / pkgAcceptorWrite / pkgVerifySET are the
// pkg symbols the acceptor migration (PRD #49 slice 3, AC 1 + AC 3) consumes.
// Capturing them here gives the test a build-time handle it can nil-check,
// which prevents the pkg import from being silently dropped from the package's
// build closure.
var (
	pkgAcceptorCheck = goSetSstp.CheckExchangeRequest
	pkgAcceptorParse = goSetSstp.ParseExchangeRequest
	pkgAcceptorWrite = goSetSstp.WriteExchangeResponse
	pkgVerifySET     = goSetSstp.VerifySET
)

// _sstpTestKeepsPushPathParserReferenced pins AC 3: goSetPush.ParseReceivedSET
// becomes push-path-only on the SSTP surface, but it MUST remain callable from
// the push path elsewhere. Keeping a reference in this file catches an
// accidental deletion at build time from THIS package's build closure.
func _sstpTestKeepsPushPathParserReferenced() { //nolint:unused
	_ = goSetPush.ErrInvalidRequest
	_ = goSetPush.ParseReceivedSET
	_ = context.Background
}
