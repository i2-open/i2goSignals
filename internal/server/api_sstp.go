package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"github.com/i2-open/i2goSignals/internal/eventRouter"
	"github.com/i2-open/i2goSignals/pkg/authSupport"
	daoInterfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/goSetPush"
	"github.com/i2-open/i2goSignals/pkg/goSetSstp"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// ReceiveSstpEvent is the HTTP entry point for the Synchronous SET Transfer
// Protocol (SSTP, draft-hunt-secevent-sstp-00) at POST /sstp/{id}. The path {id}
// is the on-wire SSF stream_id, i.e. the pair's PairId. The route is unversioned
// and POST-only with strict Content-Type, matching the /poll/{id} and /events/{id}
// conventions (PRD #154 Q19, Q21).
func (sa *SignalsApplication) ReceiveSstpEvent(w http.ResponseWriter, r *http.Request) {
	ReceiveSstpEventHandler(sa, w, r)
}

// ReceiveSstpEventHandler implements the SSTP route + auth middleware, migrated
// (PRD #49 slice 3) onto the pkg/goSetSstp acceptor primitives so parse/write
// duplication lives in one place. Observable gate order is pinned verbatim to
// the pre-migration behavior — Check(405/415) → pair-404 → bearer-401 → Parse
// (400) — with no pre-auth body read (pkg CheckExchangeRequest owns method +
// content-type only, ParseExchangeRequest owns the body).
//
// The pair record is resolved EXACTLY ONCE here (AC 2) and threaded into
// eventRouter.SstpServerHandler; the runner no longer re-looks-up. Ingest of
// each inbound SET uses goSetSstp.VerifySET (AC 3) — goSetPush.ParseReceivedSET
// remains push-path-only on this surface.
func ReceiveSstpEventHandler(sa SsfApplicationInterface, w http.ResponseWriter, r *http.Request) {
	// Gate 1 (Check): method (405) + content-type base (415). No body read —
	// this stays before the auth gate so the pinned observable ordering is
	// preserved (Seam 1 r3: split allows each consumer to keep its own gate
	// order without a pre-auth body read).
	if rerr := goSetSstp.CheckExchangeRequest(r); rerr != nil {
		if rerr.Status == http.StatusMethodNotAllowed {
			w.Header().Set("Allow", goSetSstp.Method)
		}
		writeSstpError(w, rerr.Status, goSetPush.ErrInvalidRequest, rerr.Description)
		return
	}

	pairId := mux.Vars(r)["id"]

	// Gate 2 (pair-404): resolve the pair record by PairId ONCE. AC 2 —
	// the runner no longer performs a second GetStreamStateByPairId; this
	// resolved record is threaded into SstpServerHandler.
	rec, err := sa.GetStreamService().GetStreamStateByPairId(r.Context(), pairId)
	if err != nil || rec == nil {
		if err != nil && !errors.Is(err, daoInterfaces.ErrNotFound) {
			serverLog.Error("SSTP: pair lookup failed", "pairId", pairId, "error", err)
		}
		writeSstpError(w, http.StatusNotFound, goSetPush.ErrNotFound,
			"SSTP pair "+pairId+" could not be located or was deleted")
		return
	}

	// Gate 3 (bearer-401): signing-only posture (#184) lets a business SSTP
	// pair gate trust on each SET's JWS signature rather than the stream-scoped
	// bearer, so the bearer becomes optional when the rx-side stream is
	// signing-only AND none was presented. A bearer that IS presented is still
	// held to the full check, so the gate is enforced whenever an Authorization
	// header is present or the stream is not signing-only — leaving flag-off
	// pairs byte-for-byte unchanged.
	//
	// ADR-0066 §D2 audit (i2goSignals#235): dropping the L2 bearer requirement
	// is safe ONLY when the L3 SET-signature verification path has a real trust
	// root. The invariant is enforced upstream by three cooperating layers:
	//   1. StreamService.CreateStream — validateBusinessStreamSecurity rejects
	//      SigningOnly=true without a trust root at create time.
	//   2. StreamService.UpdateStream — same validator on the update path,
	//      before any DAO write.
	//   3. LoadReceiverStreams startup guard — persisted-but-invalid records
	//      (from an older validator) are marked disabled before they can
	//      serve traffic.
	signingOnly := rec.SstpInbound != nil && rec.SstpInbound.SigningOnly
	bearerPresented := r.Header.Get("Authorization") != ""
	if (bearerPresented || !signingOnly) && !sstpAuthorized(sa, r, rec) {
		writeSstpError(w, http.StatusUnauthorized, goSetPush.ErrAuthenticationFailed,
			"The authorization was not valid for this SSTP pair")
		return
	}

	// Gate 4 (Parse): body read + JSON decode (400/413). Community business
	// acceptor stays uncapped (MaxBodyBytes: 0) — the pkg imposes no default
	// cap and the caller chooses. Only reached after the three gates above.
	inbound, rerr := goSetSstp.ParseExchangeRequest(r, goSetSstp.ParseOptions{MaxBodyBytes: 0})
	if rerr != nil {
		writeSstpError(w, rerr.Status, goSetPush.ErrInvalidRequest, rerr.Description)
		return
	}

	// Verify each inbound SET (byte-identical to an RFC8935 SET, Q5.1) against
	// the rx-side issuer/audience/JWKS via goSetSstp.VerifySET (AC 3). Per-JTI
	// verify rejections become "setErrs"; valid SETs are ingested by the runner.
	// goSetPush.ParseReceivedSET is NOT used on the SSTP surface — it remains
	// push-path-only.
	parseErrs := map[string]goSetSstp.SetErr{}
	var parsedIn []eventRouter.SstpInboundSet
	if inbound != nil && len(inbound.Sets) > 0 {
		verifyCfg := goSetSstp.VerifyConfig{}
		if rec.SstpInbound != nil {
			verifyCfg.ExpectedIssuer = rec.SstpInbound.Iss
			verifyCfg.ExpectedAudiences = rec.SstpInbound.Aud
			verifyCfg.JWKS = sa.GetStreamService().GetIssuerJwksForReceiver(r.Context(), rec.SstpInbound.Id)
			// Signing-only (#184): mandatory signature verification per inbound
			// SET so a per-JTI jws_signature_failed is reported via setErrs.
			// Even when SigningOnly is false, VerifySET already requires a JWKS
			// (nil ⇒ ErrBadSignature) — the flag is preserved for API stability.
			verifyCfg.RequireSignature = rec.SstpInbound.SigningOnly
		}
		parsedIn, parseErrs = verifySstpInboundSets(*inbound, verifyCfg)
	}

	// Run one SSTP-server cycle: ingest valid inbound SETs (persist-then-route,
	// counting eventsIn with tfr=SSTP, stream_id=rxSid) and long-poll the outbound
	// buffer. Pair-404 is already handled above — the runner receives the resolved
	// record and never re-looks-up (AC 2, PRD #49 slice 3).
	msg := inbound
	if msg == nil {
		empty := goSetSstp.Message{}
		msg = &empty
	}
	resp := sa.GetEventRouter().SstpServerHandler(r.Context(), rec, *msg, parsedIn)

	// Merge per-JTI verify errors into the response's setErrs before sending.
	for jti, se := range parseErrs {
		if resp.SetErrs == nil {
			resp.SetErrs = map[string]goSetSstp.SetErr{}
		}
		resp.SetErrs[jti] = se
	}

	if wErr := goSetSstp.WriteExchangeResponse(w, resp); wErr != nil {
		serverLog.Error("SSTP: response write failed", "pairId", pairId, "error", wErr)
	}
}

// verifySstpInboundSets verifies each SET in the SSTP message's "sets" map via
// goSetSstp.VerifySET (each SET is byte-identical to an RFC8935 SET, Q5.1) and
// splits them into (verified inbound batch, per-JTI setErrs). Rejected SETs
// carry their verify-sentinel mapped to the SSTP §2.3 vocabulary. PRD #49 slice
// 3 AC 3: replaces the pre-migration goSetPush.ParseReceivedSET-based helper —
// the push-path parser stays for RFC8935 push receivers only.
func verifySstpInboundSets(msg goSetSstp.Message, cfg goSetSstp.VerifyConfig) ([]eventRouter.SstpInboundSet, map[string]goSetSstp.SetErr) {
	parsed := make([]eventRouter.SstpInboundSet, 0, len(msg.Sets))
	setErrs := map[string]goSetSstp.SetErr{}
	for jti, raw := range msg.Sets {
		verified, vErr := goSetSstp.VerifySET(raw, cfg)
		if vErr != nil {
			setErrs[jti] = classifyVerifyErrorForAcceptor(vErr)
			continue
		}
		if verified.Token == nil {
			// Defensive: a nil Token from VerifySET would violate its
			// contract. Report as a parse error rather than fabricate ingest.
			setErrs[jti] = goSetSstp.SetErr{
				Err:         goSetSstp.ErrSetParse,
				Description: "verified SET carried a nil token",
			}
			continue
		}
		parsed = append(parsed, eventRouter.SstpInboundSet{
			Jti:   jti,
			Token: verified.Token,
			Raw:   verified.Raw,
		})
	}
	return parsed, setErrs
}

// classifyVerifyErrorForAcceptor maps a goSetSstp.VerifySET failure sentinel to
// its closest setErr code for the acceptor's per-JTI setErr surface.
// Consumer-owned mapping (classify/execute split) — the pkg exposes the trust
// vocabulary, the acceptor decides the on-wire code emitted to the sender.
//
// Emission contract (goSetSstp/problem.go §Emission contract): rejections with
// registry semantics MUST carry the canonical v1 problem URI so the peer's
// retryability dispatch resolves correctly. Signature/key failures are the
// two retryable cases — JWKS refresh can heal them — and default-deny under
// the §2.3 keyword table would silently park them.
func classifyVerifyErrorForAcceptor(err error) goSetSstp.SetErr {
	desc := err.Error()
	switch {
	case errors.Is(err, goSetSstp.ErrIssuerCertMismatch):
		return goSetSstp.SetErr{Err: goSetSstp.ErrJwtIss, Description: desc}
	case errors.Is(err, goSetSstp.ErrWrongAudience):
		return goSetSstp.SetErr{Err: goSetSstp.ErrJwtAud, Description: desc}
	case errors.Is(err, goSetSstp.ErrBadSignature):
		// Retryable: peer JWKS refresh may heal it. Use the URI, not ErrJws.
		return goSetSstp.SetErr{Err: goSetSstp.ProblemSignatureInvalid, Description: desc}
	case errors.Is(err, goSetSstp.ErrUnknownKey):
		// Retryable: peer JWKS refresh may add the kid. Use the URI, not ErrJwtCrypto.
		return goSetSstp.SetErr{Err: goSetSstp.ProblemUnknownKID, Description: desc}
	default:
		return goSetSstp.SetErr{Err: goSetSstp.ErrSetParse, Description: desc}
	}
}

// sstpAuthorized validates the request's bearer and verifies, defense-in-depth,
// that the token's StreamIds[] contains one of the pair's actual SIDs (txSid or
// rxSid) with the event scope. The SIDs come from the resolved record, not the
// request path, so a token minted for a different pair cannot act on this one.
func sstpAuthorized(sa SsfApplicationInterface, r *http.Request, rec *model.StreamStateRecord) bool {
	authorization := r.Header.Get("Authorization")
	parts := strings.SplitN(authorization, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
		return false
	}
	eat, err := sa.GetAuth().ParseAuthTokenVerbose(strings.TrimSpace(parts[1]), false)
	if err != nil || eat == nil {
		return false
	}
	scopes := []string{authSupport.ScopeEventDelivery}
	txSid := rec.StreamConfiguration.Id
	if txSid != "" && eat.IsAuthorized(txSid, scopes) {
		return true
	}
	if rec.SstpInbound != nil && rec.SstpInbound.Id != "" && eat.IsAuthorized(rec.SstpInbound.Id, scopes) {
		return true
	}
	return false
}

// writeSstpError writes the SSF {err, description} error envelope with the given
// HTTP status. HTTP status is the primary error signal; the envelope mirrors the
// RFC8935 DeliveryErr shape used by the push receiver (PRD #154 Q20). Rendering
// stays consumer-local (Seam 1: pkg/goSetSstp deliberately provides no error
// writer — community keeps this DeliveryErr shape, admin keeps its plain-text).
func writeSstpError(w http.ResponseWriter, status int, errCode string, description string) {
	body, err := json.MarshalIndent(goSetPush.DeliveryErr{ErrCode: errCode, Description: description}, "", "  ")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}
