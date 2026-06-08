package server

import (
	"encoding/json"
	"errors"
	"mime"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	daoInterfaces "github.com/i2-open/i2goSignals/internal/dao/interfaces"
	"github.com/i2-open/i2goSignals/pkg/authSupport"
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

// ReceiveSstpEventHandler implements the SSTP route + auth middleware. It performs
// content-type enforcement, deleted-pair detection, and defense-in-depth bearer
// authorization, then shapes the response for the paused-pair case. The full
// long-poll runner bodies (draining outbound / ingesting inbound SETs) are wired
// by the runner slices (#164/#165); this handler provides only the route, the
// auth gate, and the paused/enabled response envelope the issue scopes.
func ReceiveSstpEventHandler(sa SsfApplicationInterface, w http.ResponseWriter, r *http.Request) {
	// POST-only. The route is registered method-agnostically (see routers.go) so any
	// other method reaches here and gets an explicit 405 (PRD #154 Q19, Q21.a).
	if r.Method != goSetSstp.Method {
		w.Header().Set("Allow", goSetSstp.Method)
		writeSstpError(w, http.StatusMethodNotAllowed, goSetPush.ErrInvalidRequest,
			"SSTP endpoint accepts POST only")
		return
	}

	// Strict Content-Type: application/sstp+json. Match on the base media type and
	// ignore parameters so "application/sstp+json; charset=utf-8" is accepted
	// (PRD #154 Q21.c). A mismatch is a 415.
	if ct := r.Header.Get("Content-Type"); ct != "" {
		baseType, _, err := mime.ParseMediaType(ct)
		if err != nil || !strings.EqualFold(baseType, goSetSstp.ContentType) {
			writeSstpError(w, http.StatusUnsupportedMediaType, goSetPush.ErrInvalidRequest,
				"Expecting Content-Type "+goSetSstp.ContentType)
			return
		}
	}

	pairId := mux.Vars(r)["id"]

	// Resolve the pair record by PairId. A missing record means the pair was
	// deleted (or never existed) — that is the 4xx case; HTTP status is the
	// primary error signal end-to-end (PRD #154 Q20, Q7.3).
	rec, err := sa.GetStreamService().GetStreamStateByPairId(r.Context(), pairId)
	if err != nil || rec == nil {
		if err != nil && !errors.Is(err, daoInterfaces.ErrNotFound) {
			serverLog.Error("SSTP: pair lookup failed", "pairId", pairId, "error", err)
		}
		writeSstpError(w, http.StatusNotFound, goSetPush.ErrNotFound,
			"SSTP pair "+pairId+" could not be located or was deleted")
		return
	}

	// Defense-in-depth authorization. The bearer carries StreamIds=[txSid, rxSid]
	// (the internal pair SIDs), NOT the PairId on the path. We resolve the actual
	// SIDs from the record and verify the token authorizes at least one of them for
	// the event scope, via AuthContext.IsAuthorizedForStream (never a bare
	// authCtx.Eat check, which is nil for OAuth/STS callers) (PRD #154 Q19, Q42).
	if !sstpAuthorized(sa, r, rec) {
		writeSstpError(w, http.StatusUnauthorized, goSetPush.ErrAuthenticationFailed,
			"The authorization was not valid for this SSTP pair")
		return
	}

	// Paused-pair semantics: a paused pair returns 200 with returnEvents=false so
	// the long-poll cycle keeps running and resumes draining on unpause. 4xx is
	// reserved for the deleted-pair case (PRD #154 Q20, Q7.3). When either
	// direction is paused we decline to return events on this cycle.
	if rec.Status == model.StreamStatePause || rec.InboundStatus == model.StreamStatePause {
		writeSstpMessage(w, goSetSstp.Message{ReturnEvents: goSetSstp.BoolPtr(false)})
		return
	}

	// Enabled pair: the runner slices (#164/#165) fill in outbound draining and
	// inbound ingestion. Until then, answer with an empty SSTP message so the route
	// + auth gate is exercisable end-to-end.
	writeSstpMessage(w, goSetSstp.Message{})
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

// writeSstpMessage writes a 200 OK SSTP response body with the strict
// application/sstp+json Content-Type.
func writeSstpMessage(w http.ResponseWriter, msg goSetSstp.Message) {
	body, err := json.Marshal(msg)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", goSetSstp.ContentType)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// writeSstpError writes the SSF {err, description} error envelope with the given
// HTTP status. HTTP status is the primary error signal; the envelope mirrors the
// RFC8935 DeliveryErr shape used by the push receiver (PRD #154 Q20).
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
