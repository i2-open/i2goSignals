package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/gorilla/mux"
	"github.com/i2-open/i2goSignals/pkg/authSupport"
	"github.com/i2-open/i2goSignals/pkg/goSetPoll"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// JwksJson returns the JSON Web Key Set (JWKS) for the default issuer.
//
// Return values:
//   - 200 OK: JWKS as a JSON object.
//
// Errors:
//   - 404 Not Found: Default issuer keys not found.
//   - 500 Internal Server Error: Database or serialization error.
func (sa *SignalsApplication) JwksJson(w http.ResponseWriter, r *http.Request) {
	JwksJsonHandler(sa, w, r)
}

func JwksJsonHandler(sa SsfApplicationInterface, w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")

	jsonKey := sa.GetProvider().GetPublicJWKS(sa.GetDefIssuer())
	if jsonKey == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	keyBytes, err := jsonKey.MarshalJSON()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(keyBytes)
}

type IssuerResponse struct {
	Issuers []string `json:"issuers"`
}

func (sa *SignalsApplication) GetSummaries(w http.ResponseWriter, r *http.Request) {
	authCtx, stat := sa.GetAuth().ValidateAuthorizationAny(r, []string{authSupport.ScopeStreamAdmin, authSupport.ScopeRoot})
	if stat != http.StatusOK || authCtx == nil {
		if stat != http.StatusUnauthorized {
			w.WriteHeader(stat)
			return
		}
		w.WriteHeader(stat)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	summaries, err := sa.GetProvider().ListSummaries()
	if err != nil {
		serverLog.Warn("Error listing summaries", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	resp, err := json.Marshal(summaries)
	if err != nil {
		serverLog.Warn("Error marshalling summaries", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(resp)
}

// JwksIssuers lists all issuers that have JWKS available.
//
// Return values:
//   - 200 OK: JSON array of issuer names.
//
// Errors:
//   - 500 Internal Server Error: Database error.
func (sa *SignalsApplication) JwksIssuers(w http.ResponseWriter, r *http.Request) {
	JwksIssuersHandler(sa, w, r)
}

func JwksIssuersHandler(sa SsfApplicationInterface, w http.ResponseWriter, r *http.Request) {
	authCtx, stat := sa.GetAuth().ValidateAuthorizationAny(r, []string{authSupport.ScopeStreamAdmin, authSupport.ScopeRoot})
	if stat != http.StatusOK || authCtx == nil {
		if stat != http.StatusUnauthorized {
			w.WriteHeader(stat)
			return
		}
		w.WriteHeader(stat)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	names := sa.GetProvider().ListKeyNames()
	issuerResponse := IssuerResponse{
		Issuers: names,
	}
	jsonIssuers, err := json.Marshal(issuerResponse)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(jsonIssuers)
}

// JwksJsonIssuer returns the JSON Web Key Set (JWKS) for a specific issuer.
//
// Inputs:
//   - issuer (path): The name of the issuer.
//   - format (query): Optional. If set to "pem", "x509", or "pkcs", returns the keys in that format instead of JWKS.
//
// Return values:
//   - 200 OK: JWKS as a JSON object, or keys in requested format.
//
// Errors:
//   - 400 Bad Request: Unsupported format requested.
//   - 404 Not Found: Issuer keys not found.
//   - 500 Internal Server Error: Database or conversion error.
func (sa *SignalsApplication) JwksJsonIssuer(w http.ResponseWriter, r *http.Request) {
	JwksJsonIssuerHandler(sa, w, r)
}

func JwksJsonIssuerHandler(sa SsfApplicationInterface, w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	rawIssuer := vars["issuer"]
	issuer, _ := url.QueryUnescape(rawIssuer)
	jsonKey := sa.GetProvider().GetPublicJWKS(issuer)
	if jsonKey == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	queryParams := r.URL.Query()
	respType, isFormat := queryParams["format"]
	if isFormat {
		resp, err := convertKey(jsonKey, respType[0])
		if err != nil {
			serverLog.Warn("Error converting key", "error", err.Error())
			http.Error(w, fmt.Sprintf("Error converting key: %v", err), http.StatusBadRequest)
			return
		}
		switch respType[0] {
		case "pem":
			w.Header().Set("Content-Type", "application/x-pem-file")
		case "x509":
			w.Header().Set("Content-Type", "application/pkix-cert")
		case "pkcs":
			w.Header().Set("Content-Type", "application/pkcs7-mime")
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(resp)
		return
	}

	// This is the normal JWKS response
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")

	keyBytes, err := jsonKey.MarshalJSON()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(keyBytes)
	return
}

// PollEvents implements the server side of RFC8936 Poll-based delivery of SET Tokens
// PollEvents handles requests for SETs via HTTP Poll (RFC8936).
//
// Inputs:
//   - id (path): The stream ID.
//   - Authorization (header): Token with 'event_delivery' scope.
//   - Request body (JSON): Poll parameters (maxEvents, returnImmediately, etc.).
//
// Return values:
//   - 200 OK: JSON object containing sets (SETs) and moreAvailable flag.
//
// Errors:
//   - 400 Bad Request: Invalid request parameters or missing stream ID.
//   - 401/403: Unauthorized access.
//   - 404 Not Found: Stream not found.
//   - 500 Internal Server Error: Error during polling or database access.
func (sa *SignalsApplication) PollEvents(w http.ResponseWriter, r *http.Request) {
	PollEventsHandler(sa, w, r)
}

func PollEventsHandler(sa SsfApplicationInterface, w http.ResponseWriter, r *http.Request) {
	authCtx, status := sa.GetAuth().ValidateAuthorizationAny(r, []string{authSupport.ScopeEventDelivery})

	if status != http.StatusOK {
		w.WriteHeader(status)
		return
	}
	if authCtx == nil || authCtx.StreamId == "" {
		// The authorization token had no stream identifier in it
		w.WriteHeader(http.StatusForbidden)
		return
	}

	streamState, err := sa.GetProvider().GetStreamState(authCtx.StreamId)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	behavior := os.Getenv("POLL_SRV_BEHAVIOR")
	if behavior == "" {
		behavior = "MODE"
	}

	// Parse the RFC8936 poll request
	pollReq, err := goSetPoll.ParsePollRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Convert to internal model type for application-layer processing
	request := model.PollParameters{
		MaxEvents:         pollReq.MaxEvents,
		ReturnImmediately: pollReq.ReturnImmediately,
		Acks:              pollReq.Acks,
		TimeoutSecs:       pollReq.TimeoutSecs,
	}
	if len(pollReq.SetErrs) > 0 {
		request.SetErrs = make(map[string]model.SetErrorType, len(pollReq.SetErrs))
		for jti, setErr := range pollReq.SetErrs {
			request.SetErrs[jti] = model.SetErrorType{
				Error:       setErr.Error,
				Description: setErr.Description,
			}
		}
	}

	// Determine effective status based on behavior
	effectiveStatus := streamState.Status
	if behavior == "ALWAYSON" && effectiveStatus == model.StreamStateDisable {
		effectiveStatus = model.StreamStatePause
	}

	if behavior == "MODE" || behavior == "ALWAYSON" {
		hasAcksOrErrs := len(request.Acks) > 0 || len(request.SetErrs) > 0

		if effectiveStatus == model.StreamStateDisable {
			if !hasAcksOrErrs {
				w.WriteHeader(http.StatusForbidden)
				return
			}
		} else if effectiveStatus == model.StreamStatePause {
			if !hasAcksOrErrs {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
		}

		if effectiveStatus != model.StreamStateEnabled {
			request.ReturnImmediately = true
			// backoff rate limiter to prevent repeated requests
			time.Sleep(100 * time.Millisecond)
		}
	}

	wait := ""
	if !request.ReturnImmediately {
		wait = "Long "
	}
	serverLog.Debug(fmt.Sprintf("POLL-SRV[%s] %sPoll received...", authCtx.StreamId, wait))

	// First, process the acknowledgements
	for _, jti := range request.Acks {
		serverLog.Debug(fmt.Sprintf("POLL-SRV[%s] Acking: Jti[%s]", authCtx.StreamId, jti))
		err = sa.GetProvider().AckEvent(jti, authCtx.StreamId, 0)
		if err != nil {
			serverLog.Error("Error acking event in poll", "sid", authCtx.StreamId, "jti", jti, "error", err)
		}
		event := sa.GetProvider().GetEvent(jti)
		serverLog.Debug(fmt.Sprintf("EventOut [%s]: Type: POLL ", sa.Name()))
		sa.GetEventRouter().IncrementCounter(streamState, event, false)
	}

	// Second, log any errors received
	for jti, setError := range request.SetErrs {
		errMsg := fmt.Sprintf("POLL-SRV[%s] ErrReceived: Jti[%s] Type: %s, Desc: %s\n", authCtx.StreamId, jti, setError.Error, setError.Description)
		serverLog.Warn(errMsg)
	}

	sets, more, status := sa.GetEventRouter().PollStreamHandler(authCtx.StreamId, request)

	if status != http.StatusOK {
		http.Error(w, "Stream not found or not ready", status)
		return
	}
	isMore := ""
	if more {
		isMore = "More available"
	}
	if !request.ReturnImmediately && len(sets) == 0 {
		isMore = " Timed out."
	}
	serverLog.Debug(fmt.Sprintf("POLL-SRV[%s], Returning %d SETs. %s", authCtx.StreamId, len(sets), isMore))

	// Use goSetPoll to write the RFC8936 response
	goSetPoll.WritePollResponse(w, goSetPoll.PollResponse{
		Sets:          sets,
		MoreAvailable: more,
	})
}

// PushEvents has been moved to the event router (to avoid an import cycle)
