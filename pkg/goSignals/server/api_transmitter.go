package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/mux"
	"github.com/i2-open/i2goSignals/internal/authUtil"
	"github.com/i2-open/i2goSignals/internal/model"
)

func (sa *SignalsApplication) JwksJson(w http.ResponseWriter, r *http.Request) {
	JwksJsonHandler(sa, w, r)
}

func JwksJsonHandler(sa SsfApplicationInterface, w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")

	jsonKey := sa.GetProvider().GetPublicTransmitterJWKS(sa.GetDefIssuer())
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

func (sa *SignalsApplication) JwksIssuers(w http.ResponseWriter, r *http.Request) {
	JwksIssuersHandler(sa, w, r)
}

func JwksIssuersHandler(sa SsfApplicationInterface, w http.ResponseWriter, r *http.Request) {
	authCtx, stat := sa.GetAuth().ValidateAuthorizationAny(r, []string{authUtil.ScopeStreamAdmin})
	if stat != http.StatusOK || authCtx == nil {
		if stat != http.StatusUnauthorized {
			w.WriteHeader(stat)
			return
		}
		w.WriteHeader(stat)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	names := sa.GetProvider().GetIssuerKeyNames()
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

func (sa *SignalsApplication) JwksJsonIssuer(w http.ResponseWriter, r *http.Request) {
	JwksJsonIssuerHandler(sa, w, r)
}

func JwksJsonIssuerHandler(sa SsfApplicationInterface, w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	issuer := vars["issuer"]
	jsonKey := sa.GetProvider().GetPublicTransmitterJWKS(issuer)
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
func (sa *SignalsApplication) PollEvents(w http.ResponseWriter, r *http.Request) {
	PollEventsHandler(sa, w, r)
}

func PollEventsHandler(sa SsfApplicationInterface, w http.ResponseWriter, r *http.Request) {
	authCtx, status := sa.GetAuth().ValidateAuthorization(r, []string{authUtil.ScopeEventDelivery})

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

	// set default to return immediately
	request := model.PollParameters{ReturnImmediately: false}

	err = json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
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
		// TODO Nothing to do except log it?
	}

	sets, more, status := sa.GetEventRouter().PollStreamHandler(authCtx.StreamId, request)

	resp := model.PollResponse{
		Sets:          sets,
		MoreAvailable: more,
	}

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

	respBytes, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		serverLog.Warn("POLL-SRV Error serializing response", "sid", authCtx.StreamId, "error", err.Error())
		http.Error(w, "Error serializing response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(respBytes)
	return

}

// PushEvents has been moved to the event router (to avoid an import cycle)
