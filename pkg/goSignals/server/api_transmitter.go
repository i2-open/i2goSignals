package server

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/i2-open/i2goSignals/internal/authUtil"
	"github.com/i2-open/i2goSignals/internal/model"
)

func (sa *SignalsApplication) JwksJson(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")

	jsonKey := sa.Provider.GetPublicTransmitterJWKS(sa.DefIssuer)
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
	authCtx, stat := sa.Auth.ValidateAuthorizationAny(r, []string{authUtil.ScopeStreamAdmin})
	if stat != http.StatusOK || authCtx == nil {
		if stat != http.StatusUnauthorized {
			w.WriteHeader(stat)
			return
		}
		w.WriteHeader(stat)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	names := sa.Provider.GetIssuerKeyNames()
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
	vars := mux.Vars(r)
	issuer := vars["issuer"]
	jsonKey := sa.Provider.GetPublicTransmitterJWKS(issuer)
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
	authCtx, status := sa.Auth.ValidateAuthorization(r, []string{authUtil.ScopeEventDelivery})

	if status != http.StatusOK {
		w.WriteHeader(status)
		return
	}
	if authCtx == nil || authCtx.StreamId == "" {
		// The authorization token had no stream identifier in it
		w.WriteHeader(http.StatusForbidden)
		return
	}

	streamState, err := sa.Provider.GetStreamState(authCtx.StreamId)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	// set default to return immediately
	request := model.PollParameters{ReturnImmediately: false}

	err = json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}

	wait := ""
	if !request.ReturnImmediately {
		wait = "Long "
	}
	serverLog.Debug(fmt.Sprintf("POLL-SRV[%s] %sPoll received...\n", authCtx.StreamId, wait))

	// First, process the acknowledgements
	for _, jti := range request.Acks {
		serverLog.Debug(fmt.Sprintf("POLL-SRV[%s] Acking: Jti[%s]\n", authCtx.StreamId, jti))
		err = sa.Provider.AckEvent(jti, authCtx.StreamId, 0)
		if err != nil {
			serverLog.Error("Error acking event in poll", "sid", authCtx.StreamId, "jti", jti, "error", err)
		}
		event := sa.Provider.GetEvent(jti)
		serverLog.Debug(fmt.Sprintf("EventOut [%s]: Type: POLL ", sa.Name()))
		sa.EventRouter.IncrementCounter(streamState, event, false)
	}

	// Second, log any errors received
	for jti, setError := range request.SetErrs {
		errMsg := fmt.Sprintf("POLL-SRV[%s] ErrReceived: Jti[%s] Type: %s, Desc: %s\n", authCtx.StreamId, jti, setError.Error, setError.Description)
		serverLog.Warn(errMsg)
		// TODO Nothing to do except log it?
	}

	sets, more, status := sa.EventRouter.PollStreamHandler(authCtx.StreamId, request)

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
