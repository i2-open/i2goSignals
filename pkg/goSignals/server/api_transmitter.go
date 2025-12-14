package server

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/i2-open/i2goSignals/internal/authUtil"
	"github.com/i2-open/i2goSignals/internal/model"

	"github.com/gorilla/mux"
)

func (sa *SignalsApplication) JwksJson(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")

	jsonKey := sa.Provider.GetPublicTransmitterJWKS(sa.DefIssuer)
	if jsonKey == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusOK)
	keyBytes, _ := jsonKey.MarshalJSON()
	_, _ = w.Write(keyBytes)
}

func (sa *SignalsApplication) JwksJsonIssuer(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	issuer := vars["issuer"]

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")

	jsonKey := sa.Provider.GetPublicTransmitterJWKS(issuer)

	if jsonKey != nil {
		keyBytes, _ := jsonKey.MarshalJSON()

		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(keyBytes)
		return
	}
	w.WriteHeader(http.StatusNotFound)

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

	// First, process the acknowledgements
	for _, jti := range request.Acks {
		serverLog.Println(fmt.Sprintf("TRANSMIT POLL Stream[%s] Acking: Jti[%s]\n", authCtx.StreamId, jti))
		sa.Provider.AckEvent(jti, authCtx.StreamId)
		event := sa.Provider.GetEvent(jti)
		serverLog.Printf("EventOut [%s]: Type: POLL ", sa.Name())
		sa.EventRouter.IncrementCounter(streamState, event, false)
	}

	wait := ""
	if !request.ReturnImmediately {
		wait = "Long "
	}
	serverLog.Printf("TRANSMIT POLL Stream[%s] %sPoll request...\n", authCtx.StreamId, wait)

	// Second, log any errors received
	for jti, setError := range request.SetErrs {
		errMsg := fmt.Sprintf("TRANSMIT POLL Stream[%s] ErrReceived: Jti[%s] Type: %s, Desc: %s\n", authCtx.StreamId, jti, setError.Error, setError.Description)
		serverLog.Println(errMsg)
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
	serverLog.Printf("TRANSMIT POLL Stream[%s], Returning %d SETs. %s", authCtx.StreamId, len(sets), isMore)

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	respBytes, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		serverLog.Println("TRANSMIT POLL Error serializing response: " + err.Error())
		w.WriteHeader(http.StatusInternalServerError)
	}
	_, _ = w.Write(respBytes)
	return

}

// PushEvents has been moved to the event router (to avoid an import cycle)
