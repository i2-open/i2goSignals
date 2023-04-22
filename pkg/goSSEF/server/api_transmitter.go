package server

import (
	"encoding/json"
	"fmt"
	"i2goSignals/internal/model"
	"log"
	"net/http"

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
	sid, status := ValidateAuthorization(r, sa.Provider.GetAuthValidatorPubKey())

	if status != http.StatusOK {
		w.WriteHeader(status)
		return
	}
	if sid == "" {
		// The authorization token had no stream identifier in it
		w.WriteHeader(http.StatusForbidden)
		return
	}

	// set default to return immediately
	request := model.PollParameters{ReturnImmediately: false}

	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}

	// First, process the acknowledgements
	for _, jti := range request.Acks {
		sa.Provider.AckEvent(jti, sid)
	}

	// Second, log any errors received
	for jti, setError := range request.SetErrs {
		errMsg := fmt.Sprintf("TRANSMIT POLL Stream[%s] ErrReceived: Jti[%s] Type: %s, Desc: %s", sid, jti, setError.Error, setError.Description)
		log.Println(errMsg)
		// TODO Nothing to do except log it?
	}

	sets, more := sa.EventRouter.PollStreamHandler(sid, request)

	resp := model.PollResponse{
		Sets:          sets,
		MoreAvailable: more,
	}
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	respBytes, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		log.Println("TRANSMIT POLL Error serializing response: " + err.Error())
		w.WriteHeader(http.StatusInternalServerError)
	}
	_, _ = w.Write(respBytes)
	return

}

// PushEvents has been moved to the event router (to avoid an import cycle)
