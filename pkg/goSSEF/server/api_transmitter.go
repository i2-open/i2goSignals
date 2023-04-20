package server

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"i2goSignals/internal/model"
	"i2goSignals/pkg/goSet"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
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

	// First, process the acknowlegdgements
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

// PushEvents implements the server push side (http client) of RFC8935 Push Based Delivery of SET Events
func (sa *SignalsApplication) PushEvents(configuration model.StreamConfiguration, events []goSet.SecurityEventToken, key *rsa.PrivateKey) *[]string {
	jtis := make([]string, len(events))
	pushConfig := configuration.Delivery.PushDeliveryMethod

	client := http.Client{Timeout: 60 * time.Second}

	for i, token := range events {

		url := pushConfig.EndpointUrl

		token.Issuer = configuration.Iss
		token.Audience = configuration.Aud
		token.IssuedAt = jwt.NewNumericDate(time.Now())
		tokenString, err := token.JWS(jwt.SigningMethodRS256, key)
		if err != nil {
			log.Println("TRANSMIT PUSH Error signing event: " + err.Error())
		}

		req, err := http.NewRequest("POST", url, strings.NewReader(tokenString))
		if pushConfig.AuthorizationHeader != "" {
			req.Header.Set("Authorization", pushConfig.AuthorizationHeader)
		}
		req.Header.Set("Content-Type", "application/secevent+jwt")
		req.Header.Set("Accept", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			errMsg := fmt.Sprintf("TRANSMIT PUSH Error transmitting to stream (%s): %s", configuration.Id, err.Error())
			log.Println(errMsg)
			return &jtis
		}
		if resp.StatusCode != http.StatusAccepted {
			if resp.StatusCode == http.StatusBadRequest {
				var errorMsg model.SetDeliveryErr
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					sa.Provider.PauseStream(configuration.Id, model.StreamStatePause, "Unable to read response")
					log.Println("TRANSMIT PUSH Error reading response: " + err.Error())
					return &jtis
				}
				err = json.Unmarshal(body, &errorMsg)
				if err != nil {
					log.Println("TRANSMIT PUSH Error parsing error response: " + err.Error())
					sa.Provider.PauseStream(configuration.Id, model.StreamStatePause, "Unable to parse JSON response")
					return &jtis
				}
				errMsg := fmt.Sprintf("TRANSMIT PUSH [%s] %s", errorMsg.ErrCode, errorMsg.Description)
				log.Println(errMsg)
				sa.Provider.PauseStream(configuration.Id, model.StreamStatePause, errMsg)
				return &jtis
			}
			if resp.StatusCode > 400 {
				errMsg := fmt.Sprintf("TRANSMIT PUSH HTTP Error: %s, POSTING to %s", resp.Status, url)
				log.Println(errMsg)
				sa.Provider.PauseStream(configuration.Id, model.StreamStatePause, errMsg)
			}
		}

		jtis[i] = token.ID

	}

	log.Printf("Events delivered: %s", jtis)
	return &jtis
}
