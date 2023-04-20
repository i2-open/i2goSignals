package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"i2goSignals/internal/model"
	"i2goSignals/pkg/goSet"
	"io"
	"log"
	"net/http"
	"strings"
)

// PollEventsReceiver implements the client-side receiver of SET events using RFC8936
func (sa *SignalsApplication) PollEventsReceiver(stream *model.StreamStateRecord) error {
	var acks []string
	var setErrs map[string]model.SetErrorType
	client := http.Client{}
	authorization := stream.Receiver.PollAuth
	eventUrl := stream.Receiver.PollUrl
	jwks := sa.Provider.GetIssuerJwksForReceiver(stream.StreamConfiguration.Id)

	for stream.Status == model.StreamStateActive {
		pollBody := stream.Receiver.PollParams // should be a copy ( by value)
		pollBody.Acks = acks
		pollBody.SetErrs = setErrs

		bodyBytes, _ := json.MarshalIndent(pollBody, "", "  ")

		pollRequest, _ := http.NewRequest(http.MethodGet, eventUrl, bytes.NewReader(bodyBytes))
		pollRequest.Header.Set("Authorization", authorization)

		resp, err := client.Do(pollRequest)
		if err != nil || resp.StatusCode > 400 {
			if err == nil {
				errMsg := fmt.Sprintf("Stream[%s url: %s] Http error: %s", stream.Id, eventUrl, resp.Status)
				sa.pauseStreamOnError(stream.StreamConfiguration.Id, errMsg)
				log.Println(errMsg)
				stream.ErrorMsg = errMsg
				continue
			}

			errMsg := fmt.Sprintf("Stream[%s url: %s]\nError: %s", stream.Id, eventUrl, err.Error())
			sa.pauseStreamOnError(stream.StreamConfiguration.Id, errMsg)
			log.Println(errMsg)
			stream.ErrorMsg = errMsg
			continue
		}
		var pollResponse model.PollResponse
		bodyBytes, err = io.ReadAll(resp.Body)
		if err != nil {
			sa.Provider.PauseStream(stream.StreamConfiguration.Id, model.StreamStatePause, err.Error())
			log.Printf("Stream[%s] Error reading response: %s", stream.Id, err.Error())
			continue
		}
		err = json.Unmarshal(bodyBytes, &pollResponse)
		if err != nil {
			errMsg := fmt.Sprintf("Stream[%s] Error parsing response: %s", stream.Id, err.Error())
			log.Printf(errMsg)
			sa.pauseStreamOnError(stream.StreamConfiguration.Id, errMsg)
			continue
		}

		// reset the error list
		setErrs = map[string]model.SetErrorType{}
		acks = []string{}
		for jti, setString := range pollResponse.Sets {
			token, err := goSet.Parse(setString, jwks)
			// Token validation and diagnostics

			// TODO: Need to detect invalid_key errors (signing and/or decryption error)

			if err != nil {
				errMsg := fmt.Sprintf("Stream[%s] Token parsing error: %s", stream.StreamConfiguration.Id, err.Error())
				log.Printf(errMsg)
				log.Println(setString)
				setErrs[jti] = model.SetErrorType{
					Error:       "invalid_request",
					Description: "The SET could not be parsed: " + err.Error(),
				}
				continue
			}
			if !token.VerifyIssuer(stream.Iss, true) {
				errMsg := fmt.Sprintf("Stream[%s] Invalid issuer received: %s does not match %s", stream.StreamConfiguration.Id, token.Issuer, stream.Iss)
				log.Printf(errMsg)
				setErrs[jti] = model.SetErrorType{
					Error:       "invalid_issuer",
					Description: "The SET Issuer is invalid for the SET Recipient.",
				}
				continue
			}
			audMatch := false
			if len(stream.Aud) > 0 {
				for _, value := range stream.Aud {
					if token.VerifyAudience(value, false) {
						audMatch = true
					}
				}
				if !audMatch {
					errMsg := fmt.Sprintf("Stream[%s] Audience was not matched: %s", stream.StreamConfiguration.Id, token.RegisteredClaims.Audience)
					log.Printf(errMsg)
					setErrs[jti] = model.SetErrorType{
						Error:       "invalid_audience",
						Description: "The SET Audience does not correspond to the SET Recipient",
					}
					continue
				}
			}
			sa.Provider.AddEvent(token, true)
			// TODO Call the event router!
			acks = append(acks, jti)
		}

	}
	return nil
}

// ReceiveEvent events enables and endpoint to receive events from the RFC8935 SET Push provider
func (sa *SignalsApplication) ReceiveEvent(w http.ResponseWriter, r *http.Request) {
	sid, status := ValidateAuthorization(r, sa.Provider.GetAuthValidatorPubKey())

	if sid == "" {
		// The authorization token had no stream identifier in it
		processPushError(w, "access_denied", "The authorization did not contain a stream identifier")
		return
	}
	if status != http.StatusOK {
		processPushError(w, "authentication_failed", "The authorization was not successfully validated")
		return
	}

	contentType := r.Header.Get("Content-Type")
	if contentType == "" || strings.EqualFold("application/secevent+jwt", contentType) {
		config, err := sa.Provider.GetStream(sid)
		if err != nil {

			log.Printf("Stream[%s] Unable to locate stream configuration.", sid)
			processPushError(w, "access_denied", "The authorization did not contain a valid stream identifier")
			return
		}
		// TODO: check that the stream matched is inbound?

		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			log.Printf("Stream[%s] Unable to read Push Request body", sid)
			processPushError(w, "invalid_request", "Expecting body with Content-Type application/secevent+jwt")
			return
		}

		jwks := sa.Provider.GetIssuerJwksForReceiver(sid)
		token, err := goSet.Parse(string(bodyBytes), jwks)

		// Token validation and diagnostics
		if err != nil {
			errMsg := fmt.Sprintf("Stream[%s] Token parsing error: %s", config.Id, err.Error())
			log.Printf(errMsg)
			processPushError(w, "invalid_request", "The request could not be parsed as a SET.")
			return
		}
		if !token.VerifyIssuer(config.Iss, true) {
			errMsg := fmt.Sprintf("invalid issuer received: %s does not match %s", token.Issuer, config.Iss)
			log.Printf("Stream[%s] Token has %s", sid, errMsg)
			processPushError(w, "invalid_issuer", "The SET Issuer is invalid for the SET Recipient.")
			return
		}
		audMatch := false
		if len(config.Aud) > 0 {
			for _, value := range config.Aud {
				if token.VerifyAudience(value, false) {
					audMatch = true
				}
			}
			if !audMatch {
				errMsg := fmt.Sprintf("audience was not matched: %s", config.Aud)
				log.Printf("Stream[%s] Token %s", sid, errMsg)
				processPushError(w, "invalid_audience", "The SET Audience does not correspond to the SET Recipient")

			}
		}

		// Now we have a valid token, store it in the database and acknowledge it
		sa.Provider.AddEvent(token, true)
		// TODO Event router needs to be notified to handle the event
		w.WriteHeader(http.StatusAccepted)
		return
	}
	log.Printf("Stream[%s] Received invalid format received: %s", sid, contentType)
	processPushError(w, "invalid_request", "Expecting Content-Type application/secevent+jwt")
	return
}

func (sa *SignalsApplication) pauseStreamOnError(streamId string, errMsg string) {
	sa.Provider.PauseStream(streamId, model.StreamStatePause, errMsg)
	// TODO:  Update event router with stream state change??
}

func processPushError(w http.ResponseWriter, errorCode string, msg string) {
	respBody := model.SetDeliveryErr{
		ErrCode:     errorCode,
		Description: msg,
	}
	responseBytes, _ := json.MarshalIndent(respBody, "", "  ")
	w.WriteHeader(http.StatusBadRequest)
	w.Header().Set("Content-Type", "application/json")
	_, err := w.Write(responseBytes)
	if err != nil {
		log.Printf("Stream[] Error writing error response message: [%s]%s", errorCode, msg)
		return
	}
}
