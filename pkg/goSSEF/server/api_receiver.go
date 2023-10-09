package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/independentid/i2goSignals/internal/authUtil"
	"github.com/independentid/i2goSignals/internal/model"
	"github.com/independentid/i2goSignals/pkg/goSet"
)

type ClientPollStream struct {
	sa     *SignalsApplication
	stream *model.StreamStateRecord
	ctx    context.Context
	cancel context.CancelFunc
	active bool
}

/*
InitializeReceivers handles updates to a receiver client polling stream when changes occur.
*/
func (sa *SignalsApplication) InitializeReceivers() {
	states := sa.Provider.GetStateMap()
	for _, stream := range states {
		if !stream.IsReceiver() {
			continue
		}

		if stream.GetType() == model.DeliveryPush {
			serverLog.Printf("Initialized Stream: %s, Type: Inbound Method: PUSH", stream.StreamConfiguration.Id)
			sa.pushReceivers[stream.StreamConfiguration.Id] = stream
			continue
		}
		// Stream is a Polling receiver
		sa.HandleClientPollReceiver(&stream)
	}
}

func (sa *SignalsApplication) GetPushReceiverCnt() float64 {
	return float64(len(sa.pushReceivers))
}

func (sa *SignalsApplication) shutdownReceivers() {
	for _, ps := range sa.pollClients {
		ps.Close()
	}
}

func (sa *SignalsApplication) ClosePollReceiver(sid string) {

	ps, ok := sa.pollClients[sid]
	if ok {
		ps.Close()
		delete(sa.pollClients, sid)
	}

}

/*
HandleClientPollReceiver checks if a stream is already defined and updates the configuration returning the ClientPollStream.
Otherwise, if new, a new receiver is started and its handle is returned. Transmitter streams are ignored automatically.
*/
func (sa *SignalsApplication) HandleClientPollReceiver(streamState *model.StreamStateRecord) *ClientPollStream {
	if !(streamState.GetType() == model.ReceivePoll) {
		return nil // nothing to do
	}
	ps, ok := sa.pollClients[streamState.StreamConfiguration.Id]
	if !ok {
		ctx, cancel := context.WithCancel(context.Background())

		ps := &ClientPollStream{
			sa:     sa,
			stream: streamState,
			active: true,
			ctx:    ctx,
			cancel: cancel,
		}
		sa.pollClients[streamState.StreamConfiguration.Id] = ps
		pollUrl := streamState.Delivery.PollReceiveMethod.EndpointUrl
		serverLog.Printf("Initialized Stream: %s, Type: Inbound Method: POLL, EventUrl: %s", streamState.StreamConfiguration.Id, pollUrl)
		go ps.pollEventsReceiver()
		return ps
	}
	ps.stream = streamState
	return ps
}

func (sa *SignalsApplication) GetPollReceiverCnt() float64 {
	return float64(len(sa.pollClients))
}

func (ps *ClientPollStream) Close() {
	serverLog.Printf("POLL-RCV[%s] Polling client shutdown requested. ", ps.stream.StreamConfiguration.Id)
	if ps.active {
		ps.active = false // do this first to prevent cancelled request from looping
		ps.cancel()
	}
}

// PollEventsReceiver implements the client-side receiver of SET events using RFC8936
func (ps *ClientPollStream) pollEventsReceiver() {
	var acks []string
	var setErrs map[string]model.SetErrorType
	client := http.Client{}

	receiveMethod := ps.stream.Delivery.PollReceiveMethod
	authorization := receiveMethod.AuthorizationHeader
	eventUrl := receiveMethod.EndpointUrl
	jwks := ps.sa.Provider.GetIssuerJwksForReceiver(ps.stream.StreamConfiguration.Id)

	for ps.stream.Status == model.StreamStateEnabled && ps.active {
		pollBody := receiveMethod.PollConfig // should be a copy ( by value)
		pollBody.Acks = acks
		pollBody.SetErrs = setErrs

		bodyBytes, _ := json.MarshalIndent(pollBody, "", "  ")

		pollRequest, _ := http.NewRequest(http.MethodPost, eventUrl, bytes.NewReader(bodyBytes))
		pollRequest.Header.Set("Authorization", authorization)
		pollRequest.WithContext(ps.ctx)

		serverLog.Printf("POLL-RCV[%s url: %s] Request: Acks=%d, Errs=%d", ps.stream.StreamConfiguration.Id, eventUrl, len(acks), len(setErrs))
		resp, err := client.Do(pollRequest)
		if err != nil || resp.StatusCode > 400 {
			if resp.StatusCode == http.StatusNotFound {
				errMsg := fmt.Sprintf("POLL-RCV[%s url: %s] Http error: %s", ps.stream.Id.Hex(), eventUrl, resp.Status)
				ps.sa.pauseStreamOnError(ps.stream.StreamConfiguration.Id, "Disabled due to HTTP Not Found error")
				serverLog.Println(errMsg)
				ps.stream.ErrorMsg = errMsg
				continue
			}
			if err == nil {
				errMsg := fmt.Sprintf("POLL-RCV[%s url: %s] Http error: %s", ps.stream.Id.Hex(), eventUrl, resp.Status)
				ps.sa.pauseStreamOnError(ps.stream.StreamConfiguration.Id, errMsg)
				serverLog.Println(errMsg)
				ps.stream.ErrorMsg = errMsg
				continue
			}

			errMsg := fmt.Sprintf("POLL-RCV[%s url: %s]\nError: %s", ps.stream.Id.Hex(), eventUrl, err.Error())
			ps.sa.pauseStreamOnError(ps.stream.StreamConfiguration.Id, errMsg)
			serverLog.Println(errMsg)
			ps.stream.ErrorMsg = errMsg
			continue
		}

		var pollResponse model.PollResponse
		bodyBytes, err = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			ps.sa.Provider.UpdateStreamStatus(ps.stream.StreamConfiguration.Id, model.StreamStatePause, err.Error())
			errMsg := fmt.Sprintf("POLL-RCV[%s] Error reading response: %s", ps.stream.Id.Hex(), err.Error())
			serverLog.Printf(errMsg)
			continue
		}
		err = json.Unmarshal(bodyBytes, &pollResponse)
		if err != nil {
			errMsg := fmt.Sprintf("POLL-RCV[%s] Error parsing response: %s", ps.stream.Id.Hex(), err.Error())
			serverLog.Printf(errMsg)
			ps.sa.pauseStreamOnError(ps.stream.StreamConfiguration.Id, errMsg)
			continue
		}

		// reset the error list
		setErrs = map[string]model.SetErrorType{}
		acks = []string{}

		setCnt := len(pollResponse.Sets)
		serverLog.Printf("POLL-RCV[%s url: %s] Response: SETs=%d, More=%t", ps.stream.StreamConfiguration.Id, eventUrl, setCnt, pollResponse.MoreAvailable)

		for jti, setString := range pollResponse.Sets {
			serverLog.Printf("POLL-RCV[%s] Parsing Event: %s", ps.stream.Id.Hex(), jti)

			token, err := goSet.Parse(setString, jwks)
			// Auth validation and diagnostics

			// TODO: Need to detect invalid_key errors (signing and/or decryption error)

			if err != nil {
				errMsg := fmt.Sprintf("POLL-RCV[%s] Auth parsing error:\n%s\n", ps.stream.StreamConfiguration.Id, err.Error())
				serverLog.Printf(errMsg)
				// fmt.Println(setString)
				setErrs[jti] = model.SetErrorType{
					Error:       "invalid_request",
					Description: "The SET could not be parsed: " + err.Error(),
				}
				continue
			}
			if !token.VerifyIssuer(ps.stream.Iss, true) {
				errMsg := fmt.Sprintf("POLL-RCV[%s] Invalid issuer received: %s does not match %s", ps.stream.StreamConfiguration.Id, token.Issuer, ps.stream.Iss)
				serverLog.Printf(errMsg)
				setErrs[jti] = model.SetErrorType{
					Error:       "invalid_issuer",
					Description: "The SET Issuer is invalid for the SET Recipient.",
				}
				continue
			}
			audMatch := false
			if len(ps.stream.Aud) > 0 {
				for _, value := range ps.stream.Aud {
					if token.VerifyAudience(value, false) {
						audMatch = true
					}
				}
				if !audMatch {
					errMsg := fmt.Sprintf("POLL-RCV[%s] Audience was not matched: %s", ps.stream.StreamConfiguration.Id, token.RegisteredClaims.Audience)
					serverLog.Printf(errMsg)
					setErrs[jti] = model.SetErrorType{
						Error:       "invalid_audience",
						Description: "The SET Audience does not correspond to the SET Recipient",
					}
					continue
				}
			}
			// sa.Provider.AddEvent(token, true)
			serverLog.Printf("POLL-RCV[%s] Handling Event: %s", ps.stream.StreamConfiguration.Id, token.ID)
			_ = ps.sa.EventRouter.HandleEvent(token, setString, ps.stream.StreamConfiguration.Id)

			acks = append(acks, jti)
		}

	}
	if !ps.active {
		serverLog.Printf("POLL-RCV[%s] Polling stopped.", ps.stream.StreamConfiguration.Id)
	} else {
		serverLog.Printf("POLL-RCV[%s] Stream state changed to: [%s] %s", ps.stream.StreamConfiguration.Id, ps.stream.Status, ps.stream.ErrorMsg)
	}

	return
}

// ReceivePushEvent events enables an endpoint to receive events from the RFC8935 SET Push provider
func (sa *SignalsApplication) ReceivePushEvent(w http.ResponseWriter, r *http.Request) {
	authContext, status := sa.Auth.ValidateAuthorization(r, []string{authUtil.ScopeEventDelivery})

	sid := authContext.StreamId
	if authContext.StreamId == "" {
		// The authorization token had no stream identifier in it
		processPushError(w, "access_denied", "The authorization did not contain a stream identifier")
		return
	}
	config, err := sa.Provider.GetStream(sid)
	if config == nil || err != nil {

		serverLog.Printf("PUSH-RCV[%s] Unable to locate stream configuration.", sid)
		processPushError(w, "not_found", "Stream "+authContext.StreamId+" could not be located or was deleted")
		return
	}
	fmt.Println("***********Config.iss=" + config.Iss)

	if status != http.StatusOK {
		processPushError(w, "authentication_failed", "The authorization was not successfully validated")
		return
	}

	contentType := r.Header.Get("Content-Type")
	if contentType == "" || strings.EqualFold("application/secevent+jwt", contentType) {

		// TODO: check that the stream matched is inbound?

		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			serverLog.Printf("PUSH-RCV[%s] Unable to read Push Request body", sid)
			processPushError(w, "invalid_request", "Expecting body with Content-Type application/secevent+jwt")
			return
		}

		jwksKey := sa.Provider.GetIssuerJwksForReceiver(sid)
		tokenString := string(bodyBytes)

		token, err := goSet.Parse(tokenString, jwksKey)

		// Auth validation and diagnostics
		if err != nil {
			errMsg := fmt.Sprintf("PUSH-RCV[%s] Auth parsing error: %s", config.Id, err.Error())
			serverLog.Printf(errMsg)
			processPushError(w, "invalid_request", "The request could not be parsed as a SET.")
			return
		}

		if !token.VerifyIssuer(config.Iss, true) {
			errMsg := fmt.Sprintf("invalid issuer received: %s does not match %s", token.Issuer, config.Iss)
			serverLog.Printf("PUSH-RCV[%s] Auth has %s", sid, errMsg)
			processPushError(w, "invalid_issuer", "The SET Issuer is invalid for the SET Recipient.")
			return
		}
		audMatch := false
		if len(config.Aud) > 0 {
			fmt.Println(fmt.Sprintf("Auth Aud Vals: %v", token.Audience))
			for _, value := range config.Aud {
				fmt.Println("*****Checking aud match against: " + value)
				if token.VerifyAudience(value, false) {
					audMatch = true
					break
				}
			}
			if !audMatch {
				errMsg := fmt.Sprintf("audience was not matched: %s", config.Aud)
				serverLog.Printf("PUSH-RCV[%s] Auth %s", sid, errMsg)
				processPushError(w, "invalid_audience", "The SET Audience does not correspond to the SET Recipient")
				return
			}
		}

		// Now we have a valid token, store it in the database and acknowledge it
		err = sa.EventRouter.HandleEvent(token, tokenString, sid)
		// TODO: Handle different types of errors
		if err != nil {
			processPushError(w, "invalid_request", "Unexpected error: "+err.Error())
			return
		}

		// sa.Provider.AddEvent(token, true)
		// TODO Event router needs to be notified to handle the event
		w.WriteHeader(http.StatusAccepted)
		return
	}
	serverLog.Printf("PUSH-RCV[%s] Received invalid format received: %s", sid, contentType)
	processPushError(w, "invalid_request", "Expecting Content-Type application/secevent+jwt")
	return
}

func (sa *SignalsApplication) pauseStreamOnError(streamId string, errMsg string) {
	sa.Provider.UpdateStreamStatus(streamId, model.StreamStatePause, errMsg)
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
		serverLog.Printf("Stream[] Error writing error response message: [%s]%s", errorCode, msg)
		return
	}
}
