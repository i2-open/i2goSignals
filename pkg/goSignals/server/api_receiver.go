package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/i2-open/i2goSignals/internal/authUtil"
	"github.com/i2-open/i2goSignals/internal/model"
	"github.com/i2-open/i2goSignals/pkg/goSet"
)

type ClientPollStream struct {
	mu        sync.RWMutex
	sa        *SignalsApplication
	stream    *model.StreamStateRecord
	ctx       context.Context
	cancel    context.CancelFunc
	active    bool
	statusUrl string
}

/*
InitializeReceivers handles updates to a receiver client polling stream when changes occur.
*/
func (sa *SignalsApplication) InitializeReceivers() {
	sa.mu.Lock()
	defer sa.mu.Unlock()
	states := sa.Provider.GetStateMap()

	newPushReceivers := make(map[string]model.StreamStateRecord)
	currentPollClients := make(map[string]bool)

	for _, stream := range states {
		if !stream.IsReceiver() {
			continue
		}

		if stream.GetType() == model.ReceivePush {
			serverLog.Info("PUSH-RCV: Stream Ready", "sid", stream.StreamConfiguration.Id)
			newPushReceivers[stream.StreamConfiguration.Id] = stream
			continue
		}

		// Stream is a Polling receiver
		if stream.GetType() == model.ReceivePoll {
			sa.handleClientPollReceiverLocked(&stream)
			currentPollClients[stream.StreamConfiguration.Id] = true
		}
	}

	// Update push receivers
	sa.pushReceivers = newPushReceivers

	// Clean up poll clients that are no longer present or no longer receivers
	for sid := range sa.pollClients {
		if !currentPollClients[sid] {
			serverLog.Info("POLL-RCV: Closing Poll Receiver", "sid", sid)
			delete(sa.pollClients, sid)
		}
	}
}

func (sa *SignalsApplication) GetPushReceiverCnt() float64 {
	sa.mu.RLock()
	defer sa.mu.RUnlock()
	return float64(len(sa.pushReceivers))
}

func (sa *SignalsApplication) shutdownReceivers() {
	sa.mu.Lock()
	defer sa.mu.Unlock()
	for _, ps := range sa.pollClients {
		ps.Close()
	}
}

func (sa *SignalsApplication) CloseReceiver(sid string) {
	sa.mu.Lock()
	defer sa.mu.Unlock()
	ps, ok := sa.pollClients[sid]
	if ok {
		ps.Close()
		delete(sa.pollClients, sid)
	}

	// Remove so that the count is correct. The provider holds the true state
	_, ok = sa.pushReceivers[sid]
	if ok {
		delete(sa.pushReceivers, sid)
	}

}

/*
HandleReceiver checks if a stream is already defined and updates the configuration returning the ClientPollStream.
Otherwise, if new, a new receiver is started and its handle is returned. Transmitter streams are ignored automatically.
*/
func (sa *SignalsApplication) HandleReceiver(streamState *model.StreamStateRecord) *ClientPollStream {
	sa.mu.Lock()
	defer sa.mu.Unlock()
	if !(streamState.GetType() == model.ReceivePoll) {
		if streamState.GetType() == model.ReceivePush {
			sa.pushReceivers[streamState.StreamConfiguration.Id] = *streamState
		}
		return nil // nothing to do
	}
	return sa.handleClientPollReceiverLocked(streamState)
}

func (sa *SignalsApplication) handleClientPollReceiverLocked(streamState *model.StreamStateRecord) *ClientPollStream {
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
		serverLog.Info("POLL-RCV: Initialized poll receiver stream", "sid", streamState.StreamConfiguration.Id, "url", pollUrl)
		go ps.pollEventsReceiver()
		return ps
	}
	ps.mu.Lock()
	ps.stream = streamState
	ps.mu.Unlock()
	return ps
}

func (sa *SignalsApplication) GetPollReceiverCnt() float64 {
	sa.mu.RLock()
	defer sa.mu.RUnlock()
	return float64(len(sa.pollClients))
}

func (ps *ClientPollStream) Close() {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	serverLog.Info("POLL-RCV: Polling client shutdown", "sid", ps.stream.StreamConfiguration.Id)
	if ps.active {
		ps.active = false // do this first to prevent cancelled request from looping
		ps.cancel()
	}
}

// isConnectionError returns true if the error is related to connection failure
// and we should consider the server offline.
func isConnectionError(err error) bool {
	if err == nil {
		return false
	}

	// Context cancellation is usually a client-side thing, not a server offline thing
	if errors.Is(err, context.Canceled) {
		return false
	}

	// Context deadline exceeded is a timeout, which we DO consider a connection error
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}

	// Unwrap url.Error
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return isConnectionError(urlErr.Err)
	}

	// Net errors are usually connection related
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}

	// EOF during read is often a connection reset or server crash
	if errors.Is(err, io.EOF) {
		return true
	}

	return true
}

func (ps *ClientPollStream) getStatusEndpoint() string {
	ps.mu.RLock()
	if ps.statusUrl != "" {
		ps.mu.RUnlock()
		return ps.statusUrl
	}
	ps.mu.RUnlock()

	ps.mu.Lock()
	defer ps.mu.Unlock()

	// Double check
	if ps.statusUrl != "" {
		return ps.statusUrl
	}

	receiveMethod := ps.stream.Delivery.PollReceiveMethod
	if receiveMethod == nil {
		return ""
	}

	// Step a: Use TxWellKnownUrl if defined.
	if ps.stream.StreamConfiguration.TxWellKnownUrl != nil && *ps.stream.StreamConfiguration.TxWellKnownUrl != "" {
		resp, err := http.Get(*ps.stream.StreamConfiguration.TxWellKnownUrl)
		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				var txConfig model.TransmitterConfiguration
				if err := json.NewDecoder(resp.Body).Decode(&txConfig); err == nil {
					if txConfig.StatusEndpoint != "" {
						ps.statusUrl = txConfig.StatusEndpoint
						return ps.statusUrl
					}
				}
			}
		}
	}

	// Step b: Replace last path segment of EndpointUrl with /status
	eventUrl := receiveMethod.EndpointUrl
	if eventUrl != "" {
		u, err := url.Parse(eventUrl)
		if err == nil {
			path := u.Path
			if path != "" {
				segments := strings.Split(strings.TrimSuffix(path, "/"), "/")
				if len(segments) > 0 {
					segments[len(segments)-1] = "status"
					u.Path = strings.Join(segments, "/")
					ps.statusUrl = u.String()
					return ps.statusUrl
				}
			}
		}
	}

	return ""
}

func (ps *ClientPollStream) checkTransmitterStatus(ctx context.Context) (*model.StreamStatus, error) {
	statusUrl := ps.getStatusEndpoint()
	if statusUrl == "" {
		return nil, errors.New("could not determine status endpoint")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, statusUrl, nil)
	if err != nil {
		return nil, err
	}

	ps.mu.RLock()
	authHeader := ps.stream.Delivery.PollReceiveMethod.AuthorizationHeader
	ps.mu.RUnlock()
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status check failed with status %d", resp.StatusCode)
	}

	var streamStatus model.StreamStatus
	if err := json.NewDecoder(resp.Body).Decode(&streamStatus); err != nil {
		return nil, err
	}

	return &streamStatus, nil
}

func (ps *ClientPollStream) handleTransmitterStatus(ctx context.Context, statusCheckInterval time.Duration) (bool, error) {
	status, err := ps.checkTransmitterStatus(ctx)
	if err != nil {
		serverLog.Debug("POLL-RCV: Transmitter status check failed, proceeding with polling", "sid", ps.stream.StreamConfiguration.Id, "error", err)
		return true, nil // continue
	}

	sid := ps.stream.StreamConfiguration.Id

	for {
		if status.Status == model.StreamStateEnabled {
			return true, nil
		}

		if status.Status == model.StreamStateDisable {
			serverLog.Info("POLL-RCV: Transmitter stream is disabled", "sid", sid, "reason", status.Reason)
			ps.sa.updateStreamAfterError(sid, model.StreamStateDisable, "Transmitter stream is disabled: "+status.Reason)
			ps.mu.Lock()
			ps.active = false
			ps.mu.Unlock()
			return false, nil // stop
		}

		// if the stream is paused, periodically check status until it is re-enabled.
		if status.Status == model.StreamStatePause {
			serverLog.Info("POLL-RCV: Transmitter stream is paused", "sid", sid, "reason", status.Reason)
			ps.sa.pauseStreamOnError(sid, "Transmitter stream is paused: "+status.Reason)

			select {
			case <-time.After(statusCheckInterval):
				status, err = ps.checkTransmitterStatus(ctx)
				if err != nil {
					serverLog.Debug("POLL-RCV: Transmitter status check failed during pause, attempting poll as fallback", "sid", sid, "error", err)
					return true, nil
				}
				continue
			case <-ctx.Done():
				return false, ctx.Err()
			}
		}

		// Unknown status, fallback to enabled
		return true, nil
	}
}

// pollEventsReceiver manages the event polling process by acquiring a lease, running the poll loop, and handling cluster lease renewal.
func (ps *ClientPollStream) pollEventsReceiver() {
	sid := ps.stream.StreamConfiguration.Id
	resource := fmt.Sprintf("poll-receiver:%s", sid)

	for {
		ps.mu.RLock()
		stream := ps.stream
		active := ps.active
		ps.mu.RUnlock()

		if stream.Status != model.StreamStateEnabled || !active {
			serverLog.Debug("POLL-RCV: Stream not enabled. Will not start.", "sid", sid)
			return
		}

		// Attempt to acquire or renew the lease
		acquired, _, err := ps.sa.Provider.TryAcquireOrRenewLease(resource, ps.sa.NodeID, 30*time.Second)
		if ps.sa.Stats != nil {
			ps.sa.Stats.TrackLeaseAcquisition(resource, acquired && err == nil)
		}
		if err != nil {
			serverLog.Error("POLL-RCV: Lease acquisition error", "sid", sid, "error", err)
		}

		if !acquired {
			serverLog.Debug("POLL-RCV: Node lease not held, waiting...", "sid", sid)
			select {
			case <-time.After(15 * time.Second): // Retry after 15s
				continue
			case <-ps.ctx.Done():
				return
			}
		}

		// Lease acquired, start the actual polling
		serverLog.Info("POLL-RCV: Node lease acquired, starting polling", "sid", sid)
		ps.runPollLoop(resource)

		// Check if we should exit entirely
		select {
		case <-ps.ctx.Done():
			return
		default:
			// Loop back to try and re-acquire if runPollLoop exited for some reason
		}
	}
}

// runPollLoop processes polling events from a stream and manages lease renewal, error handling, and state transitions.
func (ps *ClientPollStream) runPollLoop(resource string) {
	sid := ps.stream.StreamConfiguration.Id
	if ps.sa.Stats != nil {
		ps.sa.Stats.IncLeasesHeld()
		defer ps.sa.Stats.DecLeasesHeld()
	}
	var acks []string
	var setErrs map[string]model.SetErrorType
	client := http.Client{}

	receiveMethod := ps.stream.Delivery.PollReceiveMethod
	authorization := receiveMethod.AuthorizationHeader
	eventUrl := receiveMethod.EndpointUrl
	jwks := ps.sa.Provider.GetIssuerJwksForReceiver(ps.stream.StreamConfiguration.Id)

	// Heartbeat for lease renewal
	heartbeatCtx, heartbeatCancel := context.WithCancel(ps.ctx)
	defer heartbeatCancel()

	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				ok, _, err := ps.sa.Provider.TryAcquireOrRenewLease(resource, ps.sa.NodeID, 30*time.Second)
				if ps.sa.Stats != nil {
					ps.sa.Stats.TrackLeaseAcquisition(resource, ok && err == nil)
				}
				if err != nil || !ok {
					serverLog.Warn("POLL-RCV: Lease lost or renewal failed", "sid", sid)
					heartbeatCancel()
					return
				}
			case <-heartbeatCtx.Done():
				return
			}
		}
	}()

	// Exponential backoff configuration
	baseDelay := 1.0 // default 1 second
	if v, err := strconv.ParseFloat(os.Getenv("POLL_RETRY_BASE_DELAY"), 64); err == nil {
		baseDelay = v
	}
	maxDelay := 300.0 // default 5 minutes
	if v, err := strconv.ParseFloat(os.Getenv("POLL_RETRY_MAX_DELAY"), 64); err == nil {
		maxDelay = v
	}
	backoffFactor := 2.0 // default factor of 2
	if v, err := strconv.ParseFloat(os.Getenv("POLL_RETRY_BACKOFF_FACTOR"), 64); err == nil {
		backoffFactor = v
	}
	retryLimit := 6 * time.Hour
	if v, err := strconv.ParseFloat(os.Getenv("POLL_RETRY_LIMIT"), 64); err == nil {
		retryLimit = time.Duration(v) * time.Second
	}

	statusCheckInterval := 30 * time.Second
	if v, err := strconv.ParseFloat(os.Getenv("POLL_STATUS_CHECK_INTERVAL"), 64); err == nil {
		statusCheckInterval = time.Duration(v * float64(time.Second))
	}

	// Initial status check upon lease acquisition - verify that the transmitter is active
	if ok, _ := ps.handleTransmitterStatus(heartbeatCtx, statusCheckInterval); !ok {
		return
	}

	retryCount := 0
	var firstErrorTime time.Time

	for {
		ps.mu.RLock()
		stream := ps.stream
		active := ps.active
		ps.mu.RUnlock()

		if stream.Status != model.StreamStateEnabled || !active {
			break
		}

		select {
		case <-heartbeatCtx.Done():
			serverLog.Info("POLL-RCV: Heartbeat cancelled, stopping poll loop", "sid", sid)
			return
		default:
		}

		var pollBody model.PollParameters
		if receiveMethod.PollConfig != nil {
			pollBody = *receiveMethod.PollConfig
		}
		pollBody.Acks = acks
		pollBody.SetErrs = setErrs

		bodyBytes, _ := json.MarshalIndent(pollBody, "", "  ")

		pollRequest, _ := http.NewRequest(http.MethodPost, eventUrl, bytes.NewReader(bodyBytes))
		pollRequest.Header.Set("Authorization", authorization)
		pollRequest.WithContext(heartbeatCtx)

		serverLog.Info("POLL-RCV Initiating POLL request", "sid", ps.stream.StreamConfiguration.Id, "url", eventUrl, "acks", len(acks), "setErrs", len(setErrs))
		resp, err := client.Do(pollRequest)
		if err != nil || (resp != nil && resp.StatusCode > 400) {
			if isConnectionError(err) {
				if firstErrorTime.IsZero() {
					firstErrorTime = time.Now()
				}
				serverLog.Warn("POLL-RCV: Polling connection error", "sid", sid, "error", err.Error())
				if time.Since(firstErrorTime) > retryLimit {
					errMsg := "connection error"
					if err != nil {
						errMsg = fmt.Sprintf("connection error: %s", err.Error())
					}
					ps.sa.updateStreamAfterError(ps.stream.StreamConfiguration.Id, model.StreamStateDisable, errMsg)
					ps.mu.Lock()
					ps.active = false
					ps.mu.Unlock()
					return // Use return instead of break to ensure loop exits and goroutine stops
				}

				delaySeconds := baseDelay * math.Pow(backoffFactor, float64(retryCount))
				if delaySeconds > maxDelay {
					delaySeconds = maxDelay
				}
				delay := time.Duration(delaySeconds * float64(time.Second))
				ps.sa.pauseStreamOnError(ps.stream.StreamConfiguration.Id, fmt.Sprintf("retry being attempted (delay %d attempt %d", delay, retryCount+1))
				serverLog.Info("POLL-RCV: Connection error, retrying...", "sid", ps.stream.StreamConfiguration.Id, "delay", delay, "attempt", retryCount+1)

				select {
				case <-time.After(delay):
					retryCount++

					// Complement retry with transmitter status check - if status is not active, abort retry
					if ok, _ := ps.handleTransmitterStatus(heartbeatCtx, statusCheckInterval); !ok {
						return
					}

					// Refresh the stream state to check if it's still enabled/active
					updatedStream, _ := ps.sa.Provider.GetStreamState(stream.StreamConfiguration.Id)
					if updatedStream != nil {
						ps.mu.Lock()
						ps.stream = updatedStream
						ps.stream.Status = model.StreamStateEnabled // temporarily treat as enabled to continue loop
						ps.stream.ErrorMsg = ""                     // reset error message
						ps.mu.Unlock()
					}
					continue
				case <-heartbeatCtx.Done():
					return
				}
			}
			if resp != nil && resp.StatusCode == http.StatusNotFound {
				errMsg := fmt.Sprintf("POLL-RCV[%s url: %s] Http error: %s", ps.stream.Id.Hex(), eventUrl, resp.Status)
				ps.sa.pauseStreamOnError(ps.stream.StreamConfiguration.Id, "Disabled due to HTTP Not Found error")
				serverLog.Error("POLL-RCV: Stream Not found", "sid", ps.stream.StreamConfiguration.Id, "url", eventUrl, "status", resp.Status)
				ps.stream.ErrorMsg = errMsg
				continue
			}
			if err == nil {
				errMsg := fmt.Sprintf("POLL-RCV[%s url: %s] Http error: %s", ps.stream.Id.Hex(), eventUrl, resp.Status)
				ps.sa.pauseStreamOnError(ps.stream.StreamConfiguration.Id, errMsg)
				serverLog.Error("POLL-RCV: HTTP Error", "sid", ps.stream.StreamConfiguration.Id, "url", eventUrl, "status", resp.Status)
				ps.stream.ErrorMsg = errMsg
				continue
			}

			errMsg := fmt.Sprintf("POLL-RCV[%s url: %s]\nError: %s", ps.stream.Id.Hex(), eventUrl, err.Error())
			ps.sa.pauseStreamOnError(ps.stream.StreamConfiguration.Id, errMsg)
			serverLog.Error("POLL-RCV: Request error", "sid", ps.stream.StreamConfiguration.Id, "url", eventUrl, "error", err.Error())
			ps.stream.ErrorMsg = errMsg
			continue
		}

		var pollResponse model.PollResponse
		if resp != nil {
			bodyBytes, err = io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if err != nil {
				ps.sa.Provider.UpdateStreamStatus(ps.stream.StreamConfiguration.Id, model.StreamStatePause, err.Error())
				serverLog.Warn("POLL_RCV: Error reading response body, will retry", "sid", ps.stream.StreamConfiguration.Id, "error", err.Error())
				continue
			}
			err = json.Unmarshal(bodyBytes, &pollResponse)
			if err != nil {
				errMsg := fmt.Sprintf("POLL-RCV[%s] Error parsing response: %s", ps.stream.Id.Hex(), err.Error())
				serverLog.Error("POLL_RCV: Error parsing poll response", "sid", ps.stream.StreamConfiguration.Id, "error", err.Error())
				ps.sa.pauseStreamOnError(ps.stream.StreamConfiguration.Id, errMsg)
				continue
			}
		}

		// reset the error list
		setErrs = map[string]model.SetErrorType{}
		acks = []string{}

		setCnt := len(pollResponse.Sets)
		serverLog.Info("POLL-RCV: Response received", "sid", ps.stream.StreamConfiguration.Id, "setCnt", setCnt, "hasMore", pollResponse.MoreAvailable)

		for jti, setString := range pollResponse.Sets {
			serverLog.Info(fmt.Sprintf("POLL-RCV[%s] Parsing Event: %s", ps.stream.Id.Hex(), jti))

			token, err := goSet.Parse(setString, jwks)
			// Auth validation and diagnostics

			// TODO: Need to detect invalid_key errors (signing and/or decryption error)

			if err != nil {
				serverLog.Warn("POLL-RCV: SET parsing error", "sid", ps.stream.StreamConfiguration.Id, "jti", jti, "error", err.Error())
				// fmt.Println(setString)
				setErrs[jti] = model.SetErrorType{
					Error:       "invalid_request",
					Description: "The SET could not be parsed: " + err.Error(),
				}
				continue
			}
			if !token.VerifyIssuer(ps.stream.Iss, true) {
				serverLog.Warn("POLL-RCV: Invalid issuer", "sid", ps.stream.StreamConfiguration.Id, "jti", jti, "expected-iss", ps.stream.Iss, "tokenIss", token.Issuer)
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
					serverLog.Warn("POLL-RCV: Audience not matched", "sid", ps.stream.StreamConfiguration.Id, "jti", jti, "tokenAud", token.RegisteredClaims.Audience)
					setErrs[jti] = model.SetErrorType{
						Error:       "invalid_audience",
						Description: "The SET Audience does not correspond to the SET Recipient",
					}
					continue
				}
			}
			// sa.Provider.AddEvent(token, true)
			serverLog.Debug("POLL-RCV: Handling Event", "sid", ps.stream.StreamConfiguration.Id, "jti", jti)
			_ = ps.sa.EventRouter.HandleEvent(token, setString, ps.stream.StreamConfiguration.Id)

			acks = append(acks, jti)
		}

	}
	if !ps.active {
		serverLog.Warn("POLL-RCV: Polling marked inactive", "sid", ps.stream.StreamConfiguration.Id)
	} else {
		serverLog.Warn("POLL-RCV: Stream state changed", "sid", ps.stream.StreamConfiguration.Id, "status", ps.stream.Status, "reason", ps.stream.ErrorMsg)
	}

	return
}

// ReceivePushEvent events enables an endpoint to receive events from the RFC8935 SET Push provider
func (sa *SignalsApplication) ReceivePushEvent(w http.ResponseWriter, r *http.Request) {
	authContext, status := sa.Auth.ValidateAuthorization(r, []string{authUtil.ScopeEventDelivery})
	if status != http.StatusOK || authContext == nil {
		processPushError(w, "authentication_failed", "The authorization was not successfully validated")
		return
	}

	sid := authContext.StreamId
	if authContext.StreamId == "" {
		// The authorization token had no stream identifier in it
		processPushError(w, "access_denied", "The authorization did not contain a stream identifier")
		return
	}
	config, err := sa.Provider.GetStream(sid)
	if config == nil || err != nil {

		serverLog.Error("PUSH-RCV: Stream not found", "sid", sid)
		processPushError(w, "not_found", "Stream "+authContext.StreamId+" could not be located or was deleted")
		return
	}
	// serverLog.Debug("Config issuer", "iss", config.Iss)

	contentType := r.Header.Get("Content-Type")
	if contentType == "" || strings.EqualFold("application/secevent+jwt", contentType) {

		// TODO: check that the stream matched is inbound?

		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			serverLog.Warn("PUSH-RCV: Unable to read HTTP Request body", "sid", sid)
			processPushError(w, "invalid_request", "Expecting body with Content-Type application/secevent+jwt")
			return
		}

		jwksKey := sa.Provider.GetIssuerJwksForReceiver(sid)
		tokenString := string(bodyBytes)

		token, err := goSet.Parse(tokenString, jwksKey)

		// Auth validation and diagnostics
		if err != nil {
			serverLog.Warn("PUSH-RCV: Error validating SET token", "sid", sid, "error", err.Error())
			processPushError(w, "invalid_request", "The request could not be parsed as a SET.")
			return
		}

		if !token.VerifyIssuer(config.Iss, true) {
			serverLog.Warn("PUSH-RCV: invalid issuer", "sid", sid, "expectedIss", config.Iss, "setIssuer", token.Issuer)
			processPushError(w, "invalid_issuer", "The SET Issuer is invalid for the SET Recipient.")
			return
		}
		audMatch := false
		if len(config.Aud) > 0 {
			serverLog.Debug("Auth audience values", "audience", token.Audience)
			for _, value := range config.Aud {
				serverLog.Debug("Checking audience match", "target", value)
				if token.VerifyAudience(value, false) {
					audMatch = true
					break
				}
			}
			if !audMatch {
				serverLog.Warn("PUSH-RCV: Audience match error", "sid", sid, "expectedAud", config.Aud, "setAud", token.Audience)
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
	serverLog.Warn(fmt.Sprintf("PUSH-RCV[%s] Received invalid format received: %s", sid, contentType))
	processPushError(w, "invalid_request", "Expecting Content-Type application/secevent+jwt")
	return
}

func (sa *SignalsApplication) updateStreamAfterError(streamId string, mode string, reason string) {
	sa.Provider.UpdateStreamStatus(streamId, mode, reason)
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
		serverLog.Error(fmt.Sprintf("Stream[] Error writing error response message: [%s]%s", errorCode, msg))
		return
	}
}
