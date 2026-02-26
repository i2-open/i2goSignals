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
	"github.com/i2-open/i2goSignals/internal/oauthClient"
	"github.com/i2-open/i2goSignals/pkg/goSet/events"
	"github.com/i2-open/i2goSignals/pkg/goSetPoll"
	"github.com/i2-open/i2goSignals/pkg/goSetPush"
	"github.com/i2-open/i2goSignals/pkg/tlsSupport"
	"github.com/segmentio/ksuid"
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

type ReceiverPushStream struct {
	mu          sync.RWMutex
	sa          *SignalsApplication
	stream      *model.StreamStateRecord
	ctx         context.Context
	cancel      context.CancelFunc
	active      bool
	statusUrl   string
	verifyUrl   string
	eventChan   chan struct{}
	lastEventAt time.Time
	verifying   bool
	verifyState string
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
	currentPushClients := make(map[string]bool)

	for _, stream := range states {
		if !stream.IsReceiver() {
			continue
		}

		if stream.GetType() == model.ReceivePush {
			sa.handleClientPushReceiver(&stream)
			currentPushClients[stream.StreamConfiguration.Id] = true
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
			sa.pollClients[sid].Close()
			delete(sa.pollClients, sid)
		}
	}

	// Clean up push clients that are no longer present or no longer receivers
	for sid := range sa.pushClients {
		if !currentPushClients[sid] {
			serverLog.Info("PUSH-RCV: Closing Push Receiver", "sid", sid)
			sa.pushClients[sid].Close()
			delete(sa.pushClients, sid)
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
	for _, ps := range sa.pushClients {
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

	pcs, ok := sa.pushClients[sid]
	if ok {
		pcs.Close()
		delete(sa.pushClients, sid)
	}

	// Remove so that the count is correct. The provider holds the true state
	_, ok = sa.pushReceivers[sid]
	if ok {
		delete(sa.pushReceivers, sid)
	}

}

// getHTTPClientForWellKnownEndpoint returns an HTTP client for fetching well-known configuration endpoints
// It applies the server's TLS configuration if a TxAlias is configured
func (sa *SignalsApplication) getHTTPClientForWellKnownEndpoint(ctx context.Context, stream *model.StreamStateRecord) *http.Client {
	conf := stream.StreamConfiguration

	// Try to get server configuration for TLS settings
	if conf.TxAlias != nil && *conf.TxAlias != "" {
		server, err := sa.Provider.GetServerByAlias(ctx, *conf.TxAlias)
		if err == nil && server != nil {
			client := oauthClient.GetBaseHTTPClientForServer(server)
			client.Timeout = 10 * time.Second
			return client
		}
	}

	// Fallback to default client with CA check
	client := &http.Client{Timeout: 10 * time.Second}
	tlsSupport.CheckCaInstalled(client)
	return client
}

func (sa *SignalsApplication) getHTTPClientForStream(ctx context.Context, stream *model.StreamStateRecord) (*http.Client, string, error) {
	conf := stream.StreamConfiguration
	var server *model.Server
	var err error

	// 1. Try TxAlias (New preferred method) - get server configuration first
	if conf.TxAlias != nil && *conf.TxAlias != "" {
		server, err = sa.Provider.GetServerByAlias(ctx, *conf.TxAlias)
		if err != nil || server == nil {
			serverLog.Warn("RCV: Server not found for alias", "alias", *conf.TxAlias, "error", err)
			server = nil // ensure nil if lookup failed
		}
	}

	// If we have a server, use it for OAuth or static token with proper TLS
	if server != nil {
		// Try OAuth client credentials first
		if server.OAuthClientConfig != nil {
			cfg := oauthClient.Config{
				TokenURL:     server.OAuthClientConfig.TokenURL,
				ClientID:     server.OAuthClientConfig.ClientID,
				ClientSecret: server.OAuthClientConfig.ClientSecret,
				Audience:     server.OAuthClientConfig.Audience,
				Resource:     server.OAuthClientConfig.Resource,
				Scopes:       server.OAuthClientConfig.Scopes,
			}

			// Use GetClientCredentialsClient which handles caching and applies server TLS settings
			client, err := oauthClient.GetClientCredentialsClient(ctx, cfg, server)
			if err == nil {
				return client, "", nil
			}
			serverLog.Error("RCV: Failed to get OAuth client credentials client", "alias", *conf.TxAlias, "error", err)
		}

		// Fallback to static token from server with proper TLS
		if server.ClientToken != nil && *server.ClientToken != "" {
			client := oauthClient.GetBaseHTTPClientForServer(server)
			token := *server.ClientToken
			if !strings.Contains(token, " ") {
				return client, "Bearer " + token, nil
			}
			return client, token, nil
		}
	}

	// 2. Backward compatibility: TxToken (no server object, use default TLS)
	if conf.TxToken != nil && *conf.TxToken != "" {
		client := &http.Client{}
		tlsSupport.CheckCaInstalled(client)
		token := *conf.TxToken
		if !strings.Contains(token, " ") {
			return client, "Bearer " + token, nil
		}
		return client, token, nil
	}

	// 3. Fallback for Polling Receiver (legacy delivery method auth)
	if stream.GetType() == model.ReceivePoll && stream.Delivery.PollReceiveMethod != nil && stream.Delivery.PollReceiveMethod.AuthorizationHeader != "" {
		// If we have a server, use its TLS settings; otherwise use default
		var client *http.Client
		if server != nil {
			client = oauthClient.GetBaseHTTPClientForServer(server)
		} else {
			client = &http.Client{}
			tlsSupport.CheckCaInstalled(client)
		}
		return client, stream.Delivery.PollReceiveMethod.AuthorizationHeader, nil
	}

	// Default client without extra authorization
	// Use server TLS settings if available
	var client *http.Client
	if server != nil {
		client = oauthClient.GetBaseHTTPClientForServer(server)
	} else {
		client = &http.Client{}
		tlsSupport.CheckCaInstalled(client)
	}
	return client, "", nil
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
			sa.handleClientPushReceiver(streamState)
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

		ps = &ClientPollStream{
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

func (sa *SignalsApplication) handleClientPushReceiver(streamState *model.StreamStateRecord) *ReceiverPushStream {
	ps, ok := sa.pushClients[streamState.StreamConfiguration.Id]
	if !ok {
		ctx, cancel := context.WithCancel(context.Background())

		ps = &ReceiverPushStream{
			sa:          sa,
			stream:      streamState,
			active:      true,
			ctx:         ctx,
			cancel:      cancel,
			eventChan:   make(chan struct{}, 1),
			lastEventAt: time.Now(),
		}
		sa.pushClients[streamState.StreamConfiguration.Id] = ps
		serverLog.Info("PUSH-RCV: Initialized push receiver monitoring", "sid", streamState.StreamConfiguration.Id)
		if streamState.StreamConfiguration.TxWellKnownUrl == nil || *streamState.StreamConfiguration.TxWellKnownUrl == "" {
			serverLog.Info("RFC8935 receiver mode only. SSF endpoint unavailable", "sid", streamState.StreamConfiguration.Id)
		}
		go ps.monitorPushStream()
		return ps
	}
	ps.mu.Lock()
	ps.stream = streamState
	ps.mu.Unlock()
	return ps
}

func (rps *ReceiverPushStream) Close() {
	rps.mu.Lock()
	defer rps.mu.Unlock()
	serverLog.Info("PUSH-RCV: Push client monitoring shutdown", "sid", rps.stream.StreamConfiguration.Id)
	if rps.active {
		rps.active = false
		rps.cancel()
	}
}

func (rps *ReceiverPushStream) notifyEvent() {
	select {
	case rps.eventChan <- struct{}{}:
	default:
	}
}

func (rps *ReceiverPushStream) handleVerificationEvent(state string) {
	rps.mu.Lock()
	defer rps.mu.Unlock()
	if rps.verifying && rps.verifyState == state {
		serverLog.Info("PUSH-RCV: Verification received for the stream", "sid", rps.stream.StreamConfiguration.Id)
		rps.verifying = false
		rps.verifyState = ""
		rps.lastEventAt = time.Now()

		// Mark as enabled and clear error upon successful verification
		if rps.stream.Status != model.StreamStateEnabled || rps.stream.ErrorMsg != "" {
			rps.sa.Provider.UpdateStreamStatus(rps.stream.StreamConfiguration.Id, model.StreamStateEnabled, "")
			rps.stream.Status = model.StreamStateEnabled
			rps.stream.ErrorMsg = ""
		}

		select {
		case rps.eventChan <- struct{}{}:
		default:
		}
	} else {
		serverLog.Warn("PUSH-RCV: Verification state mismatch or verified", "sid", rps.stream.StreamConfiguration.Id, "expected", rps.verifyState, "received", state)

		// TODO Should verify be tried again?  Or should stream be paused?
	}
}

func (rps *ReceiverPushStream) monitorPushStream() {
	rps.mu.RLock()
	minInterval := rps.stream.StreamConfiguration.MinVerificationInterval
	inactivityTimeout := rps.stream.StreamConfiguration.InactivityTimeout
	txWellKnown := rps.stream.StreamConfiguration.TxWellKnownUrl
	rps.mu.RUnlock()

	if minInterval <= 0 {
		minInterval = 300 // Default to 5 minutes
	}

	ssfEnabled := txWellKnown != nil && *txWellKnown != ""

	// Use a smaller ticker if we need to check inactivityTimeout more frequently
	tickerInterval := time.Duration(minInterval) * time.Second
	if !ssfEnabled && inactivityTimeout > 0 && time.Duration(inactivityTimeout)*time.Second < tickerInterval {
		tickerInterval = time.Duration(inactivityTimeout) * time.Second
	}

	ticker := time.NewTicker(tickerInterval)
	defer ticker.Stop()

	warnLogged := false
	errorLogged := false

	for {
		select {
		case <-rps.ctx.Done():
			return
		case <-rps.eventChan:
			rps.mu.Lock()
			rps.lastEventAt = time.Now()

			// If we receive an event, the stream is active - ensure it's marked as enabled
			if rps.stream.Status != model.StreamStateEnabled || rps.stream.ErrorMsg != "" {
				rps.sa.Provider.UpdateStreamStatus(rps.stream.StreamConfiguration.Id, model.StreamStateEnabled, "")
				rps.stream.Status = model.StreamStateEnabled
				rps.stream.ErrorMsg = ""
			}

			rps.mu.Unlock()
			ticker.Reset(tickerInterval)
			warnLogged = false
			errorLogged = false
		case <-ticker.C:
			rps.mu.RLock()
			lastEventAt := rps.lastEventAt
			sid := rps.stream.StreamConfiguration.Id
			rps.mu.RUnlock()

			elapsed := time.Since(lastEventAt)
			if ssfEnabled {
				if elapsed >= time.Duration(minInterval)*time.Second {
					rps.initiateVerification()
				}
			} else {
				if elapsed >= time.Duration(minInterval)*time.Second && !warnLogged {
					serverLog.Warn("PUSH-RCV: MinVerificationInterval exceeded", "sid", sid, "elapsed", elapsed)
					warnLogged = true
				}
				if inactivityTimeout > 0 && elapsed >= time.Duration(inactivityTimeout)*time.Second && !errorLogged {
					serverLog.Error("PUSH-RCV: InactivityTimeout exceeded", "sid", sid, "elapsed", elapsed)
					errorLogged = true
				}
			}
		}
	}
}

func (rps *ReceiverPushStream) initiateVerification() {
	serverLog.Debug("PUSH-RCV: Verification process is initiated", "sid", rps.stream.StreamConfiguration.Id)
	verifyUrl := rps.getVerifyEndpoint()
	if verifyUrl == "" {
		serverLog.Warn("PUSH-RCV: Could not determine verification endpoint", "sid", rps.stream.StreamConfiguration.Id)
		rps.fallbackToStatusCheck()
		return
	}

	state := ksuid.New().String()
	rps.mu.Lock()
	rps.verifying = true
	rps.verifyState = state
	rps.mu.Unlock()

	params := model.VerificationParameters{
		State: state,
	}
	body, _ := json.Marshal(params)

	client, auth, err := rps.sa.getHTTPClientForStream(rps.ctx, rps.stream)
	if err != nil {
		serverLog.Error("PUSH-RCV: Failed to get authenticated client", "error", err)
		rps.fallbackToStatusCheck()
		return
	}

	req, err := http.NewRequestWithContext(rps.ctx, http.MethodPost, verifyUrl, bytes.NewReader(body))
	if err != nil {
		serverLog.Error("PUSH-RCV: Failed to create verification request", "error", err)
		rps.fallbackToStatusCheck()
		return
	}

	req.Header.Set("Content-Type", "application/json")
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}

	resp, err := client.Do(req)
	if err != nil {
		serverLog.Warn("PUSH-RCV: Verification request failed", "error", err)
		rps.fallbackToStatusCheck()
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		serverLog.Warn("PUSH-RCV: Verification request unauthorized", "sid", rps.stream.StreamConfiguration.Id)
		return
	}

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		serverLog.Warn("PUSH-RCV: Verification endpoint returned error", "status", resp.StatusCode)
		rps.fallbackToStatusCheck()
		return
	}

	// Wait 120s for verification event
	go func(vState string) {
		select {
		case <-rps.ctx.Done():
			return
		case <-time.After(120 * time.Second):
			rps.mu.Lock()
			if rps.verifying && rps.verifyState == vState {
				serverLog.Warn("PUSH-RCV: Verification event not received in 120s", "sid", rps.stream.StreamConfiguration.Id)
				rps.verifying = false
				rps.mu.Unlock()
				rps.fallbackToStatusCheck()
			} else {
				rps.mu.Unlock()
			}
		}
	}(state)
}

func (rps *ReceiverPushStream) getVerifyEndpoint() string {
	rps.mu.RLock()
	if rps.verifyUrl != "" {
		rps.mu.RUnlock()
		return rps.verifyUrl
	}
	rps.mu.RUnlock()

	rps.mu.Lock()
	defer rps.mu.Unlock()

	if rps.verifyUrl != "" {
		return rps.verifyUrl
	}

	if rps.stream.StreamConfiguration.TxWellKnownUrl != nil && *rps.stream.StreamConfiguration.TxWellKnownUrl != "" {
		client := rps.sa.getHTTPClientForWellKnownEndpoint(rps.ctx, rps.stream)
		resp, err := client.Get(*rps.stream.StreamConfiguration.TxWellKnownUrl)
		if err == nil {
			defer handleRespClose(resp)
			if resp.StatusCode == http.StatusOK {
				var txConfig model.TransmitterConfiguration
				if err := json.NewDecoder(resp.Body).Decode(&txConfig); err == nil {
					if txConfig.VerificationEndpoint != "" {
						rps.verifyUrl = txConfig.VerificationEndpoint
						return rps.verifyUrl
					}
				}
			}
		}
	}

	// Fallback calculation
	statusUrl := rps.getStatusEndpointLocked()
	if statusUrl != "" {
		u, err := url.Parse(statusUrl)
		if err == nil {
			path := u.Path
			if strings.Contains(path, "/status") {
				u.Path = strings.Replace(path, "/status", "/verify", 1)
				rps.verifyUrl = u.String()
				return rps.verifyUrl
			}
		}
	}

	return ""
}

func (rps *ReceiverPushStream) getStatusEndpoint() string {
	rps.mu.Lock()
	defer rps.mu.Unlock()
	return rps.getStatusEndpointLocked()
}

func (rps *ReceiverPushStream) getStatusEndpointLocked() string {
	if rps.statusUrl != "" {
		return rps.statusUrl
	}

	if rps.stream.StreamConfiguration.TxWellKnownUrl != nil && *rps.stream.StreamConfiguration.TxWellKnownUrl != "" {
		client := rps.sa.getHTTPClientForWellKnownEndpoint(rps.ctx, rps.stream)
		resp, err := client.Get(*rps.stream.StreamConfiguration.TxWellKnownUrl)
		if err == nil {
			defer handleRespClose(resp)
			if resp.StatusCode == http.StatusOK {
				var txConfig model.TransmitterConfiguration
				if err := json.NewDecoder(resp.Body).Decode(&txConfig); err == nil {
					if txConfig.StatusEndpoint != "" {
						statusUrl := txConfig.StatusEndpoint
						u, err := url.Parse(statusUrl)
						if err == nil {
							q := u.Query()
							if q.Get("stream_id") == "" {
								q.Set("stream_id", rps.stream.StreamConfiguration.Id)
								u.RawQuery = q.Encode()
								statusUrl = u.String()
							}
						}
						rps.statusUrl = statusUrl
						return rps.statusUrl
					}
				}
			}
		}
	}
	return ""
}

func (rps *ReceiverPushStream) checkTransmitterStatus(ctx context.Context) (*model.StreamStatus, error) {
	statusUrl := rps.getStatusEndpoint()
	if statusUrl == "" {
		return nil, errors.New("could not determine status endpoint")
	}

	client, auth, err := rps.sa.getHTTPClientForStream(ctx, rps.stream)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, statusUrl, nil)
	if err != nil {
		return nil, err
	}

	if auth != "" {
		req.Header.Set("Authorization", auth)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status endpoint returned %d", resp.StatusCode)
	}

	var status model.StreamStatus
	err = json.NewDecoder(resp.Body).Decode(&status)
	if err != nil {
		return nil, err
	}
	return &status, nil
}

func (rps *ReceiverPushStream) fallbackToStatusCheck() {
	status, err := rps.checkTransmitterStatus(rps.ctx)
	if err != nil {
		serverLog.Error("PUSH-RCV: Status check failed", "sid", rps.stream.StreamConfiguration.Id, "error", err)
		return
	}

	rps.mu.Lock()
	defer rps.mu.Unlock()

	if status.Status != rps.stream.Status || rps.stream.ErrorMsg != "" {
		reason := ""
		if status.Status != model.StreamStateEnabled {
			reason = "Transmitter reported status: " + status.Status
		}
		serverLog.Info("PUSH-RCV: Syncing stream status from transmitter", "sid", rps.stream.StreamConfiguration.Id, "status", status.Status, "reason", reason)
		rps.sa.Provider.UpdateStreamStatus(rps.stream.StreamConfiguration.Id, status.Status, reason)
		rps.stream.Status = status.Status
		rps.stream.ErrorMsg = reason
	}
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
		client := ps.sa.getHTTPClientForWellKnownEndpoint(ps.ctx, ps.stream)
		resp, err := client.Get(*ps.stream.StreamConfiguration.TxWellKnownUrl)
		if err == nil {
			defer handleRespClose(resp)
			if resp.StatusCode == http.StatusOK {
				var txConfig model.TransmitterConfiguration
				if err := json.NewDecoder(resp.Body).Decode(&txConfig); err == nil {
					if txConfig.StatusEndpoint != "" {
						statusUrl := txConfig.StatusEndpoint
						u, err := url.Parse(statusUrl)
						if err == nil {
							q := u.Query()
							if q.Get("stream_id") == "" {
								q.Set("stream_id", ps.stream.StreamConfiguration.Id)
								u.RawQuery = q.Encode()
								statusUrl = u.String()
							}
						}
						ps.statusUrl = statusUrl
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
			q := u.Query()
			streamId := q.Get("stream_id")

			path := strings.TrimSuffix(u.Path, "/")
			segments := strings.Split(path, "/")

			// Try to find "poll" in segments
			pollIdx := -1
			for i := len(segments) - 1; i >= 0; i-- {
				if segments[i] == "poll" {
					pollIdx = i
					break
				}
			}

			if pollIdx != -1 {
				// If streamId was not in query, check if it's the segment after "poll"
				if streamId == "" && pollIdx < len(segments)-1 {
					streamId = segments[pollIdx+1]
				}

				// Replace "poll" with "status" and remove everything after it in the path
				segments[pollIdx] = "status"
				u.Path = strings.Join(segments[:pollIdx+1], "/")

				// Ensure stream_id is in the query
				if streamId == "" {
					streamId = ps.stream.StreamConfiguration.Id
				}
				q.Set("stream_id", streamId)
				u.RawQuery = q.Encode()

				ps.statusUrl = u.String()
				return ps.statusUrl
			}
		}
	}

	return ""
}

func handleRespClose(resp *http.Response) {
	if resp != nil {
		_ = resp.Body.Close()
	}
}

func (ps *ClientPollStream) checkTransmitterStatus(ctx context.Context) (*model.StreamStatus, error) {
	statusUrl := ps.getStatusEndpoint()
	if statusUrl == "" {
		return nil, errors.New("could not determine status endpoint")
	}

	client, auth, err := ps.sa.getHTTPClientForStream(ctx, ps.stream)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, statusUrl, nil)
	if err != nil {
		return nil, err
	}

	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	serverLog.Debug("POLL-RCV: Checking transmitter status", "sid", ps.stream.StreamConfiguration.Id, "url", statusUrl, "auth", maskAuthorization(auth))

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer handleRespClose(resp)

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
				if status.Status == model.StreamStateEnabled {
					serverLog.Info("POLL-RCV: Transmitter stream is now re-enabled after pause", "sid", sid)
					ps.sa.updateStreamAfterError(sid, model.StreamStateEnabled, "")
					ps.mu.Lock()
					ps.active = true
					ps.stream.Status = model.StreamStateEnabled
					ps.stream.ErrorMsg = ""
					ps.mu.Unlock()
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

		// do not start if disabled or marked inactive
		if !active || stream.Status == model.StreamStateDisable {
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
	var setErrs map[string]goSetPoll.SetErrType

	client, auth, err := ps.sa.getHTTPClientForStream(ps.ctx, ps.stream)
	if err != nil {
		serverLog.Error("POLL-RCV: Failed to get authenticated client", "sid", sid, "error", err)
	}

	receiveMethod := ps.stream.Delivery.PollReceiveMethod
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

		if !active || stream.Status == model.StreamStateDisable {
			break
		}

		select {
		case <-heartbeatCtx.Done():
			serverLog.Info("POLL-RCV: Heartbeat cancelled, stopping poll loop", "sid", sid)
			return
		default:
		}

		pollReq := goSetPoll.PollRequest{
			Acks:    acks,
			SetErrs: setErrs,
		}
		if receiveMethod.PollConfig != nil {
			pollReq.MaxEvents = receiveMethod.PollConfig.MaxEvents
			pollReq.ReturnImmediately = receiveMethod.PollConfig.ReturnImmediately
			pollReq.TimeoutSecs = receiveMethod.PollConfig.TimeoutSecs
		}

		serverLog.Debug("POLL-RCV Initiating POLL request", "sid", ps.stream.StreamConfiguration.Id, "url", eventUrl, "acks", len(acks), "setErrs", len(setErrs))
		parsed, httpStatus, err := goSetPoll.Poll(heartbeatCtx, pollReq, goSetPoll.ReceiverConfig{
			EndpointURL:       eventUrl,
			Authorization:     auth,
			HTTPClient:        client,
			JWKS:              jwks,
			ExpectedIssuer:    ps.stream.Iss,
			ExpectedAudiences: ps.stream.Aud,
		})

		if err != nil {
			if httpStatus == http.StatusForbidden || httpStatus == http.StatusUnauthorized {
				errMsg := fmt.Sprintf("POLL-RCV[%s] Stream disabled by transmitter: %d %s", sid, httpStatus, http.StatusText(httpStatus))
				ps.sa.updateStreamAfterError(sid, model.StreamStateDisable, errMsg)
				ps.mu.Lock()
				ps.active = false
				ps.mu.Unlock()
				return
			}

			if isConnectionError(err) || httpStatus == http.StatusServiceUnavailable {
				if firstErrorTime.IsZero() {
					firstErrorTime = time.Now()
				}
				serverLog.Warn("POLL-RCV: Polling connection error", "sid", sid, "error", err)
				if time.Since(firstErrorTime) > retryLimit {
					ps.sa.updateStreamAfterError(ps.stream.StreamConfiguration.Id, model.StreamStateDisable, fmt.Sprintf("connection error: %s", err.Error()))
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
						ps.mu.Unlock()
					}
					continue
				case <-heartbeatCtx.Done():
					return
				}
			}
			if httpStatus == http.StatusNotFound {
				ps.sa.pauseStreamOnError(ps.stream.StreamConfiguration.Id, "Disabled due to HTTP Not Found error")
				serverLog.Error("POLL-RCV: Stream Not found", "sid", ps.stream.StreamConfiguration.Id, "url", eventUrl, "status", httpStatus)
				continue
			}

			// General error (other HTTP errors or request failures)
			errMsg := fmt.Sprintf("POLL-RCV[%s url: %s] Error: %s", sid, eventUrl, err.Error())
			ps.sa.pauseStreamOnError(ps.stream.StreamConfiguration.Id, errMsg)
			serverLog.Error("POLL-RCV: Request error", "sid", ps.stream.StreamConfiguration.Id, "url", eventUrl, "error", err.Error())
			continue
		}

		// Reset the error list for next poll
		setErrs = make(map[string]goSetPoll.SetErrType)
		acks = []string{}

		setCnt := len(parsed.Sets)
		serverLog.Debug("POLL-RCV: Response received", "sid", ps.stream.StreamConfiguration.Id, "setCnt", setCnt, "hasMore", parsed.MoreAvailable)

		// Process successfully parsed and validated SETs
		for jti, token := range parsed.ParsedSETs {
			serverLog.Debug("POLL-RCV: Handling Event", "sid", ps.stream.StreamConfiguration.Id, "jti", jti)
			err = ps.sa.EventRouter.HandleEvent(token, parsed.Sets[jti], ps.stream.StreamConfiguration.Id)
			if err != nil {
				serverLog.Error("POLL-RCV: Error handling event", "sid", ps.stream.StreamConfiguration.Id, "jti", jti, "error", err)
				// We don't acknowledge if we couldn't handle it
				continue
			}
			acks = append(acks, jti)
		}

		// Carry over validation errors to report in next poll
		if len(parsed.Errors) > 0 {
			setErrs = parsed.Errors
		}

		// Successful poll - reset retry count and error tracking
		retryCount = 0
		firstErrorTime = time.Time{}
		ps.mu.RLock()
		needsUpdate := ps.stream.Status != model.StreamStateEnabled || ps.stream.ErrorMsg != ""
		ps.mu.RUnlock()
		if needsUpdate {
			ps.sa.Provider.UpdateStreamStatus(sid, model.StreamStateEnabled, "")
			ps.mu.Lock()
			ps.stream.Status = model.StreamStateEnabled
			ps.stream.ErrorMsg = ""
			ps.mu.Unlock()
		}

		// If the last poll returned no events, add a small delay to avoid tight loops.
		// This provides a safety valve while maintaining high performance for actual event delivery.
		if setCnt == 0 && !parsed.MoreAvailable {
			sleepTime := 100 * time.Millisecond
			select {
			case <-time.After(sleepTime):
			case <-heartbeatCtx.Done():
				return
			}
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
	ReceivePushEventHandler(sa, w, r)
}

func ReceivePushEventHandler(sa SsfApplicationInterface, w http.ResponseWriter, r *http.Request) {
	authContext, status := sa.GetAuth().ValidateAuthorizationAny(r, []string{authUtil.ScopeEventDelivery})
	if status != http.StatusOK || authContext == nil {
		if status == http.StatusForbidden {

			goSetPush.WriteDeliveryError(w, goSetPush.ErrAccessDenied, "The authorization did not contain the required stream identifier or scope")
		} else {
			goSetPush.WriteDeliveryError(w, goSetPush.ErrAuthenticationFailed, "The authorization was not successfully validated")
		}
		return
	}

	sid := authContext.StreamId
	if authContext.StreamId == "" {
		goSetPush.WriteDeliveryError(w, goSetPush.ErrAccessDenied, "The authorization did not contain a stream identifier")
		return
	}
	config, err := sa.GetProvider().GetStream(sid)
	if config == nil || err != nil {
		serverLog.Error("PUSH-RCV: Stream not found", "sid", sid)
		goSetPush.WriteDeliveryError(w, goSetPush.ErrNotFound, "Stream "+authContext.StreamId+" could not be located or was deleted")
		return
	}

	// Use goSetPush to handle RFC8935 protocol parsing and validation
	jwksKey := sa.GetProvider().GetIssuerJwksForReceiver(sid)
	received, deliveryErr := goSetPush.ParseReceivedSET(r, goSetPush.ReceiverConfig{
		JWKS:              jwksKey,
		ExpectedIssuer:    config.Iss,
		ExpectedAudiences: config.Aud,
	})
	if deliveryErr != nil {
		goSetPush.WriteDeliveryError(w, deliveryErr.ErrCode, deliveryErr.Description)
		return
	}

	// Application-layer: push monitoring and verification event handling
	if app, ok := sa.(*SignalsApplication); ok {
		app.mu.RLock()
		pcs, ok := app.pushClients[sid]
		app.mu.RUnlock()
		if ok {
			pcs.notifyEvent()

			// Check for verification event
			if payload, ok := received.Token.Events[events.VerificationEventUri]; ok {
				state := ""
				if pMap, ok := payload.(map[string]interface{}); ok {
					if s, ok := pMap["state"].(string); ok {
						state = s
					}
				} else if pStruct, ok := payload.(events.VerifyPayload); ok {
					state = pStruct.State
				}

				if state != "" {
					pcs.handleVerificationEvent(state)
				}
			}
		}
	}

	// Application-layer: route the event
	err = sa.GetEventRouter().HandleEvent(received.Token, received.TokenString, sid)
	if err != nil {
		goSetPush.WriteDeliveryError(w, goSetPush.ErrInvalidRequest, "Unexpected error: "+err.Error())
		return
	}

	goSetPush.WriteAccepted(w)
}

func (sa *SignalsApplication) updateStreamAfterError(streamId string, mode string, reason string) {
	sa.Provider.UpdateStreamStatus(streamId, mode, reason)
}

func (sa *SignalsApplication) pauseStreamOnError(streamId string, errMsg string) {
	sa.Provider.UpdateStreamStatus(streamId, model.StreamStatePause, errMsg)
	// TODO:  Update event router with stream state change??
}
