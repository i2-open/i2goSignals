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
	"net/http/httptrace"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/i2-open/i2goSignals/internal/eventRouter"
	"github.com/i2-open/i2goSignals/pkg/authSupport"
	"github.com/i2-open/i2goSignals/pkg/dao/ids"
	"github.com/i2-open/i2goSignals/pkg/goSet/events"
	"github.com/i2-open/i2goSignals/pkg/goSetPoll"
	"github.com/i2-open/i2goSignals/pkg/goSetPush"
	"github.com/i2-open/i2goSignals/pkg/goSsfUtils"
	"github.com/i2-open/i2goSignals/pkg/oauthClient"
	"github.com/i2-open/i2goSignals/pkg/services"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/i2-open/i2goSignals/pkg/tlsSupport"
	"github.com/i2-open/i2goSignals/pkg/wellKnownSupport"
)

const (
	// verificationWait is how long a push receiver waits for the SSF verification
	// event it just requested before falling back to a /status poll.
	verificationWait = 120 * time.Second

	// leaseRetryDelay is how long a node waits before re-attempting a poll-receiver
	// lease another node currently holds.
	leaseRetryDelay = 15 * time.Second

	// emptyPollBackoff is the safety-valve pause after a poll that returned no
	// events, so an idle stream does not spin the poll loop.
	emptyPollBackoff = 100 * time.Millisecond
)

type ClientPollStream struct {
	mu                  sync.RWMutex
	sa                  *SignalsApplication
	stream              *model.StreamStateRecord
	ctx                 context.Context
	cancel              context.CancelFunc
	active              bool          // false once Close() or a terminal error asked the receiver to stop
	running             bool          // true while the polling goroutine is alive (set on launch, cleared on goroutine exit)
	done                chan struct{} // closed by the polling goroutine when it exits; lets StopGracefully wait for an in-flight poll to drain
	statusUrl           string
	verifyUrl           string // cached transmitter verification endpoint
	verifyRequested     bool   // true once a verification has been requested for this goroutine (one-shot on stream establishment)
	managementExercised bool   // true once the management self-exercise has run for this goroutine (one-shot, conformance only)
}

type ReceiverPushStream struct {
	mu                       sync.RWMutex
	sa                       *SignalsApplication
	stream                   *model.StreamStateRecord
	ctx                      context.Context
	cancel                   context.CancelFunc
	active                   bool
	statusUrl                string
	verifyUrl                string
	eventChan                chan struct{}
	lastEventAt              time.Time
	verifying                bool
	verifyState              string
	verifyOnEstablishPending bool
}

/*
InitializeReceivers handles updates to a receiver client polling stream when changes occur.
*/
func (sa *SignalsApplication) InitializeReceivers() {
	sa.mu.Lock()
	defer sa.mu.Unlock()
	states := sa.StreamService.GetStateMap(context.Background())

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
			sa.handleClientPollReceiver(&stream)
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

// DrainReceiver gracefully stops a polling receiver and waits for its in-flight
// poll to complete, so no poll request to the transmitter overlaps a subsequent
// delete cascade. It does not remove the client (CloseReceiver still does the
// final cleanup); it only stops the long-poll loop without tearing the current
// request. Push receivers issue no long-poll, so they are left for CloseReceiver.
// Best-effort: a drain timeout just means CloseReceiver will force-cancel next.
func (sa *SignalsApplication) DrainReceiver(sid string) {
	sa.mu.Lock()
	ps, ok := sa.pollClients[sid]
	sa.mu.Unlock()
	if !ok {
		return
	}

	// Bound the wait by the poll's own long-poll timeout plus slack so the DELETE
	// stays responsive; the in-flight poll returns within that window.
	timeout := 12 * time.Second
	ps.mu.RLock()
	if rm := ps.stream.Delivery.PollReceiveMethod; rm != nil && rm.PollConfig != nil && rm.PollConfig.TimeoutSecs > 0 {
		timeout = time.Duration(rm.PollConfig.TimeoutSecs+2) * time.Second
	}
	ps.mu.RUnlock()

	if drained := ps.StopGracefully(timeout); !drained {
		serverLog.Warn("RCV: poll drain timed out before delete; forcing close", "sid", sid, "timeout", timeout)
	} else {
		serverLog.Debug("RCV: poll drained before delete cascade", "sid", sid)
	}
}

// getHTTPClientForWellKnownEndpoint returns an HTTP client for fetching well-known configuration endpoints
// It applies the server's TLS configuration if a TxAlias is configured
func (sa *SignalsApplication) getHTTPClientForWellKnownEndpoint(ctx context.Context, stream *model.StreamStateRecord) *http.Client {
	conf := stream.StreamConfiguration

	// Try to get server configuration for TLS settings
	if conf.TxAlias != nil && *conf.TxAlias != "" {
		server, err := sa.ServerService.GetServerByAlias(ctx, *conf.TxAlias)
		if err == nil && server != nil {
			client := oauthClient.GetBaseHTTPClientForServer(server)
			client.Timeout = 10 * time.Second
			return client
		}
	}

	// No TxAlias server: honor any per-stream transmitter-TLS settings recorded on
	// the stream itself (self-signed or hostname-mismatched transmitter), so the
	// inline static-token receiver path can discover a transmitter whose cert the
	// system roots don't trust.
	if conf.TxTLSSkipVerify || conf.TxTLSCertificate != "" {
		srv := &model.Server{TLSSkipVerify: conf.TxTLSSkipVerify, TLSCertificate: conf.TxTLSCertificate}
		client := oauthClient.GetBaseHTTPClientForServer(srv)
		client.Timeout = 10 * time.Second
		return client
	}

	// Fallback to default client with CA check
	client := &http.Client{Timeout: 10 * time.Second}
	tlsSupport.CheckCaInstalled(client)
	return client
}

func (sa *SignalsApplication) getServerForStream(ctx context.Context, stream *model.StreamStateRecord) (*model.Server, error) {
	conf := stream.StreamConfiguration
	if conf.TxAlias != nil && *conf.TxAlias != "" {
		return sa.ServerService.GetServerByAlias(ctx, *conf.TxAlias)
	}
	return nil, nil
}

// getHTTPClientForStream is the historical entrypoint for push / poll dial-
// outs. Post-slice #242 (PRD 49 2b) it delegates to ResolveTransmitterClient
// — the SINGLE named helper for the transmitter credential-selection chain
// (see internal/server/transmitter_credential_chain.go). Keeping the wrapper
// avoids churning ~15 call sites in this file; new call sites SHOULD call
// ResolveTransmitterClient directly.
func (sa *SignalsApplication) getHTTPClientForStream(ctx context.Context, stream *model.StreamStateRecord) (*http.Client, string, func(), error) {
	return sa.ResolveTransmitterClient(ctx, stream)
}

// CascadeReceiverStreamDelete deletes the corresponding stream on the FOREIGN
// transmitter when a locally-auto-registered receiver stream is removed
// (SSF 1.0 §8.1.1.5). It is best-effort: any failure is logged and swallowed so
// local deletion always succeeds (mirroring the SSTP peer-cascade contract). A
// no-op unless the stream is a receiver stream carrying a remote_stream_id.
func (sa *SignalsApplication) CascadeReceiverStreamDelete(ctx context.Context, state *model.StreamStateRecord) {
	conf := state.StreamConfiguration
	if !(state.GetType() == model.ReceivePoll || state.GetType() == model.ReceivePush) {
		return
	}
	if conf.RemoteStreamId == nil || *conf.RemoteStreamId == "" {
		return
	}

	// Resolve the transmitter's configuration_endpoint: prefer a registered
	// TxAlias server's cached metadata, else discover it from the well-known URL.
	configEndpoint := sa.resolveTransmitterConfigEndpoint(ctx, state)
	if configEndpoint == "" {
		serverLog.Warn("RCV: delete cascade skipped — no transmitter configuration_endpoint", "sid", conf.Id)
		return
	}

	delURL := goSsfUtils.AddStreamIdToUrl(configEndpoint, *conf.RemoteStreamId)
	client, auth, closeClient, err := sa.getHTTPClientForStream(ctx, state)
	if err != nil {
		serverLog.Warn("RCV: delete cascade skipped — client error", "sid", conf.Id, "error", err)
		return
	}
	defer closeClient()

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, delURL, nil)
	if err != nil {
		serverLog.Warn("RCV: delete cascade skipped — request build error", "sid", conf.Id, "error", err)
		return
	}
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}

	resp, err := client.Do(req)
	if err != nil {
		serverLog.Warn("RCV: delete cascade to transmitter failed", "sid", conf.Id, "remote", *conf.RemoteStreamId, "error", err)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	// 204/200 = deleted; 404 = already gone (also acceptable per §8.1.1.5).
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
		serverLog.Warn("RCV: delete cascade — unexpected transmitter status", "sid", conf.Id, "status", resp.StatusCode)
		return
	}
	serverLog.Info("RCV: delete cascaded to transmitter", "sid", conf.Id, "remote", *conf.RemoteStreamId, "status", resp.StatusCode)
}

// resolveTransmitterConfigEndpoint returns the transmitter's
// configuration_endpoint for a receiver stream: a registered TxAlias server's
// cached metadata if present, else discovered from the stream's well-known URL.
// Returns "" if neither is available.
func (sa *SignalsApplication) resolveTransmitterConfigEndpoint(ctx context.Context, state *model.StreamStateRecord) string {
	conf := state.StreamConfiguration
	if server, _ := sa.getServerForStream(ctx, state); server != nil && server.ServerConfiguration != nil {
		if server.ServerConfiguration.ConfigurationEndpoint != "" {
			return server.ServerConfiguration.ConfigurationEndpoint
		}
	}
	if conf.TxWellKnownUrl != nil && *conf.TxWellKnownUrl != "" {
		wkClient := sa.getHTTPClientForWellKnownEndpoint(ctx, state)
		txConfig, err := wellKnownSupport.FetchSSFConfiguration(ctx, wkClient, *conf.TxWellKnownUrl)
		if err != nil {
			serverLog.Warn("RCV: failed to discover transmitter configuration_endpoint", "sid", conf.Id, "error", err)
			return ""
		}
		return txConfig.ConfigurationEndpoint
	}
	return ""
}

// resolveTransmitterStatusEndpoint mirrors resolveTransmitterConfigEndpoint for
// the status_endpoint (SSF 1.0 §8.1.2). Returns "" if it cannot be resolved.
func (sa *SignalsApplication) resolveTransmitterStatusEndpoint(ctx context.Context, state *model.StreamStateRecord) string {
	conf := state.StreamConfiguration
	if server, _ := sa.getServerForStream(ctx, state); server != nil && server.ServerConfiguration != nil {
		if server.ServerConfiguration.StatusEndpoint != "" {
			return server.ServerConfiguration.StatusEndpoint
		}
	}
	if conf.TxWellKnownUrl != nil && *conf.TxWellKnownUrl != "" {
		wkClient := sa.getHTTPClientForWellKnownEndpoint(ctx, state)
		txConfig, err := wellKnownSupport.FetchSSFConfiguration(ctx, wkClient, *conf.TxWellKnownUrl)
		if err != nil {
			serverLog.Warn("RCV: failed to discover transmitter status_endpoint", "sid", conf.Id, "error", err)
			return ""
		}
		return txConfig.StatusEndpoint
	}
	return ""
}

// ExerciseReceiverManagement performs a one-shot, best-effort self-exercise of
// the transmitter's stream-management API against a receiver stream once it is
// established: read (GET), update (PATCH), replace (PUT) and status-update
// (POST status). It is gated by I2SIG_RCV_MANAGEMENT_EXERCISE (off by default)
// because a production receiver does not spontaneously mutate its own stream;
// the OpenID SSF receiver conformance plan (happypath, stream-status-update)
// requires the suite to observe these receiver-initiated calls.
//
// Every request is best-effort: any failure is logged and swallowed so the
// receiver keeps polling. Each request body carries only Receiver-Supplied
// properties plus the remote stream_id — Read-Only/transmitter-supplied
// properties are omitted, as strict transmitters reject them (SSF 1.0 §8.1.1.3,
// §8.1.1.4). Callers must invoke this OUTSIDE any in-flight long-poll window so
// the requests run sequentially and never race a concurrent poll at a
// single-threaded transmitter.
func (sa *SignalsApplication) ExerciseReceiverManagement(ctx context.Context, state *model.StreamStateRecord) {
	if !services.RcvManagementExerciseEnabled() {
		return
	}
	conf := state.StreamConfiguration
	if !(state.GetType() == model.ReceivePoll || state.GetType() == model.ReceivePush) {
		return
	}
	if conf.RemoteStreamId == nil || *conf.RemoteStreamId == "" {
		return
	}
	remoteId := *conf.RemoteStreamId

	configEndpoint := sa.resolveTransmitterConfigEndpoint(ctx, state)
	if configEndpoint == "" {
		serverLog.Warn("RCV: management exercise skipped — no transmitter configuration_endpoint", "sid", conf.Id)
		return
	}

	client, auth, closeClient, err := sa.getHTTPClientForStream(ctx, state)
	if err != nil {
		serverLog.Warn("RCV: management exercise skipped — client error", "sid", conf.Id, "error", err)
		return
	}
	defer closeClient()

	// 1. Read the stream configuration (SSF 1.0 §8.1.1.2 — stream_id as query param).
	readURL := goSsfUtils.AddStreamIdToUrl(configEndpoint, remoteId)
	sa.doReceiverManagementRequest(ctx, client, auth, http.MethodGet, readURL, nil, conf.Id, "read")

	// 2. Update the stream configuration (SSF 1.0 §8.1.1.3 — PATCH, Receiver-Supplied only).
	updateBody := map[string]any{
		"stream_id":   remoteId,
		"description": "i2goSignals receiver (management exercise: update)",
	}
	sa.doReceiverManagementRequest(ctx, client, auth, http.MethodPatch, configEndpoint, updateBody, conf.Id, "update")

	// 3. Replace the stream configuration (SSF 1.0 §8.1.1.4 — PUT, full Receiver-Supplied set).
	replaceBody := map[string]any{
		"stream_id":   remoteId,
		"description": "i2goSignals receiver (management exercise: replace)",
		"delivery":    receiverDeliveryBody(state),
	}
	if len(conf.EventsRequested) > 0 {
		replaceBody["events_requested"] = conf.EventsRequested
	}
	sa.doReceiverManagementRequest(ctx, client, auth, http.MethodPut, configEndpoint, replaceBody, conf.Id, "replace")

	// 4. Update the stream status (SSF 1.0 §8.1.2.2 — POST status). enabled→enabled
	// is a safe no-op transition that keeps the stream running.
	statusEndpoint := sa.resolveTransmitterStatusEndpoint(ctx, state)
	if statusEndpoint == "" {
		serverLog.Warn("RCV: management exercise — no transmitter status_endpoint, skipping status update", "sid", conf.Id)
		return
	}
	statusBody := map[string]any{
		"stream_id": remoteId,
		"status":    string(model.StreamStateEnabled),
		"reason":    "i2goSignals receiver (management exercise: status update)",
	}
	sa.doReceiverManagementRequest(ctx, client, auth, http.MethodPost, statusEndpoint, statusBody, conf.Id, "status-update")
}

// receiverDeliveryBody builds the Receiver-Supplied delivery sub-object for a
// replace request, expressed with the management-API (transmit-direction)
// method URN the transmitter expects, derived from the receiver's own delivery.
func receiverDeliveryBody(state *model.StreamStateRecord) map[string]any {
	if state.GetType() == model.ReceivePush && state.Delivery != nil && state.Delivery.PushReceiveMethod != nil {
		return map[string]any{
			"method":       model.DeliveryPush,
			"endpoint_url": state.Delivery.PushReceiveMethod.EndpointUrl,
		}
	}
	return map[string]any{"method": model.DeliveryPoll}
}

// doReceiverManagementRequest issues one best-effort management request to the
// transmitter and logs the outcome. A nil body sends no payload. The
// Authorization header is set only when an explicit token is supplied; for
// TxAlias/OAuth clients the returned http.Client injects credentials itself.
func (sa *SignalsApplication) doReceiverManagementRequest(ctx context.Context, client *http.Client, auth, method, url string, body map[string]any, sid, op string) {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			serverLog.Warn("RCV: management exercise — failed to marshal body", "sid", sid, "op", op, "error", err)
			return
		}
		reader = bytes.NewReader(raw)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, reader)
	if err != nil {
		serverLog.Warn("RCV: management exercise — request build failed", "sid", sid, "op", op, "error", err)
		return
	}
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := client.Do(req)
	if err != nil {
		serverLog.Warn("RCV: management exercise request failed", "sid", sid, "op", op, "error", err)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		serverLog.Warn("RCV: management exercise — unexpected transmitter status", "sid", sid, "op", op, "status", resp.StatusCode)
		return
	}
	serverLog.Info("RCV: management exercise step ok", "sid", sid, "op", op, "remote", url, "status", resp.StatusCode)
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
	return sa.handleClientPollReceiver(streamState)
}

func (sa *SignalsApplication) handleClientPollReceiver(streamState *model.StreamStateRecord) *ClientPollStream {
	ps, ok := sa.pollClients[streamState.StreamConfiguration.Id]
	if !ok {
		ctx, cancel := context.WithCancel(context.Background())

		ps = &ClientPollStream{
			sa:      sa,
			stream:  streamState,
			active:  true,
			running: true,
			ctx:     ctx,
			cancel:  cancel,
			done:    make(chan struct{}),
		}
		sa.pollClients[streamState.StreamConfiguration.Id] = ps
		pollUrl := streamState.Delivery.PollReceiveMethod.EndpointUrl
		serverLog.Info("POLL-RCV: Initialized poll receiver stream", "sid", streamState.StreamConfiguration.Id, "url", pollUrl)
		go ps.pollEventsReceiver()
		return ps
	}

	ps.mu.Lock()
	ps.stream = streamState
	// Revive whenever the goroutine isn't alive and the caller wants the stream to run.
	// Two paths reach here with a dead goroutine: (a) a prior terminal error set active=false
	// and the goroutine returned, (b) the goroutine exited via pollEventsReceiver's outer-loop
	// status check because the stream was Disabled at the time, leaving active=true but
	// running=false. The status flip back to non-Disable is what re-arms the receiver.
	needsRevive := !ps.running && streamState.Status != model.StreamStateDisable
	if needsRevive {
		// Cancel any lingering context from the previous goroutine before replacing.
		if ps.cancel != nil {
			ps.cancel()
		}
		ctx, cancel := context.WithCancel(context.Background())
		ps.ctx = ctx
		ps.cancel = cancel
		ps.active = true
		ps.running = true
		ps.done = make(chan struct{}) // fresh drain signal for the revived goroutine
	}
	ps.mu.Unlock()

	if needsRevive {
		serverLog.Info("POLL-RCV: Reviving inactive poll receiver", "sid", streamState.StreamConfiguration.Id, "status", streamState.Status)
		go ps.pollEventsReceiver()
	}
	return ps
}

func (sa *SignalsApplication) handleClientPushReceiver(streamState *model.StreamStateRecord) *ReceiverPushStream {
	ps, ok := sa.pushClients[streamState.StreamConfiguration.Id]
	if !ok {
		ctx, cancel := context.WithCancel(context.Background())

		ps = &ReceiverPushStream{
			sa:                       sa,
			stream:                   streamState,
			active:                   true,
			ctx:                      ctx,
			cancel:                   cancel,
			eventChan:                make(chan struct{}, 1),
			lastEventAt:              time.Now(),
			verifyOnEstablishPending: true,
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
	priorRemoteStreamId := ""
	if ps.stream != nil && ps.stream.StreamConfiguration.RemoteStreamId != nil {
		priorRemoteStreamId = *ps.stream.StreamConfiguration.RemoteStreamId
	}
	newRemoteStreamId := ""
	if streamState.StreamConfiguration.RemoteStreamId != nil {
		newRemoteStreamId = *streamState.StreamConfiguration.RemoteStreamId
	}
	ps.stream = streamState
	// Fire deferred verify-on-establish once the CLI back-patch persists a
	// non-empty RemoteStreamId. Prevents the original race where the very-first
	// verify went out with our local sid and got "Streams not found" from the
	// conformance suite.
	fireDeferredVerify := false
	if services.RcvVerifyOnEstablishEnabled() &&
		ps.verifyOnEstablishPending &&
		priorRemoteStreamId == "" &&
		newRemoteStreamId != "" {
		ps.verifyOnEstablishPending = false
		fireDeferredVerify = true
	}
	ps.mu.Unlock()
	if fireDeferredVerify {
		serverLog.Info("PUSH-RCV: Firing deferred verify-on-establish after RemoteStreamId arrival", "sid", streamState.StreamConfiguration.Id, "remote_sid", newRemoteStreamId)
		go ps.initiateVerification()
	}
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
			rps.sa.StreamService.UpdateStreamStatus(context.Background(), rps.stream.StreamConfiguration.Id, model.StreamStateEnabled, "")
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

	// Verify-on-establish (I2SIG_RCV_VERIFY_ON_ESTABLISH): one-shot /verify call
	// at stream startup so the OpenID SSF receiver conformance plan observes a
	// receiver-initiated verification before its 240s wait_for_state window.
	// Without this, the periodic ticker only fires verify after MinVerificationInterval
	// (default 300s). getVerifyEndpoint resolves through server registry, SSF
	// well-known, or status-URL transform — so we don't require ssfEnabled here;
	// initiateVerification early-returns harmlessly if no endpoint can be resolved.
	//
	// Gate the immediate fire on RemoteStreamId being non-empty: if the CLI
	// hasn't back-patched the publisher-assigned stream_id yet, firing now would
	// POST /verify quoting our local sid and the conformance suite would return
	// "Streams not found", invalidating its registration. We leave the
	// verifyOnEstablishPending flag set so handleClientPushReceiver fires the
	// verify once the back-patch arrives.
	if services.RcvVerifyOnEstablishEnabled() {
		rps.mu.RLock()
		remoteSid := ""
		if rps.stream.StreamConfiguration.RemoteStreamId != nil {
			remoteSid = *rps.stream.StreamConfiguration.RemoteStreamId
		}
		sid := rps.stream.StreamConfiguration.Id
		rps.mu.RUnlock()
		if remoteSid != "" {
			rps.mu.Lock()
			rps.verifyOnEstablishPending = false
			rps.mu.Unlock()
			go rps.initiateVerification()
		} else {
			serverLog.Info("PUSH-RCV: Deferring verify-on-establish until RemoteStreamId is back-patched", "sid", sid)
		}
	}

	for {
		select {
		case <-rps.ctx.Done():
			return
		case <-rps.eventChan:
			rps.mu.Lock()
			rps.lastEventAt = time.Now()

			// If we receive an event, the stream is active - ensure it's marked as enabled
			if rps.stream.Status != model.StreamStateEnabled || rps.stream.ErrorMsg != "" {
				rps.sa.StreamService.UpdateStreamStatus(context.Background(), rps.stream.StreamConfiguration.Id, model.StreamStateEnabled, "")
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

	state := ids.NewSecret()
	rps.mu.Lock()
	rps.verifying = true
	rps.verifyState = state
	rps.mu.Unlock()

	// The transmitter identifies the stream by its own (remote) stream_id.
	remoteId := rps.stream.StreamConfiguration.Id
	if rid := rps.stream.StreamConfiguration.RemoteStreamId; rid != nil && *rid != "" {
		remoteId = *rid
	}
	params := model.VerificationParameters{
		StreamId: remoteId,
		State:    state,
	}

	client, _, closeClient, err := rps.sa.getHTTPClientForStream(rps.ctx, rps.stream)
	if err != nil {
		serverLog.Error("PUSH-RCV: Failed to get authenticated client", "error", err)
		rps.fallbackToStatusCheck()
		return
	}
	defer closeClient()

	err = goSsfUtils.PostVerification(rps.ctx, client, verifyUrl, params)
	if err != nil {
		if err.Error() == "unauthorized" {
			serverLog.Warn("PUSH-RCV: Verification request unauthorized", "sid", rps.stream.StreamConfiguration.Id)
			return
		}
		serverLog.Warn("PUSH-RCV: Verification request failed", "error", err)
		rps.fallbackToStatusCheck()
		return
	}

	// Wait for the verification event, giving up after verificationWait. SleepCtx
	// stops its timer on the cancellation path, so a stream torn down seconds after
	// verification is requested does not hold a two-minute runtime timer.
	go func(vState string) {
		if !eventRouter.SleepCtx(rps.ctx, verificationWait) {
			return
		}
		rps.mu.Lock()
		if rps.verifying && rps.verifyState == vState {
			serverLog.Warn("PUSH-RCV: Verification event not received", "sid", rps.stream.StreamConfiguration.Id, "waited", verificationWait)
			rps.verifying = false
			rps.mu.Unlock()
			rps.fallbackToStatusCheck()
		} else {
			rps.mu.Unlock()
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

	// Using goSsfUtils if server is available
	server, _ := rps.sa.getServerForStream(rps.ctx, rps.stream)
	if server != nil {
		client := rps.sa.getHTTPClientForWellKnownEndpoint(rps.ctx, rps.stream)
		endpoint, err := goSsfUtils.GetVerificationEndpoint(rps.ctx, client, server)
		if err == nil && endpoint != "" {
			rps.verifyUrl = endpoint
			return rps.verifyUrl
		}
	}

	if rps.stream.StreamConfiguration.TxWellKnownUrl != nil && *rps.stream.StreamConfiguration.TxWellKnownUrl != "" {
		client := rps.sa.getHTTPClientForWellKnownEndpoint(rps.ctx, rps.stream)
		txConfig, err := wellKnownSupport.FetchSSFConfiguration(rps.ctx, client, *rps.stream.StreamConfiguration.TxWellKnownUrl)
		if err == nil && txConfig.VerificationEndpoint != "" {
			rps.verifyUrl = txConfig.VerificationEndpoint
			return rps.verifyUrl
		}
	}

	// Iss-derived discovery: when the receiver was registered without an
	// explicit TxWellKnownUrl or TxAlias (the conformance suite's emulated
	// transmitter never round-trips one), insert the well-known component
	// between the iss authority and path per RFC 8615 / SSF §7.2 and try a
	// direct SSF metadata fetch.
	if rps.stream.StreamConfiguration.Iss != "" {
		if wkUrl, err := wellKnownSupport.InsertWellKnownURL(rps.stream.StreamConfiguration.Iss, wellKnownSupport.SSFConfigurationPath); err == nil && wkUrl != "" {
			client := rps.sa.getHTTPClientForWellKnownEndpoint(rps.ctx, rps.stream)
			if txConfig, err := wellKnownSupport.FetchSSFConfiguration(rps.ctx, client, wkUrl); err == nil && txConfig.VerificationEndpoint != "" {
				rps.verifyUrl = txConfig.VerificationEndpoint
				return rps.verifyUrl
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

	// Remote calls must reference the TRANSMITTER's stream_id (remote_stream_id),
	// not our local id — they identify different streams on each side.
	remoteId := rps.stream.StreamConfiguration.Id
	if rid := rps.stream.StreamConfiguration.RemoteStreamId; rid != nil && *rid != "" {
		remoteId = *rid
	}

	// Using goSsfUtils if server is available
	server, _ := rps.sa.getServerForStream(rps.ctx, rps.stream)
	if server != nil {
		client := rps.sa.getHTTPClientForWellKnownEndpoint(rps.ctx, rps.stream)
		endpoint, err := goSsfUtils.GetStatusEndpoint(rps.ctx, client, server)
		if err == nil && endpoint != "" {
			rps.statusUrl = goSsfUtils.AddStreamIdToUrl(endpoint, remoteId)
			return rps.statusUrl
		}
	}

	if rps.stream.StreamConfiguration.TxWellKnownUrl != nil && *rps.stream.StreamConfiguration.TxWellKnownUrl != "" {
		client := rps.sa.getHTTPClientForWellKnownEndpoint(rps.ctx, rps.stream)
		txConfig, err := wellKnownSupport.FetchSSFConfiguration(rps.ctx, client, *rps.stream.StreamConfiguration.TxWellKnownUrl)
		if err == nil && txConfig.StatusEndpoint != "" {
			rps.statusUrl = goSsfUtils.AddStreamIdToUrl(txConfig.StatusEndpoint, remoteId)
			return rps.statusUrl
		}
	}

	// Iss-derived discovery (see getVerifyEndpoint for rationale).
	if rps.stream.StreamConfiguration.Iss != "" {
		if wkUrl, err := wellKnownSupport.InsertWellKnownURL(rps.stream.StreamConfiguration.Iss, wellKnownSupport.SSFConfigurationPath); err == nil && wkUrl != "" {
			client := rps.sa.getHTTPClientForWellKnownEndpoint(rps.ctx, rps.stream)
			if txConfig, err := wellKnownSupport.FetchSSFConfiguration(rps.ctx, client, wkUrl); err == nil && txConfig.StatusEndpoint != "" {
				rps.statusUrl = goSsfUtils.AddStreamIdToUrl(txConfig.StatusEndpoint, remoteId)
				return rps.statusUrl
			}
		}
	}
	return ""
}

func (rps *ReceiverPushStream) checkTransmitterStatus(ctx context.Context) (*model.StreamStatus, error) {
	server, _ := rps.sa.getServerForStream(ctx, rps.stream)
	client, _, closeClient, err := rps.sa.getHTTPClientForStream(ctx, rps.stream)
	if err != nil {
		return nil, err
	}
	defer closeClient()

	if server != nil {
		return goSsfUtils.GetStreamStatus(ctx, client, server, rps.stream.StreamConfiguration.Id)
	}

	statusUrl := rps.getStatusEndpoint()
	if statusUrl == "" {
		return nil, errors.New("could not determine status endpoint")
	}

	return goSsfUtils.GetResourceFromEndpoint[model.StreamStatus](ctx, client, statusUrl, rps.stream.StreamConfiguration.Id, "status check")
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
		rps.sa.StreamService.UpdateStreamStatus(context.Background(), rps.stream.StreamConfiguration.Id, status.Status, reason)
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

// StopGracefully asks the polling goroutine to stop WITHOUT cancelling its
// context, then waits up to timeout for it to exit. Because the context is left
// intact, an in-flight long-poll completes naturally instead of being torn
// mid-request — the loop only re-checks active between polls, so it exits once
// the current poll returns. This is used before a delete cascade so the receiver
// is not issuing a poll to the transmitter at the same moment the cascade hits
// it (a single-threaded transmitter would otherwise race the two requests).
// Returns true if the goroutine exited within the window; on timeout the caller
// should fall back to Close() to force-cancel.
func (ps *ClientPollStream) StopGracefully(timeout time.Duration) bool {
	ps.mu.Lock()
	if !ps.running {
		ps.mu.Unlock()
		return true
	}
	ps.active = false // stop issuing new polls; do NOT cancel so the in-flight poll drains
	done := ps.done
	ps.mu.Unlock()

	if done == nil {
		return false
	}
	select {
	case <-done:
		return true
	case <-time.After(timeout):
		return false
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
	if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
		return true
	}

	return false
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

	// Remote calls must reference the TRANSMITTER's stream_id (remote_stream_id),
	// not our local id — they identify different streams on each side.
	remoteId := ps.stream.StreamConfiguration.Id
	if rid := ps.stream.StreamConfiguration.RemoteStreamId; rid != nil && *rid != "" {
		remoteId = *rid
	}

	// Using goSsfUtils if server is available
	server, _ := ps.sa.getServerForStream(ps.ctx, ps.stream)
	if server != nil {
		client := ps.sa.getHTTPClientForWellKnownEndpoint(ps.ctx, ps.stream)
		endpoint, err := goSsfUtils.GetStatusEndpoint(ps.ctx, client, server)
		if err == nil && endpoint != "" {
			ps.statusUrl = goSsfUtils.AddStreamIdToUrl(endpoint, remoteId)
			return ps.statusUrl
		}
	}

	receiveMethod := ps.stream.Delivery.PollReceiveMethod
	if receiveMethod == nil {
		return ""
	}

	// Step a: Use TxWellKnownUrl if defined.
	if ps.stream.StreamConfiguration.TxWellKnownUrl != nil && *ps.stream.StreamConfiguration.TxWellKnownUrl != "" {
		client := ps.sa.getHTTPClientForWellKnownEndpoint(ps.ctx, ps.stream)
		txConfig, err := wellKnownSupport.FetchSSFConfiguration(ps.ctx, client, *ps.stream.StreamConfiguration.TxWellKnownUrl)
		if err == nil && txConfig.StatusEndpoint != "" {
			ps.statusUrl = goSsfUtils.AddStreamIdToUrl(txConfig.StatusEndpoint, remoteId)
			return ps.statusUrl
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

// getVerifyEndpoint resolves (and caches) the transmitter's verification endpoint
// for this polling receiver. Unlike the status endpoint the stream_id is NOT put
// in the URL — SSF 1.0 §8.1.4.2 carries it in the request body — so the bare
// endpoint is cached. Resolution mirrors getStatusEndpoint: a registered TxAlias
// server's discovered config first, else well-known discovery, else a fallback
// derived from the status endpoint by swapping the trailing /status for /verify.
func (ps *ClientPollStream) getVerifyEndpoint() string {
	ps.mu.RLock()
	if ps.verifyUrl != "" {
		ps.mu.RUnlock()
		return ps.verifyUrl
	}
	ps.mu.RUnlock()

	// Resolve WITHOUT holding ps.mu: the helpers below (getServerForStream,
	// well-known discovery, getStatusEndpoint) manage their own state/locks, and
	// getStatusEndpoint takes ps.mu itself — holding it here would deadlock.
	resolved := ""
	if server, _ := ps.sa.getServerForStream(ps.ctx, ps.stream); server != nil {
		client := ps.sa.getHTTPClientForWellKnownEndpoint(ps.ctx, ps.stream)
		if endpoint, err := goSsfUtils.GetVerificationEndpoint(ps.ctx, client, server); err == nil && endpoint != "" {
			resolved = endpoint
		}
	}

	if resolved == "" && ps.stream.StreamConfiguration.TxWellKnownUrl != nil && *ps.stream.StreamConfiguration.TxWellKnownUrl != "" {
		client := ps.sa.getHTTPClientForWellKnownEndpoint(ps.ctx, ps.stream)
		txConfig, err := wellKnownSupport.FetchSSFConfiguration(ps.ctx, client, *ps.stream.StreamConfiguration.TxWellKnownUrl)
		if err == nil && txConfig.VerificationEndpoint != "" {
			resolved = txConfig.VerificationEndpoint
		}
	}

	// Fallback: derive /verify from the resolved status endpoint, dropping the
	// stream_id query the status URL carries (it belongs in the verify body).
	if resolved == "" {
		if statusUrl := ps.getStatusEndpoint(); statusUrl != "" {
			if u, err := url.Parse(statusUrl); err == nil && strings.Contains(u.Path, "/status") {
				u.Path = strings.Replace(u.Path, "/status", "/verify", 1)
				u.RawQuery = ""
				resolved = u.String()
			}
		}
	}

	ps.mu.Lock()
	if ps.verifyUrl == "" {
		ps.verifyUrl = resolved
	}
	v := ps.verifyUrl
	ps.mu.Unlock()
	return v
}

// initiateVerification asks the transmitter to emit a verification event for this
// stream (SSF 1.0 §8.1.4.2). The resulting SET is delivered on a subsequent poll
// and handled by the normal inbound path. Best-effort: failures are logged and do
// not stop polling. Run once per goroutine, after the stream is confirmed enabled.
func (ps *ClientPollStream) initiateVerification() {
	if !services.RcvVerifyOnEstablishEnabled() {
		return
	}
	sid := ps.stream.StreamConfiguration.Id

	// The transmitter identifies the stream by its own (remote) stream_id.
	remoteId := sid
	if rid := ps.stream.StreamConfiguration.RemoteStreamId; rid != nil && *rid != "" {
		remoteId = *rid
	}

	verifyUrl := ps.getVerifyEndpoint()
	if verifyUrl == "" {
		serverLog.Warn("POLL-RCV: Could not determine verification endpoint", "sid", sid)
		return
	}

	client, _, closeClient, err := ps.sa.getHTTPClientForStream(ps.ctx, ps.stream)
	if err != nil {
		serverLog.Warn("POLL-RCV: Failed to get client for verification request", "sid", sid, "error", err)
		return
	}
	defer closeClient()

	params := model.VerificationParameters{
		StreamId: remoteId,
		State:    ids.NewSecret(),
	}
	if err := goSsfUtils.PostVerification(ps.ctx, client, verifyUrl, params); err != nil {
		serverLog.Warn("POLL-RCV: Verification request failed", "sid", sid, "error", err)
		return
	}
	serverLog.Info("POLL-RCV: Verification requested", "sid", sid, "remote", remoteId)
}

func (ps *ClientPollStream) checkTransmitterStatus(ctx context.Context) (*model.StreamStatus, error) {
	server, _ := ps.sa.getServerForStream(ctx, ps.stream)
	client, _, closeClient, err := ps.sa.getHTTPClientForStream(ctx, ps.stream)
	if err != nil {
		return nil, err
	}
	defer closeClient()

	if server != nil {
		return goSsfUtils.GetStreamStatus(ctx, client, server, ps.stream.StreamConfiguration.Id)
	}

	statusUrl := ps.getStatusEndpoint()
	if statusUrl == "" {
		return nil, errors.New("could not determine status endpoint")
	}

	return goSsfUtils.GetResourceFromEndpoint[model.StreamStatus](ctx, client, statusUrl, ps.stream.StreamConfiguration.Id, "status check")
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

			// Cancellable pause-probe delay. This is the top of a for loop that can
			// spin for the entire time a transmitter stays paused, so the wait must
			// not leave a timer behind on each iteration.
			if !eventRouter.SleepCtx(ctx, statusCheckInterval) {
				return false, ctx.Err()
			}
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
		}

		// Unknown status, fallback to enabled
		return true, nil
	}
}

// pollEventsReceiver manages the event polling process by acquiring a lease, running the poll loop, and handling cluster lease renewal.
func (ps *ClientPollStream) pollEventsReceiver() {
	sid := ps.stream.StreamConfiguration.Id
	resource := fmt.Sprintf("poll-receiver:%s", sid)

	defer func() {
		ps.mu.Lock()
		ps.running = false
		if ps.done != nil {
			close(ps.done) // wake any StopGracefully waiter: the in-flight poll has fully drained
		}
		ps.mu.Unlock()
	}()

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
		acquired, _, err := ps.sa.Coordinator.TryAcquireOrRenewLease(resource, ps.sa.NodeID, 30*time.Second)
		if ps.sa.Stats != nil {
			ps.sa.Stats.TrackLeaseAcquisition(resource, acquired && err == nil)
		}
		if err != nil {
			serverLog.Error("POLL-RCV: Lease acquisition error", "sid", sid, "error", err)
		}

		if !acquired {
			serverLog.Debug("POLL-RCV: Node lease not held, waiting...", "sid", sid)
			// Cancellable retry delay; a time.After here would arm a fresh runtime
			// timer on every spin of this loop and hold it to expiry after shutdown.
			if !eventRouter.SleepCtx(ps.ctx, leaseRetryDelay) {
				return
			}
			continue
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

	client, auth, closeClient, err := ps.sa.getHTTPClientForStream(ps.ctx, ps.stream)
	if err != nil {
		serverLog.Error("POLL-RCV: Failed to get authenticated client", "sid", sid, "error", err)
	}
	defer closeClient()

	if ps.stream.Delivery == nil || ps.stream.Delivery.PollReceiveMethod == nil {
		serverLog.Error("POLL-RCV: Missing delivery configuration", "sid", sid)
		return
	}
	receiveMethod := ps.stream.Delivery.PollReceiveMethod
	eventUrl := receiveMethod.EndpointUrl
	jwks := ps.sa.StreamService.GetIssuerJwksForReceiver(context.Background(), ps.stream.StreamConfiguration.Id)

	// Heartbeat for lease renewal
	heartbeatCtx, heartbeatCancel := context.WithCancel(ps.ctx)
	defer heartbeatCancel()

	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				ok, _, err := ps.sa.Coordinator.TryAcquireOrRenewLease(resource, ps.sa.NodeID, 30*time.Second)
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

	pollCfg := loadPollConfig()
	baseDelay := pollCfg.BaseDelay
	maxDelay := pollCfg.MaxDelay
	backoffFactor := pollCfg.BackoffFactor
	retryLimit := pollCfg.RetryLimit
	statusCheckInterval := pollCfg.StatusCheckInterval
	unauthorizedRetryDelay := pollCfg.UnauthorizedRetryDelay
	unauthorizedRetryLimit := pollCfg.UnauthorizedRetryLimit
	forbiddenRetryDelay := pollCfg.ForbiddenRetryDelay
	forbiddenRetryLimit := pollCfg.ForbiddenRetryLimit

	// Initial status check upon lease acquisition - verify that the transmitter is active
	if ok, _ := ps.handleTransmitterStatus(heartbeatCtx, statusCheckInterval); !ok {
		return
	}

	// Once the stream is established, optionally request a verification event from
	// the transmitter (SSF 1.0 §8.1.4.2) so the receiver confirms end-to-end
	// delivery. Gated by I2SIG_RCV_VERIFY_ON_ESTABLISH (off by default; the gate
	// lives in initiateVerification). One-shot per goroutine; the verification SET
	// arrives on a later poll and is processed by the normal inbound path.
	// Best-effort — never blocks polling.
	ps.mu.Lock()
	shouldVerify := !ps.verifyRequested
	ps.verifyRequested = true
	ps.mu.Unlock()
	if shouldVerify {
		ps.initiateVerification()
	}

	// Conformance-only (I2SIG_RCV_MANAGEMENT_EXERCISE): once per goroutine, drive a
	// read/update/replace/status-update round against the transmitter. Runs here,
	// in the pre-poll window before any long-poll is open, so the calls are
	// sequential and never race a concurrent poll at a single-threaded transmitter.
	ps.mu.Lock()
	shouldExercise := !ps.managementExercised
	ps.managementExercised = true
	ps.mu.Unlock()
	if shouldExercise {
		ps.sa.ExerciseReceiverManagement(ps.ctx, ps.stream)
	}

	retryCount := 0
	unauthorizedCount := 0
	forbiddenCount := 0
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
		var capturedPollAddr string
		pollTrace := &httptrace.ClientTrace{
			GotConn: func(info httptrace.GotConnInfo) {
				capturedPollAddr = info.Conn.RemoteAddr().String()
			},
		}
		tracedCtx := httptrace.WithClientTrace(heartbeatCtx, pollTrace)

		// Resolve this receiver's event_validation mode and engage the matching
		// validators (spec #247 #251). Re-resolved every iteration so an operator
		// changing the mode on a live stream takes effect on the next poll; under
		// NONE the validator set is nil and Poll takes exactly the pre-#247 path.
		validationMode := resolveReceiveValidationMode(ps.sa.StreamService, stream)
		validators := buildReceiveValidatorSet(stream, validationMode)

		parsed, httpStatus, err := goSetPoll.Poll(tracedCtx, pollReq, goSetPoll.ReceiverConfig{
			EndpointURL:       eventUrl,
			Authorization:     auth,
			HTTPClient:        client,
			JWKS:              jwks,
			ExpectedIssuer:    ps.stream.Iss,
			ExpectedAudiences: ps.stream.Aud,
			// Signing-only (#184): make verification of pulled SETs mandatory so a
			// nil JWKS rejects rather than silently accepting unsigned events.
			RequireSignature: ps.stream.SigningOnly,
			Validators:       validators,
		})

		if err != nil {
			if httpStatus == http.StatusUnauthorized {
				unauthorizedCount++
				if unauthorizedCount >= unauthorizedRetryLimit {
					errMsg := fmt.Sprintf("POLL-RCV[%s] Stream disabled after %d unauthorized attempts", sid, unauthorizedCount)
					ps.sa.updateStreamAfterError(sid, model.StreamStateDisable, errMsg)
					ps.mu.Lock()
					ps.active = false
					ps.mu.Unlock()
					return
				}

				delaySeconds := float64(unauthorizedRetryDelay) / float64(time.Second) * math.Pow(backoffFactor, float64(unauthorizedCount-1))
				if delaySeconds > maxDelay {
					delaySeconds = maxDelay
				}
				delay := time.Duration(delaySeconds * float64(time.Second))

				serverLog.Warn("POLL-RCV: Unauthorized response, retrying after delay", "sid", sid, "delay", delay, "attempt", unauthorizedCount)
				authMethod := "by client credential"
				if auth != "" {
					authMethod = "static token: " + maskAuthorization(auth)
				}
				serverLog.Debug("POLL-RCV: Authentication method", "sid", sid, "method", authMethod)
				ps.sa.pauseStreamOnError(sid, fmt.Sprintf("unauthorized response (401), retrying after %v delay (attempt %d)", delay, unauthorizedCount))
				// Cancellable backoff: the enclosing poll loop retries 401s until the
				// stream is disabled, so each iteration must not strand a timer.
				if !eventRouter.SleepCtx(heartbeatCtx, delay) {
					return
				}
				// Refresh the stream state to check if it's still enabled/active
				updatedStream, _ := ps.sa.StreamService.GetStreamState(context.Background(), sid)
				if updatedStream != nil {
					ps.mu.Lock()
					ps.stream = updatedStream
					ps.mu.Unlock()
				}
				// Refresh the client and auth header before retrying.
				// Close the old X509Source before creating a new one.
				closeClient()
				client, auth, closeClient, err = ps.sa.getHTTPClientForStream(ps.ctx, ps.stream)
				if err != nil {
					serverLog.Error("POLL-RCV: Failed to refresh client/auth after 401", "sid", sid, "error", err)
				}
				continue
			}

			if httpStatus == http.StatusForbidden {
				forbiddenCount++
				if forbiddenCount >= forbiddenRetryLimit {
					scopesDesc := ps.sa.describeRequestedScopes(ps.ctx, ps.stream)
					errMsg := fmt.Sprintf(
						"POLL-RCV[%s] Stream disabled after %d forbidden (403) attempts. "+
							"Transmitter rejected the token. Likely cause: OAuth client_credentials scope mismatch. "+
							"Requested scopes: %s. Required scope: '%s'.",
						sid, forbiddenCount, scopesDesc, authSupport.ScopeEventDelivery)
					ps.sa.updateStreamAfterError(sid, model.StreamStateDisable, errMsg)
					ps.mu.Lock()
					ps.active = false
					ps.mu.Unlock()
					return
				}

				delaySeconds := float64(forbiddenRetryDelay) / float64(time.Second) * math.Pow(backoffFactor, float64(forbiddenCount-1))
				if delaySeconds > maxDelay {
					delaySeconds = maxDelay
				}
				delay := time.Duration(delaySeconds * float64(time.Second))

				scopesDesc := ps.sa.describeRequestedScopes(ps.ctx, ps.stream)
				serverLog.Warn("POLL-RCV: Forbidden response, retrying after delay",
					"sid", sid, "delay", delay, "attempt", forbiddenCount, "limit", forbiddenRetryLimit,
					"requested_scopes", scopesDesc, "required_scope", authSupport.ScopeEventDelivery)
				ps.sa.pauseStreamOnError(sid,
					fmt.Sprintf("forbidden response (403), retrying after %v (attempt %d/%d). "+
						"Requested scopes: %s. Required scope: '%s'.",
						delay, forbiddenCount, forbiddenRetryLimit, scopesDesc, authSupport.ScopeEventDelivery))

				// Cancellable backoff — see the 401 path above.
				if !eventRouter.SleepCtx(heartbeatCtx, delay) {
					return
				}
				updatedStream, _ := ps.sa.StreamService.GetStreamState(context.Background(), sid)
				if updatedStream != nil {
					ps.mu.Lock()
					ps.stream = updatedStream
					ps.mu.Unlock()
				}
				closeClient()
				client, auth, closeClient, err = ps.sa.getHTTPClientForStream(ps.ctx, ps.stream)
				if err != nil {
					serverLog.Error("POLL-RCV: Failed to refresh client/auth after 403", "sid", sid, "error", err)
				}
				continue
			}

			if isConnectionError(err) || httpStatus == http.StatusServiceUnavailable {
				if firstErrorTime.IsZero() {
					firstErrorTime = time.Now()
				}
				serverLog.Warn("POLL-RCV: Polling connection error", "sid", sid, "error", err)
				if time.Since(firstErrorTime) > retryLimit {
					serverLog.Error("POLL-RCV: Exceeded retry limit, disabling stream", "sid", ps.stream.StreamConfiguration.Id, "elapsed", time.Since(firstErrorTime), "limit", retryLimit)
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

				// Cancellable backoff — see the 401 path above.
				if !eventRouter.SleepCtx(heartbeatCtx, delay) {
					return
				}
				retryCount++

				// Complement retry with transmitter status check - if status is not active, abort retry
				if ok, _ := ps.handleTransmitterStatus(heartbeatCtx, statusCheckInterval); !ok {
					return
				}

				// Refresh the stream state to check if it's still enabled/active
				updatedStream, _ := ps.sa.StreamService.GetStreamState(context.Background(), stream.StreamConfiguration.Id)
				if updatedStream != nil {
					ps.mu.Lock()
					ps.stream = updatedStream
					ps.mu.Unlock()
				}
				continue
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

		// Carry over the parse / iss / aud errors goSetPoll reported, to be sent
		// back in the next poll's setErrs. Merged rather than assigned so the
		// event_validation rejections added below are not clobbered.
		for jti, setErr := range parsed.Errors {
			setErrs[jti] = setErr
		}

		// Process successfully parsed and validated SETs
		for jti, token := range parsed.ParsedSETs {
			// Apply the stream's event_validation mode to the dispositions
			// goSetPoll computed (spec #247 #251). A rejected jti is reported in
			// setErrs with invalid_request and is never routed; other jtis in the
			// same batch still ack normally, because the decision is per-jti even
			// though it is whole-SET within a jti.
			//
			// It is ALSO acked. RFC8936 §2.4 keeps ack and setErrs separate and
			// leaves a transmitter free to keep an un-acked SET pending, so
			// reporting the error alone means a transmitter that does not read
			// setErrs as an acknowledgement re-delivers the same SET on every poll
			// forever — and with a bounded maxEvents or JTI-ordered service, the
			// poison SET occupies the batch every cycle and nothing behind it is
			// ever delivered. The stream livelocks while still reporting enabled.
			//
			// Acking it says "do not send this again", which is true: a payload
			// that fails validation fails identically on resend. The setErr is
			// what carries WHY, so the transmitter still learns the SET was
			// rejected rather than processed. This is the disposition the other
			// two transports already take — push clears a corroborated rejection,
			// SSTP maps invalid_request to Clear.
			if decision := applyEventValidation(validationMode, validationTransportPoll,
				ps.stream.StreamConfiguration.Id, jti, parsed.Validations[jti], ps.sa.Stats); decision.Reject {
				setErrs[jti] = goSetPoll.SetErrType{
					Error:       decision.ErrCode,
					Description: decision.Description,
				}
				acks = append(acks, jti)
				continue
			}

			serverLog.Debug("POLL-RCV: Handling Event", "sid", ps.stream.StreamConfiguration.Id, "jti", jti)
			err = ps.sa.EventRouter.HandleEvent(token, parsed.Sets[jti], ps.stream.StreamConfiguration.Id)
			if err != nil {
				serverLog.Error("POLL-RCV: Error handling event", "sid", ps.stream.StreamConfiguration.Id, "jti", jti, "error", err)
				// We don't acknowledge if we couldn't handle it
				continue
			}
			acks = append(acks, jti)
		}

		// Persist the resolved peer address on first connection or when it changes
		if capturedPollAddr != "" {
			endpointURL, _ := url.Parse(eventUrl)
			scheme := "http"
			if endpointURL != nil && endpointURL.Scheme != "" {
				scheme = endpointURL.Scheme
			}
			remoteIP := model.BuildOutboundRemoteIP(scheme, capturedPollAddr)
			ps.mu.RLock()
			currentRemote := ps.stream.RemoteAddress
			ps.mu.RUnlock()
			if !remoteIP.Equals(currentRemote) {
				serverLog.Debug("POLL-RCV: Remote address information", "sid", sid, "old", currentRemote.String(), "new", remoteIP.String())
				ps.sa.StreamService.UpdateRemoteAddress(context.Background(), sid, remoteIP)
				ps.mu.Lock()
				ps.stream.RemoteAddress = remoteIP
				ps.mu.Unlock()
			}
		}

		// Successful poll - reset retry count and error tracking
		retryCount = 0
		unauthorizedCount = 0
		firstErrorTime = time.Time{}
		ps.mu.RLock()
		needsUpdate := ps.stream.Status != model.StreamStateEnabled || ps.stream.ErrorMsg != ""
		ps.mu.RUnlock()
		if needsUpdate {
			ps.sa.StreamService.UpdateStreamStatus(context.Background(), sid, model.StreamStateEnabled, "")
			ps.mu.Lock()
			ps.stream.Status = model.StreamStateEnabled
			ps.stream.ErrorMsg = ""
			ps.mu.Unlock()
		}

		// If the last poll returned no events, add a small delay to avoid tight loops.
		// This provides a safety valve while maintaining high performance for actual event delivery.
		if setCnt == 0 && !parsed.MoreAvailable {
			// Runs on every empty poll, i.e. continuously on an idle stream. A
			// time.After here armed (and abandoned) a runtime timer ten times a
			// second per idle receiver stream.
			if !eventRouter.SleepCtx(heartbeatCtx, emptyPollBackoff) {
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

// ReceivePushEvent handles incoming Security Event Tokens (SETs) via HTTP Push (RFC8935).
//
// Inputs:
//   - id (path): The stream ID (captured by gorilla/mux, but auth context is used for validation).
//   - Authorization (header): Token with 'event_delivery' scope.
//   - Request body: Signed SET (JWT).
//
// Return values:
//   - 202 Accepted: SET successfully received and accepted.
//
// Errors:
//   - 401 Unauthorized: Authentication failed.
//   - 403 Forbidden: Access denied or missing stream ID.
//   - 404 Not Found: Stream not found.
//   - 400 Bad Request: Invalid request or SET parsing error.
func (sa *SignalsApplication) ReceivePushEvent(w http.ResponseWriter, r *http.Request) {
	ReceivePushEventHandler(sa, w, r)
}

func ReceivePushEventHandler(sa SsfApplicationInterface, w http.ResponseWriter, r *http.Request) {
	authContext, status := sa.GetAuth().ValidateAuthorizationAny(r, []string{authSupport.ScopeEventDelivery})
	if status != http.StatusOK || authContext == nil {
		// Bearer missing or invalid. Signing-only posture (#184): a business stream
		// may gate trust on the SET's JWS signature rather than a transport bearer, so
		// when NO bearer is presented we resolve the stream from the route's {id} and
		// fall through to the per-SET signature check below. A bearer that IS presented
		// must still pass the normal stream+scope check, so a presented-but-invalid
		// bearer is rejected here at the request level exactly as before.
		if sid, ok := resolveSigningOnlyPush(sa, r); ok {
			receivePushForStream(sa, w, r, sid)
			return
		}
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
	receivePushForStream(sa, w, r, sid)
}

// resolveSigningOnlyPush returns the path-addressed stream id when a push request is
// eligible for the signing-only posture (#184): no bearer was presented AND the stream
// named on the route ({id}) is signing-only. A presented bearer is never bypassed — it
// must pass the normal stream+scope check — so this returns ok=false whenever an
// Authorization header is present, leaving the caller to reject it at the request level.
func resolveSigningOnlyPush(sa SsfApplicationInterface, r *http.Request) (string, bool) {
	if r.Header.Get("Authorization") != "" {
		return "", false
	}
	pathId := mux.Vars(r)["id"]
	if pathId == "" {
		return "", false
	}
	st, err := sa.GetStreamService().GetStreamState(r.Context(), pathId)
	if err != nil || st == nil || !st.SigningOnly {
		return "", false
	}
	return pathId, true
}

// receivePushForStream runs the RFC8935 receive pipeline for an already-authorized
// stream: resolve state, refresh the peer address, parse+validate the SET, drive push
// monitoring/verification, and route the event. Under the stream's signing-only posture
// (#184) signature verification is mandatory (RequireSignature); otherwise the behavior
// is unchanged.
func receivePushForStream(sa SsfApplicationInterface, w http.ResponseWriter, r *http.Request, sid string) {
	streamState, err := sa.GetStreamService().GetStreamState(r.Context(), sid)
	if streamState == nil || err != nil {
		serverLog.Error("PUSH-RCV: Stream not found", "sid", sid)
		goSetPush.WriteDeliveryError(w, goSetPush.ErrNotFound, "Stream "+sid+" could not be located or was deleted")
		return
	}

	remoteIP := model.BuildRemoteIPFromRequest(r)
	if !remoteIP.Equals(streamState.RemoteAddress) {
		sa.GetStreamService().UpdateRemoteAddress(r.Context(), sid, remoteIP)
	}

	// Resolve this receiver's event_validation mode and engage the matching
	// validators (spec #247 #251). Under NONE the validator set is nil, so
	// ParseReceivedSET takes exactly the pre-#247 path.
	validationMode := resolveReceiveValidationMode(sa.GetStreamService(), streamState)
	validators := buildReceiveValidatorSet(streamState, validationMode)

	// Use goSetPush to handle RFC8935 protocol parsing and validation
	jwksKey := sa.GetStreamService().GetIssuerJwksForReceiver(r.Context(), sid)
	received, deliveryErr := goSetPush.ParseReceivedSET(r, goSetPush.ReceiverConfig{
		JWKS:              jwksKey,
		ExpectedIssuer:    streamState.Iss,
		ExpectedAudiences: streamState.Aud,
		RequireSignature:  streamState.SigningOnly,
		Validators:        validators,
	})
	if deliveryErr != nil {
		goSetPush.WriteDeliveryError(w, deliveryErr.ErrCode, deliveryErr.Description)
		return
	}

	// Apply the mode to the dispositions goSetPush computed. This sits between the
	// parse and everything downstream, so a rejected SET reaches neither the push
	// monitor nor the event router: HTTP 400 with an RFC8935 §2.4 invalid_request
	// body naming the event URI and failing claim, and nothing is routed.
	if decision := applyEventValidation(validationMode, validationTransportPush, sid,
		received.Token.ID, received.Validation, statsFor(sa)); decision.Reject {
		goSetPush.WriteDeliveryError(w, decision.ErrCode, decision.Description)
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
	sa.StreamService.UpdateStreamStatus(context.Background(), streamId, mode, reason)
}

func (sa *SignalsApplication) pauseStreamOnError(streamId string, errMsg string) {
	sa.StreamService.UpdateStreamStatus(context.Background(), streamId, model.StreamStatePause, errMsg)
	// TODO:  Update event router with stream state change??
}

// describeRequestedScopes returns a human-readable list of the OAuth scopes the
// stream's TxAlias server is configured to request via client_credentials. Used
// to surface scope-mismatch hints in stream error messages.
func (sa *SignalsApplication) describeRequestedScopes(ctx context.Context, stream *model.StreamStateRecord) string {
	if stream == nil || stream.StreamConfiguration.TxAlias == nil || *stream.StreamConfiguration.TxAlias == "" {
		return "(no TxAlias)"
	}
	server, err := sa.ServerService.GetServerByAlias(ctx, *stream.StreamConfiguration.TxAlias)
	if err != nil || server == nil {
		return "(server lookup failed)"
	}
	if server.OAuthClientConfig == nil {
		return "(not using OAuth client_credentials)"
	}
	if len(server.OAuthClientConfig.Scopes) == 0 {
		return "(none)"
	}
	return "[" + strings.Join(server.OAuthClientConfig.Scopes, ", ") + "]"
}
