package eventRouter

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/i2-open/i2goSignals/pkg/httpSupport"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/i2-open/i2goSignals/internal/eventRouter/buffer"
	"github.com/i2-open/i2goSignals/internal/providers/dbProviders"
	"github.com/i2-open/i2goSignals/pkg/authSupport"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/goSetPush"
	"github.com/i2-open/i2goSignals/pkg/logger"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/i2-open/i2goSignals/pkg/tlsSupport"
)

var eventLogger = logger.Sub("ROUTER")

type EventRouter interface {
	UpdateStreamState(stream *model.StreamStateRecord)
	RemoveStream(sid string)
	HandleEvent(eventToken *goSet.SecurityEventToken, rawEvent string, sid string) error
	//	PushStreamHandler(stream *model.StreamStateRecord, eventBuf *buffer.EventPushBuffer)
	PollStreamHandler(sid string, params model.PollParameters) (map[string]string, bool, int)
	Shutdown()
	SetEventCounter(inCounter, outCounter *prometheus.CounterVec)
	PreInitializeCounter(stream *model.StreamStateRecord)
	GetPushStreamCnt() float64
	GetPollStreamCnt() float64
	IncrementCounter(stream *model.StreamStateRecord, token *goSet.SecurityEventToken, inBound bool)
	SetStatsHandler(stats interface{})
	ResetStream(sid string)
	WakeTransmitter(sid string, mode string)
}

type router struct {
	mu                  sync.RWMutex
	pushStreams         map[string]model.StreamStateRecord // These are transmitters
	pollStreams         map[string]model.StreamStateRecord
	ctx                 context.Context
	cancel              context.CancelFunc
	enabled             bool
	nodeId              string
	issuerKeys          map[string]*rsa.PrivateKey
	issuerKids          map[string]string
	pollBuffers         map[string]*buffer.EventPollBuffer
	pushBuffers         map[string]*buffer.EventPushBuffer
	provider            dbProviders.DbProviderInterface
	eventsIn, eventsOut *prometheus.CounterVec
	stats               statsTracker

	httpClient          *http.Client
	clusterSecret       string
	recentOutboundWakes map[string]time.Time
	outboundWakesMu     sync.Mutex
	backfillInterval    time.Duration
	backfillBatch       int
	// x509Source is the SPIFFE X509Source used to build the SPIFFE mTLS transport
	// for inter-cluster calls. Non-nil only when SPIFFE_ENDPOINT_SOCKET is set.
	x509Source *workloadapi.X509Source
}

type statsTracker interface {
	TrackLeaseAcquisition(resource string, success bool)
	IncLeasesHeld()
	DecLeasesHeld()
}

func (r *router) GetPushStreamCnt() float64 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	eventLogger.Debug("GetPushStreamCnt request", "count", len(r.pushStreams))
	return float64(len(r.pushStreams))
}

func (r *router) GetPollStreamCnt() float64 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return float64(len(r.pollStreams))
}

func NewRouter(provider dbProviders.DbProviderInterface, nodeId string) EventRouter {
	ctx, cancel := context.WithCancel(context.Background())
	router := &router{
		provider:            provider,
		nodeId:              nodeId,
		pushStreams:         map[string]model.StreamStateRecord{},
		pollStreams:         map[string]model.StreamStateRecord{},
		pushBuffers:         map[string]*buffer.EventPushBuffer{},
		pollBuffers:         map[string]*buffer.EventPollBuffer{},
		issuerKeys:          map[string]*rsa.PrivateKey{},
		issuerKids:          map[string]string{},
		enabled:             false,
		ctx:                 context.WithValue(ctx, "provider", provider),
		cancel:              cancel,
		httpClient:          &http.Client{Timeout: 5 * time.Second},
		clusterSecret:       os.Getenv("I2SIG_CLUSTER_INTERNAL_TOKEN"),
		recentOutboundWakes: make(map[string]time.Time),
	}

	// When SPIFFE is configured, replace the plain HTTP client with one that
	// uses mutual TLS backed by the workload's X509-SVID. This allows inter-cluster
	// wake-up calls to authenticate via SPIFFE without the shared HMAC secret.
	if tlsSupport.SpiffeEnabled() {
		spiffeCtx, spiffeCancel := context.WithTimeout(ctx, 60*time.Second)
		x509Source, err := tlsSupport.NewX509Source(spiffeCtx)
		spiffeCancel()
		if err == nil {
			tlsCfg, cfgErr := tlsSupport.NewResilientMTLSClientConfig(x509Source)
			if cfgErr == nil {
				router.httpClient = &http.Client{
					Timeout:   5 * time.Second,
					Transport: &http.Transport{TLSClientConfig: tlsCfg},
				}
				router.x509Source = x509Source
				eventLogger.Info("ROUTER: Resilient SPIFFE mTLS enabled for inter-cluster communication")
			} else {
				_ = x509Source.Close()
				eventLogger.Warn("ROUTER: Resilient SPIFFE config invalid; using HMAC-only", "err", cfgErr)
			}
		} else {
			eventLogger.Warn("ROUTER: SPIFFE configured but X509Source failed; using HMAC-only", "err", err)
		}
	}

	backfillInterval := 1 * time.Second
	if val := os.Getenv("I2SIG_TRANSMITTER_BACKFILL_INTERVAL"); val != "" {
		if d, err := time.ParseDuration(val); err == nil {
			backfillInterval = d
		}
	}
	router.backfillInterval = backfillInterval

	backfillBatch := 100
	if val := os.Getenv("I2SIG_TRANSMITTER_BACKFILL_BATCH"); val != "" {
		if i, err := strconv.Atoi(val); err == nil {
			backfillBatch = i
		}
	}
	router.backfillBatch = backfillBatch

	states := router.provider.GetStateMap()

	for k, state := range states {
		eventLogger.Info("Initializing", "streamKey", k, "configId", state.StreamConfiguration.Id)
		router.UpdateStreamState(&state)
	}
	router.enabled = true

	// Start the background watcher if explicitly enabled
	if os.Getenv("I2SIG_MONGO_WATCH_ENABLED") == "true" {
		eventLogger.Info("Background watcher enabled via I2SIG_MONGO_WATCH_ENABLED")
		go router.provider.WatchPending(ctx, func(jti string, streamId bson.ObjectID) {
			sid := streamId.Hex()
			router.mu.RLock()
			pollBuf, pollOk := router.pollBuffers[sid]
			pushBuf, pushOk := router.pushBuffers[sid]
			router.mu.RUnlock()

			if pollOk {
				eventLogger.Debug("Background watcher: submitting event to poll buffer", "sid", sid, "jti", jti)
				pollBuf.SubmitEvent(jti)
			}
			if pushOk {
				eventLogger.Debug("Background watcher: submitting event to push buffer", "sid", sid, "jti", jti)
				pushBuf.SubmitEvent(jti)
			}
		})
	} else {
		eventLogger.Info("Background watcher disabled (using wake-up calls and backfill)")
	}

	return router
}

func (r *router) ResetStream(sid string) {
	r.mu.RLock()
	buf, ok := r.pollBuffers[sid]
	r.mu.RUnlock()
	if ok {
		buf.Clear()
	}
	_ = r.provider.ClearPending(sid)
}

func (r *router) WakeTransmitter(sid string, mode string) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if mode == "push" {
		if buf, ok := r.pushBuffers[sid]; ok {
			eventLogger.Debug("Waking push transmitter", "sid", sid)
			buf.Wakeup()
		}
	} else if mode == "poll" {
		if buf, ok := r.pollBuffers[sid]; ok {
			eventLogger.Debug("Waking poll transmitter", "sid", sid)
			buf.Wakeup()
		}
	}
}

func (r *router) IncrementCounter(stream *model.StreamStateRecord, token *goSet.SecurityEventToken, inBound bool) {
	/*
			Note:  Because the event router must initialize before the server is initialized, the
		    event counter cannot be initialized immediately. To avoid a who goes first conflict,
			the counter may briefly be nil during startup.

		    TODO:  Should the incrementer wait until r.eventsOut is not nil?  This will block the outbound stream
	*/
	r.mu.RLock()
	eventsOut := r.eventsOut
	eventsIn := r.eventsIn
	r.mu.RUnlock()

	if eventsOut == nil {
		eventLogger.Warn("events counter not initialized")
		return
	}
	dir := "Out"
	if inBound {
		dir = "In"
	}

	tfr := "PUSH"
	switch stream.GetType() {
	case model.DeliveryPoll, model.ReceivePoll:
		tfr = "POLL"
	}

	eventTypes := "UNSET"
	if token != nil {
		types := token.GetEventIds()
		if len(types) > 0 {
			eventTypes = types[0]
			if len(types) > 1 {
				for i := 1; i < len(types); i++ {
					eventTypes = eventTypes + "," + types[i]
				}
			}
		}
	}

	eventLogger.Info("Event counter incremented", "dir", dir, "sid", stream.StreamConfiguration.Id, "tfr", tfr, "types", eventTypes)
	if dir == "In" {
		eventLogger.Debug("Inbound token", "token", token.String())
	}
	tokenIssuer := ""
	if token != nil {
		tokenIssuer = token.Issuer
	}
	label := prometheus.Labels{
		"type":      eventTypes,
		"iss":       tokenIssuer,
		"tfr":       tfr,
		"stream_id": stream.StreamConfiguration.Id,
	}

	isOut := true
	if inBound {
		isOut = false
	}
	if isOut {
		m := eventsOut.With(label)
		m.Inc()
	} else {
		m := eventsIn.With(label)
		m.Inc()
	}
}

func (r *router) SetEventCounter(inCounter, outCounter *prometheus.CounterVec) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.eventsOut = outCounter
	r.eventsIn = inCounter
}

func (r *router) SetStatsHandler(stats interface{}) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if s, ok := stats.(statsTracker); ok {
		r.stats = s
	}
}

func (r *router) PreInitializeCounter(stream *model.StreamStateRecord) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	r.preInitializeCounterLocked(stream)
}

func (r *router) preInitializeCounterLocked(stream *model.StreamStateRecord) {
	eventsOut := r.eventsOut
	eventsIn := r.eventsIn

	if eventsOut == nil || eventsIn == nil {
		return
	}

	tfr := "PUSH"
	switch stream.GetType() {
	case model.DeliveryPoll, model.ReceivePoll:
		tfr = "POLL"
	}

	iss := stream.StreamConfiguration.Iss
	if iss == "" {
		iss = "DEFAULT"
	}

	// For pre-initialization, we don't know the event type yet, but we can initialize
	// the counter with "UNKNOWN" or just wait for the first event.
	// Actually, the user wants to see the metric. If we initialize it with a specific label set,
	// it will show up.
	labels := prometheus.Labels{
		"type":      "NONE",
		"iss":       iss,
		"tfr":       tfr,
		"stream_id": stream.StreamConfiguration.Id,
	}

	eventsIn.With(labels).Add(0)
	eventsOut.With(labels).Add(0)
}

func (r *router) checkAndLoadKey(streamID string, issuer string) (*rsa.PrivateKey, string) {
	r.mu.RLock()
	key, ok := r.issuerKeys[issuer]
	kid := r.issuerKids[issuer]
	r.mu.RUnlock()
	if !ok {
		r.mu.Lock()
		// Double check
		key, ok = r.issuerKeys[issuer]
		if !ok {
			var err error
			key, kid, err = r.provider.GetPrivateKeyWithKid(issuer)
			if err != nil {
				eventLogger.Warn("Unable to locate key for issuer, retrying...", "streamID", streamID, "issuer", issuer)
				r.mu.Unlock()
				return nil, ""
			}
			copyKey := *key
			r.issuerKeys[issuer] = &copyKey
			r.issuerKids[issuer] = kid
		}
		r.mu.Unlock()
	}
	return key, kid
}

func (r *router) UpdateStreamState(stream *model.StreamStateRecord) {
	if stream == nil {
		return
	}

	if stream.StreamConfiguration.Id != "" && stream.IsReceiver() {
		// TODO WHY are we not updating stream state?
		return
	}

	// Preload the issuer keys to avoid necessary provider lookups
	issuer := stream.StreamConfiguration.Iss
	if issuer != "" {
		if stream.StreamConfiguration.Id == "" || stream.GetRouteMode() == model.RouteModePublish || stream.GetRouteMode() == "" {
			r.checkAndLoadKey(stream.StreamConfiguration.Id, issuer)
		}
	}

	if stream.StreamConfiguration.Id == "" {
		// This might be a partial update (e.g. from rotateIssuer)
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if stream.StreamConfiguration.Delivery.GetMethod() == model.DeliveryPoll {
		r.preInitializeCounterLocked(stream)

		currentState, ok := r.pollStreams[stream.StreamConfiguration.Id]

		if ok {
			eventLogger.Debug("Syncing stream state", "sid", currentState.StreamConfiguration.Id)
			oldStatus := currentState.Status
			currentState.Update(stream)
			r.pollStreams[stream.StreamConfiguration.Id] = currentState
			if (currentState.Status == model.StreamStatePause || currentState.Status == model.StreamStateDisable) && oldStatus == model.StreamStateEnabled {
				if pb, ok := r.pollBuffers[stream.StreamConfiguration.Id]; ok {
					pb.Wakeup() // This will cause current long poll sessions to end
				}
			}
		} else {
			eventLogger.Info("Adding stream to Pollers", "sid", stream.StreamConfiguration.Id)
			r.pollStreams[stream.StreamConfiguration.Id] = *stream
		}
		_, ok = r.pollBuffers[stream.StreamConfiguration.Id]
		if !ok {
			// Preload any outstanding pending events (because we may be re-starting)
			// We release the lock for provider call
			r.mu.Unlock()
			jtis, _ := r.provider.GetEventIds(stream.StreamConfiguration.Id, model.PollParameters{
				MaxEvents:         0,
				ReturnImmediately: true,
				Acks:              nil,
				SetErrs:           nil,
				TimeoutSecs:       10,
			})
			r.mu.Lock()
			// TODO:  might have to check for existing events!
			r.pollBuffers[stream.StreamConfiguration.Id] = buffer.CreateEventPollBuffer(jtis)
		}
		return
	}
	// The stream is delivery PUSH
	r.preInitializeCounterLocked(stream)

	currentState, ok := r.pushStreams[stream.StreamConfiguration.Id]
	if ok {
		currentState.Update(stream)
		r.pushStreams[stream.StreamConfiguration.Id] = currentState
	} else {
		// preload the buffer with any existing events
		// We release the lock for provider call
		r.mu.Unlock()
		jtis, _ := r.provider.GetEventIds(stream.StreamConfiguration.Id, model.PollParameters{
			MaxEvents:         0,
			ReturnImmediately: true,
			Acks:              nil,
			SetErrs:           nil,
			TimeoutSecs:       10,
		})
		r.mu.Lock()
		r.pushStreams[stream.StreamConfiguration.Id] = *stream
		r.initPushStreamLocked(stream.StreamConfiguration.Id, stream, jtis)
	}

}

func (r *router) initPushStreamLocked(sid string, state *model.StreamStateRecord, jtis []string) {
	pushBuffer := buffer.CreateEventPushBuffer(jtis)
	r.pushBuffers[sid] = pushBuffer
	go r.PushStreamHandler(state, pushBuffer)
}

/*
HandleEvent takes a new event received and adds it to the local token store. It then looks at the event to
evaluates if it should be added to any streams for outgoing propagation
*/
func (r *router) HandleEvent(eventToken *goSet.SecurityEventToken, rawEvent string, sid string) error {
	// eventLogger.Println("\n", event.Event.String())

	streamState, err := r.provider.GetStreamState(sid)
	if err != nil {
		return err
	}

	event, err := r.provider.AddEvent(eventToken, sid, rawEvent)
	if err != nil {
		return err
	}
	r.IncrementCounter(streamState, eventToken, true)

	if (streamState != nil && streamState.IsReceiver()) && streamState.GetRouteMode() == model.RouteModeImport {
		// nothing more to do
		return nil
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	// Check to see if the event should be routed to outbound push streams
	for _, stream := range r.pushStreams {
		if StreamEventMatch(&stream, event) {

			eventLogger.Info("ROUTER: Selected", "sid", stream.StreamConfiguration.Id, "jti", event.Jti, "mode", "PUSH", "types", event.Types)

			// The transmitter API will forward or sign/encrypt the event based on route mode at delivery time!
			err = r.provider.AddEventToStream(event.Jti, stream.Id)
			if err != nil {
				eventLogger.Error("ROUTER: Error adding event to push stream", "sid", stream.StreamConfiguration.Id, "jti", event.Jti, "error", err)
			}

			// Lease-aware routing
			resource := fmt.Sprintf("push-transmitter:%s", stream.StreamConfiguration.Id)
			ownerNodeId, _, _, _ := r.provider.GetLeaseOwner(resource)

			if ownerNodeId == "" || ownerNodeId == r.nodeId {
				// Local owner or no owner (we'll try to take it or backfill will find it)
				r.pushBuffers[stream.StreamConfiguration.Id].SubmitEvent(event.Jti)
			} else {
				// Remote owner, send wake-up
				go r.sendWakeup(stream.StreamConfiguration.Id, "push", ownerNodeId)
			}
		}
	}

	// Check to see if the event should be routed to outbound polling stream
	for k, pollStream := range r.pollStreams {
		eventLogger.Debug("ROUTER: Checking stream", "sid", k)

		if StreamEventMatch(&pollStream, event) {
			eventLogger.Info("ROUTER: Selected", "sid", pollStream.StreamConfiguration.Id, "jti", event.Jti, "mode", "POLL", "types", event.Types)

			// The transmitter API will forward or sign/encrypt the event based on route mode at delivery time!
			err = r.provider.AddEventToStream(event.Jti, pollStream.Id)
			if err != nil {
				eventLogger.Error("ROUTER: Error adding event to poll stream", "sid", pollStream.StreamConfiguration.Id, "jti", event.Jti, "error", err)
			}
			// For poll streams, every node serving a long poll should be woken up.
			// Since we don't have a transmitter lease for poll, we just submit locally.
			// Ideally we'd broadcast to all nodes, but let's start with local.
			r.pollBuffers[pollStream.StreamConfiguration.Id].SubmitEvent(event.Jti)
		}
	}
	return nil
}

func (r *router) sendWakeup(sid, mode, ownerNodeId string) {
	// Rate limiting / Coalescing
	key := sid + ":" + mode
	r.outboundWakesMu.Lock()
	lastWake, exists := r.recentOutboundWakes[key]
	if exists && time.Since(lastWake) < 250*time.Millisecond {
		r.outboundWakesMu.Unlock()
		return
	}
	r.recentOutboundWakes[key] = time.Now()
	r.outboundWakesMu.Unlock()

	node, err := r.provider.GetNode(ownerNodeId)
	if err != nil || node == nil {
		eventLogger.Error("ROUTER: Error getting node info for wake-up", "nodeId", ownerNodeId, "error", err)
		return
	}

	if node.Address == "" {
		eventLogger.Warn("ROUTER: Node address empty, cannot send wake-up", "nodeId", ownerNodeId)
		return
	}

	r.callWakeupAPI(node.Address, sid, mode)
}

func (r *router) callWakeupAPI(address, sid, mode string) {
	url := strings.TrimSuffix(address, "/") + "/_cluster/wake-transmitter"

	reqBody, _ := json.Marshal(map[string]string{
		"sid":  sid,
		"mode": mode,
	})

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(reqBody))
	if err != nil {
		eventLogger.Error("ROUTER: Error creating wake-up request", "url", url, "error", err)
		return
	}

	token := authSupport.GenerateClusterToken(r.clusterSecret, sid, mode)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		eventLogger.Error("ROUTER: Wake-up call failed", "url", url, "error", err)
		return
	}

	defer httpSupport.HandleRespClose(resp)

	if resp.StatusCode != http.StatusAccepted {
		eventLogger.Warn("ROUTER: Wake-up call rejected", "url", url, "status", resp.Status)
	} else {
		eventLogger.Debug("ROUTER: Wake-up call successful", "url", url, "sid", sid)
	}
}

func (r *router) PollStreamHandler(sid string, params model.PollParameters) (map[string]string, bool, int) {
	r.mu.RLock()
	state, exist := r.pollStreams[sid]
	pollBuffer, bufExist := r.pollBuffers[sid]
	r.mu.RUnlock()

	if !exist || !bufExist {
		eventLogger.Error("POLL-SRV: Error Poll Transmitter not found", "sid", sid)
		return nil, false, http.StatusNotFound
	}

	if len(params.Acks) > 0 {
		pollBuffer.AckEvents(params.Acks)
		for _, jti := range params.Acks {
			_ = r.provider.AckEvent(jti, sid, 0)
		}
	}

	if len(params.SetErrs) > 0 {
		jtis := make([]string, 0, len(params.SetErrs))
		for jti := range params.SetErrs {
			jtis = append(jtis, jti)
		}
		pollBuffer.AckEvents(jtis)
		for _, jti := range jtis {
			_ = r.provider.AckEvent(jti, sid, 0)
		}
	}

	if state.Status != model.StreamStateEnabled {
		if (state.Status == model.StreamStatePause || state.Status == model.StreamStateDisable) && (len(params.Acks) > 0 || len(params.SetErrs) > 0) {
			return map[string]string{}, false, http.StatusOK
		}
		stateString, _ := json.MarshalIndent(&state, "", "  ")
		eventLogger.Debug("Stream State", "state", string(stateString))
		eventLogger.Error("POLL-SRV: Error Poll request but stream is not active", "sid", sid)
		return nil, false, http.StatusConflict
	}

	// Opportunistically prefetch pending JTIs if the buffer is empty
	if pollBuffer.Cnt() == 0 {
		jtis, _ := r.provider.GetEventIds(sid, model.PollParameters{
			MaxEvents:         int32(r.backfillBatch),
			ReturnImmediately: true,
		})
		if len(jtis) > 0 {
			eventLogger.Debug("POLL-SRV: Prefetched events", "sid", sid, "count", len(jtis))
			pollBuffer.SubmitEvents(jtis)
		}
	}

	var key *rsa.PrivateKey
	var kid string
	forwardMode := false
	if state.GetRouteMode() == model.RouteModeForward {
		forwardMode = true
	} else {
		key, kid = r.checkAndLoadKey(sid, state.StreamConfiguration.Iss)
	}

	/*
		if (key == nil) && !forwardMode {
			eventLogger.Printf("POLL-SRV[%s] WARNING: no issuer key available for %s", sid, state.StreamConfiguration.Iss)
			return nil, false, http.StatusConflict
		}
	*/

	jtiSlice, more := pollBuffer.GetEvents(params)

	jtiSize := 0
	if jtiSlice != nil {
		jtiSize = len(*jtiSlice)
	}

	var err error
	if jtiSize > 0 {
		sets := make(map[string]string, jtiSize)
		if forwardMode {
			jtis := *jtiSlice
			for _, jti := range jtis {
				eventRecord := r.provider.GetEventRecord(jti)
				if eventRecord == nil {
					eventLogger.Warn("POLL-SRV: JTI Not found", "sid", sid, "jti", jti)
					continue
				}
				sets[jti] = eventRecord.Original
			}
		} else {
			tokens := r.provider.GetEvents(*jtiSlice)
			for _, token := range tokens {
				token.Issuer = state.StreamConfiguration.Iss
				token.Audience = state.StreamConfiguration.Aud
				token.IssuedAt = jwt.NewNumericDate(time.Now())
				token.Kid = kid

				sets[token.ID], err = token.JWS(jwt.SigningMethodRS256, key)
				if err != nil {
					eventLogger.Error("POLL-SRV: Error signing", "sid", sid, "error", err)
				}
			}
		}
		return sets, more, http.StatusOK
	}
	return map[string]string{}, false, http.StatusOK
}

// PushStreamHandler manages the lifecycle of a push stream, including lease handling and event transmission.
func (r *router) PushStreamHandler(stream *model.StreamStateRecord, eventBuf *buffer.EventPushBuffer) {
	sid := stream.StreamConfiguration.Id
	resource := fmt.Sprintf("push-transmitter:%s", sid)

	for {
		if stream.Status != model.StreamStateEnabled {
			eventLogger.Info("PUSH-SRV is no longer enabled. PushHandler exiting.", "sid", sid)
			return
		}

		// Attempt to acquire or renew the lease
		acquired, fencingToken, err := r.provider.TryAcquireOrRenewLease(resource, r.nodeId, 30*time.Second)
		if r.stats != nil {
			r.stats.TrackLeaseAcquisition(resource, acquired && err == nil)
		}
		if err != nil {
			eventLogger.Error("PUSH-SRV: Node lease acquisition error", "sid", sid, "error", err)
		}

		if !acquired {
			eventLogger.Debug("PUSH-SRV: Node lease not held, waiting...", "sid", sid)
			select {
			case <-time.After(15 * time.Second): // Retry after 15s
				continue
			case <-r.ctx.Done():
				return
			}
		}

		// Lease acquired, start the actual push loop
		eventLogger.Info("PUSH-SRV: Node lease acquired, starting transmission", "sid", sid)
		shouldRetry := r.runPushLoop(resource, stream, eventBuf, fencingToken)
		if !shouldRetry {
			return
		}

		// Check if we should exit entirely
		select {
		case <-r.ctx.Done():
			return
		default:
			// Loop back to try and re-acquire if runPushLoop exited for some reason
		}
	}
}

// runPushLoop handles the event push loop for a given stream, including lease renewal and event processing.
func (r *router) runPushLoop(resource string, stream *model.StreamStateRecord, eventBuf *buffer.EventPushBuffer, fencingToken int64) bool {
	sid := stream.StreamConfiguration.Id
	eventLogger.Info("PUSH-SRV: Starting transmission loop", "sid", sid)
	if r.stats != nil {
		r.stats.IncLeasesHeld()
		defer r.stats.DecLeasesHeld()
	}

	var rsaKey *rsa.PrivateKey
	var kid string
	if stream.GetRouteMode() == model.RouteModePublish {
		rsaKey, kid = r.checkAndLoadKey(stream.StreamConfiguration.Id, stream.Iss)
		if rsaKey == nil {
			eventLogger.Warn("PUSH-SRV: no issuer key available", "sid", sid, "issuer", stream.StreamConfiguration.Iss)
		}
	}

	// Heartbeat for lease renewal
	heartbeatCtx, heartbeatCancel := context.WithCancel(r.ctx)
	defer heartbeatCancel()

	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				ok, _, err := r.provider.TryAcquireOrRenewLease(resource, r.nodeId, 30*time.Second)
				if r.stats != nil {
					r.stats.TrackLeaseAcquisition(resource, ok && err == nil)
				}
				if err != nil || !ok {
					eventLogger.Warn("PUSH-SRV: Node lease lost or renewal failed", "sid", sid)
					heartbeatCancel()
					return
				}
			case <-heartbeatCtx.Done():
				return
			}
		}
	}()

	backfillTicker := time.NewTicker(r.backfillInterval)
	defer backfillTicker.Stop()

	out := eventBuf.Out
	wakeup := eventBuf.WakeupCh()

	for {
		select {
		case <-heartbeatCtx.Done():
			return true // Heartbeat lost, but should try to re-acquire
		case v, ok := <-out:
			if !ok {
				return false // Buffer closed, stop entirely
			}
			jti := v.(string)
			r.prepareAndSendEvent(jti, stream, rsaKey, kid, fencingToken)
			if stream.Status != model.StreamStateEnabled {
				eventLogger.Info("PUSH-SRV is no longer active. PushHandler exiting.", "sid", stream.Id.Hex())
				return false
			}
		case <-backfillTicker.C:
			r.backfillPushBuffer(sid, eventBuf)
		case <-wakeup:
			eventLogger.Debug("PUSH-SRV: Wake-up received, triggering backfill", "sid", sid)
			r.backfillPushBuffer(sid, eventBuf)
		}
	}
}

func (r *router) backfillPushBuffer(sid string, eventBuf *buffer.EventPushBuffer) {
	if eventBuf.Cnt() > 0 {
		return
	}

	jtis, _ := r.provider.GetEventIds(sid, model.PollParameters{
		MaxEvents:         int32(r.backfillBatch),
		ReturnImmediately: true,
	})

	if len(jtis) > 0 {
		eventLogger.Debug("PUSH-SRV: Backfill found pending events", "sid", sid, "count", len(jtis))
		eventBuf.SubmitEvents(jtis)
	}
}

func (r *router) prepareAndSendEvent(jti string, config *model.StreamStateRecord, rsaKey *rsa.PrivateKey, kid string, fencingToken int64) {
	eventRecord := r.provider.GetEventRecord(jti)
	// Get the event
	if eventRecord != nil {

		delivered := r.pushEvent(config.StreamConfiguration, eventRecord, rsaKey, kid)
		if delivered {
			err := r.provider.AckEvent(jti, config.StreamConfiguration.Id, fencingToken)
			if err != nil {
				eventLogger.Error("PUSH-SRV: Error acking event", "sid", config.StreamConfiguration.Id, "jti", jti, "error", err)
			}
			r.IncrementCounter(config, &eventRecord.Event, false)
		}
	}
}

// pushEvent implements the server push side (http client) of RFC8935 Push Based Delivery of SET Events
// Note: Moved from the api_transmitter.go in server package
func (r *router) pushEvent(configuration model.StreamConfiguration, event *model.EventRecord, key *rsa.PrivateKey, kid string) bool {
	pushConfig := configuration.Delivery.PushTransmitMethod

	// Prepare the token string (application-layer: signing or forwarding)
	var tokenString string
	if configuration.RouteMode == model.RouteModeForward {
		tokenString = event.Original // In forward mode, we just pass on the raw event
	} else {
		token := &event.Event
		token.Issuer = configuration.Iss
		token.Audience = configuration.Aud
		token.IssuedAt = jwt.NewNumericDate(time.Now())
		token.Kid = kid
		var err error
		tokenString, err = token.JWS(jwt.SigningMethodRS256, key)
		if err != nil {
			eventLogger.Error("PUSH-SRV: Error signing event", "sid", configuration.Id, "error", err)
		}
	}

	// Use goSetPush for the RFC8935 wire protocol
	result := goSetPush.PushSET(context.Background(), tokenString, goSetPush.TransmitterConfig{
		EndpointURL:   pushConfig.EndpointUrl,
		Authorization: pushConfig.AuthorizationHeader,
	})

	if !result.Accepted {
		if result.Err != nil {
			var deliveryErr *goSetPush.DeliveryErr
			if errors.As(result.Err, &deliveryErr) {
				errMsg := fmt.Sprintf("PUSH-SRV[%s] %s", deliveryErr.ErrCode, deliveryErr.Description)
				eventLogger.Error("PUSH-SRV: Push failed", "sid", configuration.Id, "code", deliveryErr.ErrCode, "desc", deliveryErr.Description)
				r.provider.UpdateStreamStatus(configuration.Id, model.StreamStatePause, errMsg)
			}
		}
		return false
	}

	eventLogger.Info("PUSH-SRV: JTI delivered", "sid", configuration.Id, "jti", event.Jti)
	return true
}

/*
StreamEventMatch checks provided event to see if it should be routed to the selected stream. If the aud or iss value
is not specified for the stream is will be considered a wildcard. If the event has no value for aud or iss, they too
will be considered a wildcard leading to the event being a match.
*/
func StreamEventMatch(stream *model.StreamStateRecord, event *model.EventRecord) bool {
	// First check that the direction of the stream matches the event InBound = true means local consumption
	if stream.IsReceiver() && stream.GetRouteMode() == model.RouteModeImport {
		return false
	}

	// Check for issuer match if stream has an issuer set
	if stream.Iss != "" {
		compIss := event.Event.Issuer

		if compIss != "" && !strings.EqualFold(stream.Iss, compIss) {
			return false
		}
	}

	// Check for Aud match
	if len(stream.Aud) > 0 {
		audMatch := false
		for _, value := range stream.Aud {
			// fmt.Println("Trying value: " + value)
			// test below returns true if the event has no aud value
			if len(event.Event.Audience) == 0 || slices.Contains([]string(event.Event.Audience), value) {
				audMatch = true
				// fmt.Println("Stream Aud Matched!")
				break
			}
		}
		if !audMatch {
			return false
		}
	}

	for _, eventType := range event.Types {
		// The following events should always be returned.
		if eventType == "https://schemas.openid.net/secevent/sse/event-type/verification" {
			return true
		}
		if eventType == "https://schemas.openid.net/secevent/ssf/event-type/verification" {
			return true
		}
		if eventType == "https://schemas.openid.net/secevent/ssf/event-type/stream-updated" {
			return true
		}
		for _, streamType := range stream.EventsDelivered {
			if strings.EqualFold(eventType, streamType) {
				return true
			}
		}
	}
	return false
}

func (r *router) RemoveStream(sid string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	pb, ok := r.pushBuffers[sid]
	if ok {
		pb.Close()
	}

	_, ok = r.pushStreams[sid]
	if ok {
		delete(r.pushBuffers, sid)
		delete(r.pushStreams, sid)
	} else {
		_, ok := r.pollStreams[sid]
		if ok {
			delete(r.pollStreams, sid)
		}

		if pb, ok := r.pollBuffers[sid]; ok {
			pb.Close()
		}
		delete(r.pollBuffers, sid)
	}
	eventLogger.Info("STREAM Removed from router", "sid", sid)
}

func (r *router) CloseStream(sid string) {
	r.mu.RLock()
	pb, ok := r.pushBuffers[sid]
	r.mu.RUnlock()
	if ok {
		pb.Close()
	}
}

// Shutdown closes all the PushHandlers. Events will continue to be routed but only delivered when server restarts
func (r *router) Shutdown() {
	// This will shut down the threads that are pushing events.
	r.mu.Lock()
	defer r.mu.Unlock()
	r.enabled = false
	if r.cancel != nil {
		r.cancel()
	}
	for _, pushBuffer := range r.pushBuffers {
		pushBuffer.Close()
	}
	if r.x509Source != nil {
		_ = r.x509Source.Close()
		r.x509Source = nil
	}
	// Nothing need to be done for polling.
}
