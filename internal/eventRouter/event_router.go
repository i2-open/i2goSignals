package eventRouter

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/i2-open/i2goSignals/pkg/httpSupport"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/spiffe/go-spiffe/v2/workloadapi"

	"github.com/i2-open/i2goSignals/internal/envcompat"
	"github.com/i2-open/i2goSignals/internal/eventRouter/buffer"
	"github.com/i2-open/i2goSignals/internal/eventRouter/delivery"
	"github.com/i2-open/i2goSignals/internal/providers/cluster"
	"github.com/i2-open/i2goSignals/internal/services"
	"github.com/i2-open/i2goSignals/pkg/authSupport"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/goSet/events"
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
	// SubmitOperationalEvent persists an operational event (Operational=true) and submits it directly
	// to the target stream's pending list, bypassing the MatchesStream predicate. Operational events
	// are point-to-point SSF protocol events scoped to a single SSF endpoint relationship (e.g. verify,
	// stream-updated).
	SubmitOperationalEvent(sid string, eventToken *goSet.SecurityEventToken, rawEvent string) (*model.AgEventRecord, error)
	// GenerateVerifyEvent creates an SSF verification SET scoped to the target stream's iss/aud,
	// persists it as an operational event, and submits it to the target stream's pending list.
	// Used by both the operator-triggered API handler and the push-side T3 idle keepalive.
	GenerateVerifyEvent(sid string, state string) (*model.AgEventRecord, error)
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
	coordinator         cluster.ClusterCoordinator
	streamService       *services.StreamService
	keyService          *services.KeyService
	eventService        *services.EventService
	pushDelivery        delivery.PushDelivery
	eventsIn, eventsOut *prometheus.CounterVec
	stats               statsTracker

	httpClient          *http.Client
	clusterSecret       string
	recentOutboundWakes map[string]time.Time
	outboundWakesMu     sync.Mutex
	backfillInterval    time.Duration
	backfillBatch       int
	// pollDefaultTimeoutSecs is the resolved I2SIG_POLL_DEFAULT_TIMEOUT
	// applied to every EventPollBuffer constructed for the lifetime of this
	// router. 0 means "no implicit long-poll" — receiver omitting timeoutSecs
	// gets an immediate return on an empty buffer.
	pollDefaultTimeoutSecs int
	// pollMaxTimeoutSecs is the resolved I2SIG_POLL_MAX_TIMEOUT cap on
	// inbound receiver timeoutSecs values. 0 disables the cap.
	pollMaxTimeoutSecs int
	// x509Source is the SPIFFE X509Source used to build the SPIFFE mTLS transport
	// for inter-cluster calls. Non-nil only when SPIFFE_ENDPOINT_SOCKET is set.
	x509Source *workloadapi.X509Source
}

type statsTracker interface {
	TrackLeaseAcquisition(resource string, success bool)
	IncLeasesHeld()
	DecLeasesHeld()

	// RecordPushFailure increments push_failures_total{sid, errClass}. Called from the
	// failure path in prepareAndSendEvent for every non-Accepted push response. errClass
	// values come from goSetPush.FailureClass.String().
	RecordPushFailure(sid, errClass string)

	// RecordStateTransition increments push_state_transitions_total{sid, from, to}. Called
	// from updateStream whenever the persisted status actually changes (no-op suppressions
	// are not counted), so the counter exactly mirrors the audit log.
	RecordStateTransition(sid, from, to string)

	// ObservePushRecoveryDuration observes push_recovery_duration_seconds{sid}. Called from
	// logRecoveryResolved with the elapsed wall time from recovery entry to exit (any outcome).
	ObservePushRecoveryDuration(sid string, seconds float64)

	// RecordIdleVerifyOutcome increments push_idle_verify_total{sid, outcome}. Outcome is
	// "acked" when the verify-event push receives 202, or "failed" otherwise. This counts any
	// push of an operational verification SET, which in practice is dominated by T3 idle
	// keepalives — operator-triggered verifications also flow through the same path and
	// contribute to the same counter (rare in production).
	RecordIdleVerifyOutcome(sid, outcome string)
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

// RouterDeps is the dependency bundle the event router needs from the
// composition root. Callers wire it directly from a *dbProviders.Persistence
// (or build one ad hoc in tests).
type RouterDeps struct {
	StreamService *services.StreamService
	KeyService    *services.KeyService
	EventService  *services.EventService
	Coordinator   cluster.ClusterCoordinator
	// PushDelivery is the seam for one-attempt SET delivery. Main.go injects the
	// HTTP adapter (production); tests may inject delivery.NewMemoryAdapter for
	// deterministic outcomes. If nil, NewRouter constructs a default HTTPAdapter
	// wired to the router as KeyReloader.
	PushDelivery delivery.PushDelivery
}

func NewRouter(deps RouterDeps, nodeId string) EventRouter {
	ctx, cancel := context.WithCancel(context.Background())
	router := &router{
		coordinator:         deps.Coordinator,
		streamService:       deps.StreamService,
		keyService:          deps.KeyService,
		eventService:        deps.EventService,
		nodeId:              nodeId,
		pushStreams:         map[string]model.StreamStateRecord{},
		pollStreams:         map[string]model.StreamStateRecord{},
		pushBuffers:         map[string]*buffer.EventPushBuffer{},
		pollBuffers:         map[string]*buffer.EventPollBuffer{},
		issuerKeys:          map[string]*rsa.PrivateKey{},
		issuerKids:          map[string]string{},
		enabled:             false,
		ctx:                 ctx,
		cancel:              cancel,
		httpClient:          &http.Client{Timeout: 5 * time.Second},
		clusterSecret:       os.Getenv("I2SIG_CLUSTER_INTERNAL_TOKEN"),
		recentOutboundWakes: make(map[string]time.Time),
	}

	if deps.PushDelivery != nil {
		router.pushDelivery = deps.PushDelivery
		// Late-bind the KeyReloader for any adapter that needs it (HTTPAdapter
		// does; MemoryAdapter doesn't implement the setter and is skipped).
		if setter, ok := deps.PushDelivery.(interface {
			SetKeyReloader(delivery.KeyReloader)
		}); ok {
			setter.SetKeyReloader(router)
		}
	} else {
		router.pushDelivery = delivery.NewHTTPAdapter(deps.StreamService, router)
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
	if val := envcompat.Lookup("I2SIG_PUSH_BACKFILL_INTERVAL", "I2SIG_TRANSMITTER_BACKFILL_INTERVAL"); val != "" {
		if d, err := time.ParseDuration(val); err == nil {
			backfillInterval = d
		}
	}
	router.backfillInterval = backfillInterval

	backfillBatch := 100
	if val := envcompat.Lookup("I2SIG_PUSH_BACKFILL_BATCH", "I2SIG_TRANSMITTER_BACKFILL_BATCH"); val != "" {
		if i, err := strconv.Atoi(val); err == nil {
			backfillBatch = i
		}
	}
	router.backfillBatch = backfillBatch

	router.pollDefaultTimeoutSecs, router.pollMaxTimeoutSecs = resolvePollTimeoutEnv()
	eventLogger.Info("Poll long-poll timeouts resolved",
		"I2SIG_POLL_DEFAULT_TIMEOUT", router.pollDefaultTimeoutSecs,
		"I2SIG_POLL_MAX_TIMEOUT", router.pollMaxTimeoutSecs)

	states := router.streamService.GetStateMap(ctx)

	for k, state := range states {
		eventLogger.Info("Initializing", "streamKey", k, "configId", state.StreamConfiguration.Id)
		router.UpdateStreamState(&state)
	}
	router.enabled = true

	// Start the background watcher if explicitly enabled
	if envcompat.Lookup("I2SIG_STORE_MONGO_WATCH_ENABLED", "I2SIG_MONGO_WATCH_ENABLED") == "true" {
		eventLogger.Info("Background watcher enabled via I2SIG_STORE_MONGO_WATCH_ENABLED")
		go router.eventService.WatchPending(ctx, func(jti string, streamId string) {
			sid := streamId
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

const (
	pollDefaultTimeoutSecsDefault = 30
	pollMaxTimeoutSecsDefault     = 300
)

// resolvePollTimeoutEnv reads I2SIG_POLL_DEFAULT_TIMEOUT and
// I2SIG_POLL_MAX_TIMEOUT (with legacy POLL_DEFAULT_TIMEOUT / POLL_MAX_TIMEOUT
// as fallbacks via envcompat) and applies the validation policy:
//
//   - Unset / empty: use code default.
//   - Unparseable or negative: log WARN, fall back to code default.
//     Server starts successfully.
//   - default > max with max > 0: clamp default down to max, log WARN.
//   - Returned values are pure ints in seconds; either may be 0
//     (operator-requested escape hatch).
func resolvePollTimeoutEnv() (defaultSecs, maxSecs int) {
	defaultSecs = parsePollTimeoutEnv("I2SIG_POLL_DEFAULT_TIMEOUT", "POLL_DEFAULT_TIMEOUT", pollDefaultTimeoutSecsDefault)
	maxSecs = parsePollTimeoutEnv("I2SIG_POLL_MAX_TIMEOUT", "POLL_MAX_TIMEOUT", pollMaxTimeoutSecsDefault)
	if maxSecs > 0 && defaultSecs > maxSecs {
		eventLogger.Warn("I2SIG_POLL_DEFAULT_TIMEOUT exceeds I2SIG_POLL_MAX_TIMEOUT; clamping default to max",
			"I2SIG_POLL_DEFAULT_TIMEOUT", defaultSecs, "I2SIG_POLL_MAX_TIMEOUT", maxSecs)
		defaultSecs = maxSecs
	}
	return defaultSecs, maxSecs
}

func parsePollTimeoutEnv(newName, oldName string, fallback int) int {
	val := envcompat.Lookup(newName, oldName)
	if val == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(val)
	if err != nil {
		eventLogger.Warn("Invalid integer; falling back to default",
			"env", newName, "value", val, "default", fallback)
		return fallback
	}
	if parsed < 0 {
		eventLogger.Warn("Negative value not permitted; falling back to default",
			"env", newName, "value", parsed, "default", fallback)
		return fallback
	}
	return parsed
}

func (r *router) ResetStream(sid string) {
	r.mu.RLock()
	buf, ok := r.pollBuffers[sid]
	r.mu.RUnlock()
	if ok {
		buf.Clear()
	}
	_, _ = r.eventService.ClearPendingForStream(r.ctx, sid)
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
			key, kid, err = r.keyService.GetPrivateKeyWithKeyname(r.ctx, issuer)
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
			jtis, _ := r.eventService.GetEventIds(r.ctx, stream.StreamConfiguration.Id, model.PollParameters{
				MaxEvents:         0,
				ReturnImmediately: true,
				Acks:              nil,
				SetErrs:           nil,
				TimeoutSecs:       10,
			})
			r.mu.Lock()
			// TODO:  might have to check for existing events!
			r.pollBuffers[stream.StreamConfiguration.Id] = buffer.CreateEventPollBuffer(jtis, r.pollDefaultTimeoutSecs, r.pollMaxTimeoutSecs)
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
		jtis, _ := r.eventService.GetEventIds(r.ctx, stream.StreamConfiguration.Id, model.PollParameters{
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

	streamState, err := r.streamService.GetStreamState(r.ctx, sid)
	if err != nil {
		return err
	}

	event, err := r.eventService.AddEvent(r.ctx, eventToken, sid, rawEvent)
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
		if r.eventService.MatchesStream(&stream, event) {

			eventLogger.Info("ROUTER: Selected", "sid", stream.StreamConfiguration.Id, "jti", event.Jti, "mode", "PUSH", "types", event.Types)

			// The transmitter API will forward or sign/encrypt the event based on route mode at delivery time!
			err = r.eventService.AddEventToStream(r.ctx, event.Jti, stream.Id.Hex())
			if err != nil {
				eventLogger.Error("ROUTER: Error adding event to push stream", "sid", stream.StreamConfiguration.Id, "jti", event.Jti, "error", err)
			}

			// Lease-aware routing
			resource := fmt.Sprintf("push-transmitter:%s", stream.StreamConfiguration.Id)
			ownerNodeId, _, _, _ := r.coordinator.GetLeaseOwner(resource)

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

		if r.eventService.MatchesStream(&pollStream, event) {
			eventLogger.Info("ROUTER: Selected", "sid", pollStream.StreamConfiguration.Id, "jti", event.Jti, "mode", "POLL", "types", event.Types)

			// The transmitter API will forward or sign/encrypt the event based on route mode at delivery time!
			err = r.eventService.AddEventToStream(r.ctx, event.Jti, pollStream.Id.Hex())
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

// SubmitOperationalEvent persists an operational event with Operational=true and submits the JTI directly to
// the target stream's pending list. It bypasses the MatchesStream predicate (operational events are
// point-to-point), and is used for SSF protocol events such as verify and stream-updated. If the target stream's transmitter lease
// is held by a remote node, a wake-up is dispatched so the owner picks up the new JTI.
func (r *router) SubmitOperationalEvent(sid string, eventToken *goSet.SecurityEventToken, rawEvent string) (*model.AgEventRecord, error) {
	stream, err := r.streamService.GetStreamState(r.ctx, sid)
	if err != nil {
		return nil, err
	}
	if stream == nil {
		return nil, fmt.Errorf("stream not found: %s", sid)
	}

	rec, err := r.eventService.AddOperationalEvent(r.ctx, eventToken, sid, rawEvent)
	if err != nil {
		return nil, err
	}
	r.IncrementCounter(stream, eventToken, true)

	if err := r.eventService.AddEventToStream(r.ctx, rec.Jti, stream.Id.Hex()); err != nil {
		eventLogger.Error("ROUTER: Error adding operational event to stream", "sid", sid, "jti", rec.Jti, "error", err)
		return rec, err
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	if pushBuf, ok := r.pushBuffers[sid]; ok {
		resource := fmt.Sprintf("push-transmitter:%s", sid)
		ownerNodeId, _, _, _ := r.coordinator.GetLeaseOwner(resource)
		if ownerNodeId == "" || ownerNodeId == r.nodeId {
			pushBuf.SubmitEvent(rec.Jti)
		} else {
			go r.sendWakeup(sid, "push", ownerNodeId)
		}
		eventLogger.Info("ROUTER: Operational event submitted (push)", "sid", sid, "jti", rec.Jti, "types", rec.Types)
		return rec, nil
	}

	if pollBuf, ok := r.pollBuffers[sid]; ok {
		pollBuf.SubmitEvent(rec.Jti)
		eventLogger.Info("ROUTER: Operational event submitted (poll)", "sid", sid, "jti", rec.Jti, "types", rec.Types)
		return rec, nil
	}

	eventLogger.Warn("ROUTER: Operational event persisted but stream has no buffer", "sid", sid, "jti", rec.Jti)
	return rec, nil
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

	node, err := r.coordinator.GetNode(ownerNodeId)
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
			_ = r.eventService.AckEvent(r.ctx, jti, sid, 0)
		}
	}

	if len(params.SetErrs) > 0 {
		jtis := make([]string, 0, len(params.SetErrs))
		for jti := range params.SetErrs {
			jtis = append(jtis, jti)
		}
		pollBuffer.AckEvents(jtis)
		for _, jti := range jtis {
			_ = r.eventService.AckEvent(r.ctx, jti, sid, 0)
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
		jtis, _ := r.eventService.GetEventIds(r.ctx, sid, model.PollParameters{
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
				eventRecord := r.eventService.GetEventRecord(r.ctx, jti)
				if eventRecord == nil {
					eventLogger.Warn("POLL-SRV: JTI Not found", "sid", sid, "jti", jti)
					continue
				}
				sets[jti] = eventRecord.Original
			}
		} else {
			tokens := r.eventService.GetEvents(r.ctx, *jtiSlice)
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
		acquired, fencingToken, err := r.coordinator.TryAcquireOrRenewLease(resource, r.nodeId, 30*time.Second)
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

// runPushLoop handles the event push loop for a given stream, including lease renewal, T2
// pre-flight, T1 reactive recovery on push failures, and event processing. Returns true if the
// caller should attempt to re-acquire the lease (e.g. lease lost), false if the lifecycle
// goroutine should exit (buffer closed, stream disabled, shutdown).
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
				ok, _, err := r.coordinator.TryAcquireOrRenewLease(resource, r.nodeId, 30*time.Second)
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

	recoveryCfg := LoadRecoveryConfig()
	statusFetcher := r.pushStatusFetcher()
	idleVerifyInterval := LoadIdleVerifyInterval()

	// T2 pre-flight: check the receiver's reported state before draining the buffer. If the
	// receiver self-paused or self-disabled while we were not the lease holder, we should not
	// attempt the first push; that wastes a JTI on a known failure and produces noise in logs.
	// Transport/auth/decode errors are tolerated — they will surface immediately on the first
	// push attempt and dispatch to T1 with the right RecoveryMode.
	switch outcome := r.preflightCheckStatus(heartbeatCtx, stream, statusFetcher, recoveryCfg); outcome {
	case RecoveryOutcomeDisabled:
		return false
	case RecoveryOutcomeContextDone:
		return true
	}

	backfillTicker := time.NewTicker(r.backfillInterval)
	defer backfillTicker.Stop()

	// T3 idle keepalive timer. A non-positive interval disables the feature: idleC stays nil,
	// which means the corresponding select arm is never chosen. The timer is local to this
	// lease-holding goroutine (C1) — failover resets the idle clock to "now" naturally.
	var idleTimer *time.Timer
	var idleC <-chan time.Time
	if idleVerifyInterval > 0 {
		idleTimer = time.NewTimer(idleVerifyInterval)
		defer idleTimer.Stop()
		idleC = idleTimer.C
	}

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
			cls, newKey, newKid := r.prepareAndSendEvent(jti, stream, rsaKey, kid, fencingToken)
			rsaKey, kid = newKey, newKid

			if cls.Class == goSetPush.ClassAccepted {
				// R1: reset T3 idle timer on every successful push, including verify itself.
				resetIdleTimer(idleTimer, idleVerifyInterval)
				continue
			}

			// T1 reactive: dispatch the failure into the right recovery mode (or disable, or
			// rate-limit sleep). The lease heartbeat and backfill behavior is managed here so
			// the recovery sub-loop doesn't have to know about either.
			recoverOutcome, exit := r.dispatchPushFailure(heartbeatCtx, stream, jti, cls, statusFetcher, recoveryCfg, backfillTicker, idleTimer, idleVerifyInterval)
			if exit {
				return recoverOutcome == RecoveryOutcomeContextDone
			}
			// Resumed — refresh signing key in case the issuer rotated while we were paused.
			if stream.GetRouteMode() == model.RouteModePublish {
				rsaKey, kid = r.checkAndLoadKey(sid, stream.Iss)
			}
		case <-backfillTicker.C:
			r.backfillPushBuffer(sid, eventBuf)
		case <-wakeup:
			eventLogger.Debug("PUSH-SRV: Wake-up received, triggering backfill", "sid", sid)
			r.backfillPushBuffer(sid, eventBuf)
		case <-idleC:
			// T3 fired: no successful push in the last idleVerifyInterval. Generate a real
			// verify event via the operational-event direct-submission path. The new JTI lands
			// in eventBuf and the next iteration of this loop will pull it from `out` and push
			// it via the normal path. If the push succeeds, R1 resets the timer above; if it
			// fails, the failure dispatch stops the timer for the duration of recovery.
			//
			// Pre-emptively reset here so we don't fire again while the verify push is in
			// flight; the success-path reset is idempotent.
			if _, err := r.GenerateVerifyEvent(sid, ""); err != nil {
				eventLogger.Warn("PUSH-SRV: T3 idle verify generation failed", "sid", sid, "error", err)
			} else {
				eventLogger.Debug("PUSH-SRV: T3 idle verify event generated", "sid", sid, "interval", idleVerifyInterval)
			}
			if idleTimer != nil {
				idleTimer.Reset(idleVerifyInterval)
			}
		}
	}
}

// preflightCheckStatus performs the T2 pre-flight /status fetch right after lease acquisition.
// Possible outcomes returned to the caller:
//   - RecoveryOutcomeResumed (fall through and start delivering): receiver reports enabled, or
//     the fetch failed (we tolerate — first push will surface the real failure).
//   - RecoveryOutcomeDisabled (return false from runPushLoop): receiver reports disabled, OR
//     receiver was paused and recoveryLoop later observed disabled.
//   - RecoveryOutcomeContextDone (return true from runPushLoop): heartbeat ctx cancelled while
//     waiting for receiver to un-pause.
func (r *router) preflightCheckStatus(ctx context.Context, stream *model.StreamStateRecord, fetcher StatusFetcher, cfg RecoveryConfig) RecoveryOutcome {
	sid := stream.StreamConfiguration.Id
	status, err := fetcher(ctx, stream)
	if err != nil {
		eventLogger.Debug("PUSH-SRV: T2 pre-flight status check failed; proceeding with delivery",
			"sid", sid, "error", err)
		return RecoveryOutcomeResumed
	}
	if status == nil {
		return RecoveryOutcomeResumed
	}
	switch status.Status {
	case model.StreamStateEnabled:
		eventLogger.Debug("PUSH-SRV: T2 pre-flight: receiver enabled", "sid", sid)
		return RecoveryOutcomeResumed
	case model.StreamStateDisable:
		reason := fmt.Sprintf("PUSH-SRV: T2 pre-flight: receiver disabled: %s", status.Reason)
		r.updateStream(stream, model.StreamStateDisable, reason)
		return RecoveryOutcomeDisabled
	case model.StreamStatePause:
		reason := fmt.Sprintf("PUSH-SRV: T2 pre-flight: receiver paused: %s", status.Reason)
		r.updateStream(stream, model.StreamStatePause, reason)
		return r.recoveryLoop(ctx, stream, RecoveryModePausedByRemote, fetcher, cfg)
	}
	// Unknown status string: be permissive and proceed.
	return RecoveryOutcomeResumed
}

// dispatchPushFailure reacts to a non-Accepted push Classification. It either:
//   - sleeps the receiver-suggested Retry-After (rate-limited), then returns Resumed (no exit);
//   - disables the stream and returns (Disabled, true);
//   - dispatches into recoveryLoop with the appropriate RecoveryMode and propagates its outcome,
//     stopping/restarting the backfill ticker around the call.
//
// Returns (outcome, shouldExit). When shouldExit is true the caller's runPushLoop must return
// (true if outcome == ContextDone for re-acquire, false otherwise for terminal exit).
func (r *router) dispatchPushFailure(
	ctx context.Context,
	stream *model.StreamStateRecord,
	jti string,
	cls goSetPush.Classification,
	fetcher StatusFetcher,
	cfg RecoveryConfig,
	backfillTicker *time.Ticker,
	idleTimer *time.Timer,
	idleVerifyInterval time.Duration,
) (RecoveryOutcome, bool) {
	sid := stream.StreamConfiguration.Id

	switch cls.Class {
	case goSetPush.ClassRateLimited:
		// 429 (or 503 + Retry-After) is peer back-pressure, not a state change. Honor the
		// suggested delay and continue. JTI stays unacked; backfill will re-pull it.
		delay := cls.NextDelay
		if delay <= 0 {
			delay = cfg.BaseDelay
		}
		eventLogger.Info("PUSH-SRV: rate-limited, honoring Retry-After", "sid", sid, "jti", jti, "delay", delay)
		if !cfg.Sleep(ctx, delay) {
			return RecoveryOutcomeContextDone, true
		}
		return RecoveryOutcomeResumed, false

	case goSetPush.ClassForbidden:
		reason := fmt.Sprintf("PUSH-SRV: 403 Forbidden on jti=%s", jti)
		r.updateStream(stream, model.StreamStateDisable, reason)
		return RecoveryOutcomeDisabled, true

	case goSetPush.ClassRFC8935Error:
		// Caller already retried jws_signature_failed once via the key-flush sub-policy. Any
		// RFC8935 §2.4 error reaching us here is deterministic per-SET — disable.
		reason := fmt.Sprintf("PUSH-SRV: RFC8935 %s on jti=%s: %s", cls.RFC8935ErrCode, jti, cls.RFC8935Description)
		r.updateStream(stream, model.StreamStateDisable, reason)
		return RecoveryOutcomeDisabled, true

	case goSetPush.ClassWeirdClientError:
		reason := fmt.Sprintf("PUSH-SRV: weird 4xx on jti=%s", jti)
		r.updateStream(stream, model.StreamStateDisable, reason)
		return RecoveryOutcomeDisabled, true

	case goSetPush.ClassWeirdResponse:
		reason := fmt.Sprintf("PUSH-SRV: weird response on jti=%s", jti)
		r.updateStream(stream, model.StreamStateDisable, reason)
		return RecoveryOutcomeDisabled, true
	}

	// Remaining classes route into recoveryLoop with the appropriate mode.
	var mode RecoveryMode
	var enterReason string
	switch cls.Class {
	case goSetPush.ClassUnauthorized:
		mode = RecoveryModeAuthBounded
		enterReason = fmt.Sprintf("PUSH-SRV: 401 on jti=%s; entering auth-bounded recovery", jti)
	case goSetPush.ClassTransport:
		mode = RecoveryModeTransportBackoff
		enterReason = fmt.Sprintf("PUSH-SRV: transport failure on jti=%s; entering transport-backoff recovery", jti)
	default: // ClassServerError
		mode = RecoveryModeTransportBackoff
		enterReason = fmt.Sprintf("PUSH-SRV: 5xx on jti=%s; entering transport-backoff recovery", jti)
	}
	r.updateStream(stream, model.StreamStatePause, enterReason)

	// Pause backfill and the T3 idle timer while we are in recovery — no point pulling more
	// JTIs from the provider just to re-classify the same failure, and no point synthesizing
	// idle-keepalive verify events when we are already actively probing /status. Restart both
	// on Resumed; failure paths leave them stopped (the goroutine exits).
	backfillTicker.Stop()
	if idleTimer != nil {
		idleTimer.Stop()
	}
	outcome := r.recoveryLoop(ctx, stream, mode, fetcher, cfg)
	switch outcome {
	case RecoveryOutcomeResumed:
		backfillTicker.Reset(r.backfillInterval)
		if idleTimer != nil && idleVerifyInterval > 0 {
			idleTimer.Reset(idleVerifyInterval)
		}
		return outcome, false
	case RecoveryOutcomeDisabled:
		return outcome, true
	default: // ContextDone
		return outcome, true
	}
}

func (r *router) backfillPushBuffer(sid string, eventBuf *buffer.EventPushBuffer) {
	if eventBuf.Cnt() > 0 {
		return
	}

	jtis, _ := r.eventService.GetEventIds(r.ctx, sid, model.PollParameters{
		MaxEvents:         int32(r.backfillBatch),
		ReturnImmediately: true,
	})

	if len(jtis) > 0 {
		eventLogger.Debug("PUSH-SRV: Backfill found pending events", "sid", sid, "count", len(jtis))
		eventBuf.SubmitEvents(jtis)
	}
}

// prepareAndSendEvent fetches the event, hands it to the PushDelivery seam for a single
// attempt (the seam owns RFC8935 §2.4 jws_signature_failed rotate-and-retry internally),
// and acks if the receiver returned 202. Returns the final Classification along with the
// (possibly-rotated) signing key and kid so the caller's subsequent pushes reuse them.
//
// Failures are not acked. The JTI stays in the provider's pending list and will be re-pulled
// by the next backfill iteration once the caller has resolved any required recovery.
func (r *router) prepareAndSendEvent(jti string, config *model.StreamStateRecord, rsaKey *rsa.PrivateKey, kid string, fencingToken int64) (goSetPush.Classification, *rsa.PrivateKey, string) {
	eventRecord := r.eventService.GetEventRecord(r.ctx, jti)
	if eventRecord == nil {
		// Event was deleted between buffer pop and dispatch (e.g. operator reset). Treat as a no-op
		// success so the caller advances rather than entering recovery for a stale JTI.
		return goSetPush.Classification{Class: goSetPush.ClassAccepted}, rsaKey, kid
	}

	outcome := r.pushDelivery.Deliver(r.ctx, delivery.PushRequest{
		Stream: config,
		Event:  eventRecord,
		Key:    rsaKey,
		Kid:    kid,
	})
	cls := outcome.Classification
	rsaKey, kid = outcome.Key, outcome.Kid

	sid := config.StreamConfiguration.Id
	isVerifyPush := isOperationalVerify(eventRecord)

	if cls.Class == goSetPush.ClassAccepted {
		if err := r.eventService.AckEvent(r.ctx, jti, sid, fencingToken); err != nil {
			eventLogger.Error("PUSH-SRV: Error acking event", "sid", sid, "jti", jti, "error", err)
		}
		r.IncrementCounter(config, &eventRecord.Event, false)
		if isVerifyPush && r.stats != nil {
			r.stats.RecordIdleVerifyOutcome(sid, "acked")
		}
		return cls, rsaKey, kid
	}

	eventLogger.Warn("PUSH-SRV: push failed",
		"sid", sid,
		"jti", jti,
		"errClass", cls.Class.String(),
		"rfc8935ErrCode", cls.RFC8935ErrCode,
		"retryAfter", cls.NextDelay,
	)
	if r.stats != nil {
		r.stats.RecordPushFailure(sid, cls.Class.String())
		if isVerifyPush {
			r.stats.RecordIdleVerifyOutcome(sid, "failed")
		}
	}
	return cls, rsaKey, kid
}

// isOperationalVerify returns true when the event was both submitted via the operational-event
// path (slice 2) AND carries the SSF verification event-type. Used at push time to attribute
// the outcome to push_idle_verify_total{outcome=acked|failed}. In production this is dominated
// by T3 idle keepalives; operator-triggered verifies (rare) also pass through this branch.
func isOperationalVerify(rec *model.AgEventRecord) bool {
	if rec == nil || !rec.Operational {
		return false
	}
	for _, t := range rec.Types {
		if t == events.VerificationEventUri {
			return true
		}
	}
	return false
}

// InvalidateAndReload satisfies delivery.KeyReloader. The HTTP push adapter calls this
// on RFC8935 §2.4 jws_signature_failed to flush the cached private key for issuer and
// reload a fresh one from the KeyService. Returns (nil, "") when the reload fails.
func (r *router) InvalidateAndReload(streamID, issuer string) (*rsa.PrivateKey, string) {
	r.mu.Lock()
	delete(r.issuerKeys, issuer)
	delete(r.issuerKids, issuer)
	r.mu.Unlock()
	return r.checkAndLoadKey(streamID, issuer)
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
