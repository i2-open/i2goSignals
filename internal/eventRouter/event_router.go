package eventRouter

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/i2-open/i2goSignals/internal/eventRouter/buffer"
	"github.com/i2-open/i2goSignals/internal/logger"
	"github.com/i2-open/i2goSignals/internal/model"
	"github.com/i2-open/i2goSignals/internal/providers/dbProviders"
	"github.com/i2-open/i2goSignals/pkg/goSet"

	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/prometheus/client_golang/prometheus"
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
}

type router struct {
	pushStreams         map[string]model.StreamStateRecord // These are transmitters
	pollStreams         map[string]model.StreamStateRecord
	ctx                 context.Context
	enabled             bool
	issuerKeys          map[string]*rsa.PrivateKey
	issuerKids          map[string]string
	pollBuffers         map[string]*buffer.EventPollBuffer
	pushBuffers         map[string]*buffer.EventPushBuffer
	provider            dbProviders.DbProviderInterface
	eventsIn, eventsOut *prometheus.CounterVec
}

func (r *router) GetPushStreamCnt() float64 {
	eventLogger.Debug("GetPushStreamCnt request", "count", len(r.pushStreams))
	return float64(len(r.pushStreams))
}

func (r *router) GetPollStreamCnt() float64 {
	return float64(len(r.pollStreams))
}

func NewRouter(provider dbProviders.DbProviderInterface) EventRouter {
	router := &router{
		provider:    provider,
		pushStreams: map[string]model.StreamStateRecord{},
		pollStreams: map[string]model.StreamStateRecord{},
		pushBuffers: map[string]*buffer.EventPushBuffer{},
		pollBuffers: map[string]*buffer.EventPollBuffer{},
		issuerKeys:  map[string]*rsa.PrivateKey{},
		issuerKids:  map[string]string{},
		enabled:     false,
		ctx:         context.WithValue(context.Background(), "provider", provider),
	}

	states := router.provider.GetStateMap()

	for k, state := range states {
		eventLogger.Info("Initializing", "streamKey", k, "configId", state.StreamConfiguration.Id)
		router.UpdateStreamState(&state)
	}
	router.enabled = true
	return router
}

func (r *router) IncrementCounter(stream *model.StreamStateRecord, token *goSet.SecurityEventToken, inBound bool) {
	/*
			Note:  Because the event router must initialize before the server is initialized, the
		    event counter cannot be initialized immediately. To avoid a who goes first conflict,
			the counter may briefly be nil during startup.

		    TODO:  Should the incrementer wait until r.eventsOut is not nil?  This will block the outbound stream
	*/
	if r.eventsOut == nil {
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
		fmt.Println(token.String())
	}

	label := prometheus.Labels{
		"type":      eventTypes,
		"iss":       token.Issuer,
		"tfr":       tfr,
		"stream_id": stream.StreamConfiguration.Id,
	}

	isOut := true
	if inBound {
		isOut = false
	}
	if isOut {
		m := r.eventsOut.With(label)
		m.Inc()
	} else {
		m := r.eventsIn.With(label)
		m.Inc()
	}
}

func (r *router) SetEventCounter(inCounter, outCounter *prometheus.CounterVec) {
	r.eventsOut = outCounter
	r.eventsIn = inCounter
}

func (r *router) PreInitializeCounter(stream *model.StreamStateRecord) {
	if r.eventsOut == nil || r.eventsIn == nil {
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

	r.eventsIn.With(labels).Add(0)
	r.eventsOut.With(labels).Add(0)
}

func (r *router) initPushStream(sid string, state *model.StreamStateRecord, jtis []string) {
	pushBuffer := buffer.CreateEventPushBuffer(jtis)
	r.pushBuffers[sid] = pushBuffer
	go r.PushStreamHandler(state, pushBuffer)
}

func (r *router) checkAndLoadKey(streamID string, issuer string) (*rsa.PrivateKey, string) {
	key, ok := r.issuerKeys[issuer]
	kid := r.issuerKids[issuer]
	if !ok {
		var err error
		key, kid, err = r.provider.GetIssuerPrivateKeyWithKid(issuer)
		if err != nil {
			eventLogger.Warn("Unable to locate key for issuer, retrying...", "streamID", streamID, "issuer", issuer)

			return nil, ""
		}
		copyKey := *key
		r.issuerKeys[issuer] = &copyKey
		r.issuerKids[issuer] = kid
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

	if stream.StreamConfiguration.Delivery.GetMethod() == model.DeliveryPoll {
		r.PreInitializeCounter(stream)

		currentState, ok := r.pollStreams[stream.StreamConfiguration.Id]

		if ok {
			fmt.Println("Found existing match: " + currentState.StreamConfiguration.Id)
			currentState.Update(stream)
		} else {
			fmt.Println("Adding stream to Pollers: " + stream.StreamConfiguration.Id)
			r.pollStreams[stream.StreamConfiguration.Id] = *stream
		}
		_, ok = r.pollBuffers[stream.StreamConfiguration.Id]
		if !ok {
			// Preload any outstanding pending events (because we may be re-starting)
			jtis, _ := r.provider.GetEventIds(stream.StreamConfiguration.Id, model.PollParameters{
				MaxEvents:         0,
				ReturnImmediately: true,
				Acks:              nil,
				SetErrs:           nil,
				TimeoutSecs:       10,
			})
			// TODO:  might have to check for existing events!
			r.pollBuffers[stream.StreamConfiguration.Id] = buffer.CreateEventPollBuffer(jtis)
		}
		return
	}
	// The stream is delivery PUSH
	r.PreInitializeCounter(stream)

	currentState, ok := r.pushStreams[stream.StreamConfiguration.Id]
	if ok {
		currentState.Update(stream)
	} else {
		// preload the buffer with any existing events
		jtis, _ := r.provider.GetEventIds(stream.StreamConfiguration.Id, model.PollParameters{
			MaxEvents:         0,
			ReturnImmediately: true,
			Acks:              nil,
			SetErrs:           nil,
			TimeoutSecs:       10,
		})
		r.pushStreams[stream.StreamConfiguration.Id] = *stream
		r.initPushStream(stream.StreamConfiguration.Id, stream, jtis)
	}

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

	event := r.provider.AddEvent(eventToken, sid, rawEvent)
	r.IncrementCounter(streamState, eventToken, true)

	if (streamState != nil && streamState.IsReceiver()) && streamState.GetRouteMode() == model.RouteModeImport {
		// nothing more to do
		return nil
	}

	// Check to see if the event should be routed to outbound push streams
	for _, stream := range r.pushStreams {
		if StreamEventMatch(&stream, event) {

			eventLogger.Info("ROUTER: Selected", "sid", stream.StreamConfiguration.Id, "jti", event.Jti, "mode", "PUSH", "types", event.Types)

			// The transmitter API will forward or sign/encrypt the event based on route mode at delivery time!
			r.provider.AddEventToStream(event.Jti, stream.Id)
			// This will cause the PollStreamHandler assigned to deliver the event
			r.pushBuffers[stream.StreamConfiguration.Id].SubmitEvent(event.Jti)
		}
	}

	// Check to see if the event should be routed to outbound polling stream
	for k, pollStream := range r.pollStreams {
		eventLogger.Debug("ROUTER: Checking stream", "sid", k)

		if StreamEventMatch(&pollStream, event) {
			eventLogger.Info("ROUTER: Selected", "sid", pollStream.StreamConfiguration.Id, "jti", event.Jti, "mode", "POLL", "types", event.Types)

			// The transmitter API will forward or sign/encrypt the event based on route mode at delivery time!
			r.provider.AddEventToStream(event.Jti, pollStream.Id)
			// This causes the event to be available on the next poll
			r.pollBuffers[pollStream.StreamConfiguration.Id].SubmitEvent(event.Jti)
		}
	}
	return nil
}

func (r *router) PollStreamHandler(sid string, params model.PollParameters) (map[string]string, bool, int) {
	state, exist := r.pollStreams[sid]
	if !exist {
		eventLogger.Error("POLL-SRV: Error Poll Transmitter not found", "sid", sid)
		return nil, false, http.StatusNotFound
	}

	if state.Status != model.StreamStateEnabled {
		stateString, _ := json.MarshalIndent(&state, "", "  ")
		eventLogger.Debug("Stream State", "state", string(stateString))
		eventLogger.Error("POLL-SRV: Error Poll request but stream is not active", "sid", sid)
		return nil, false, http.StatusConflict
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

	pollBuffer := r.pollBuffers[sid]
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

/*
PushStreamHandler is started as a separate thread during the initialization of the eventRouter. To stop the handler the buffer is closed.
*/
func (r *router) PushStreamHandler(stream *model.StreamStateRecord, eventBuf *buffer.EventPushBuffer) {
	eventLogger.Info("PUSH-HANDLER: Starting", "sid", stream.StreamConfiguration.Id)

	var rsaKey *rsa.PrivateKey
	var kid string
	if stream.GetRouteMode() == model.RouteModePublish {
		rsaKey, kid = r.checkAndLoadKey(stream.StreamConfiguration.Id, stream.Iss)
		if rsaKey == nil {
			eventLogger.Warn("PUSH-SRV: no issuer key available", "sid", stream.StreamConfiguration.Id, "issuer", stream.StreamConfiguration.Iss)
			// TODO: What should be done about undelivered events?
		}
	}

	out := eventBuf.Out
eventLoop:
	for v := range out {
		jti := v.(string)
		r.prepareAndSendEvent(jti, stream, rsaKey, kid)
		if stream.Status != model.StreamStateEnabled {
			eventLogger.Info("PUSH-SRV is no longer active. PushHandler exiting.", "sid", stream.Id.Hex())
			break eventLoop
		}
	}
	eventLogger.Info("PUSH-SRV: Stopped", "sid", stream.StreamConfiguration.Id)
}

func (r *router) prepareAndSendEvent(jti string, config *model.StreamStateRecord, rsaKey *rsa.PrivateKey, kid string) {
	eventRecord := r.provider.GetEventRecord(jti)
	// Get the event
	if eventRecord != nil {

		delivered := r.pushEvent(config.StreamConfiguration, eventRecord, rsaKey, kid)
		if delivered {
			r.provider.AckEvent(jti, config.StreamConfiguration.Id)
			r.IncrementCounter(config, &eventRecord.Event, false)
		}
	}
}

// pushEvent implements the server push side (http client) of RFC8935 Push Based Delivery of SET Events
// Note: Moved from the api_transmitter.go in server package
func (r *router) pushEvent(configuration model.StreamConfiguration, event *model.EventRecord, key *rsa.PrivateKey, kid string) bool {
	pushConfig := configuration.Delivery.PushTransmitMethod

	client := http.Client{Timeout: 60 * time.Second}

	var tokenString string
	url := pushConfig.EndpointUrl

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

	req, err := http.NewRequest("POST", url, strings.NewReader(tokenString))

	if pushConfig.AuthorizationHeader != "" {
		authorization := pushConfig.AuthorizationHeader
		if strings.ToLower(authorization[0:4]) != "bear" {
			authorization = "Bearer " + authorization
		}
		req.Header.Set("Authorization", authorization)
	}
	req.Header.Set("Content-Type", "application/secevent+jwt")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		eventLogger.Error("PUSH-SRV: Error sending", "sid", configuration.Id, "error", err)
		return false
	}
	if resp.StatusCode != http.StatusAccepted {
		if resp.StatusCode == http.StatusBadRequest {
			var errorMsg model.SetDeliveryErr
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				r.provider.UpdateStreamStatus(configuration.Id, model.StreamStatePause, "Unable to read response")
				eventLogger.Error("PUSH-SRV: Error reading response", "sid", configuration.Id, "error", err)
				return false
			}
			err = json.Unmarshal(body, &errorMsg)
			if err != nil {
				eventLogger.Error("PUSH-SRV: Error parsing error response", "sid", configuration.Id, "error", err)
				r.provider.UpdateStreamStatus(configuration.Id, model.StreamStatePause, "Unable to parse JSON response")
				return false
			}
			errMsg := fmt.Sprintf("PUSH-SRV[%s] %s", errorMsg.ErrCode, errorMsg.Description)
			eventLogger.Error("PUSH-SRV: Push failed", "sid", configuration.Id, "code", errorMsg.ErrCode, "desc", errorMsg.Description)
			r.provider.UpdateStreamStatus(configuration.Id, model.StreamStatePause, errMsg)
			return false
		}
		if resp.StatusCode > 400 {
			errMsg := fmt.Sprintf("PUSH-SRV[%s] HTTP Error: %s, POSTING to %s", configuration.Id, resp.Status, url)
			eventLogger.Error("PUSH-SRV: HTTP Error", "sid", configuration.Id, "status", resp.Status, "url", url)
			r.provider.UpdateStreamStatus(configuration.Id, model.StreamStatePause, errMsg)
		}
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
			if event.Event.VerifyAudience(value, false) {
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
		if eventType == "https://schemas.openid.net/secevent/sse/event-type/verification" {
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

	r.CloseStream(sid)
	_, ok := r.pushStreams[sid]
	if ok {
		delete(r.pushBuffers, sid)
		delete(r.pushStreams, sid)
	} else {
		_, ok := r.pollStreams[sid]
		if ok {
			delete(r.pollStreams, sid)
		}

		delete(r.pollBuffers, sid)
	}
	eventLogger.Info("STREAM Removed from router", "sid", sid)
}

func (r *router) CloseStream(sid string) {
	pb, ok := r.pushBuffers[sid]
	if ok {
		pb.Close()
	}
}

// Shutdown closes all the PushHandlers. Events will continue to be routed but only delivered when server restarts
func (r *router) Shutdown() {
	// This will shut down the threads that are pushing events.
	r.enabled = false
	for _, pushBuffer := range r.pushBuffers {
		pushBuffer.Close()
	}

	// Nothing need to be done for polling because.
}
