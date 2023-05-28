package eventRouter

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"i2goSignals/internal/eventRouter/buffer"
	"i2goSignals/internal/model"
	"i2goSignals/internal/providers/dbProviders"
	"i2goSignals/pkg/goSet"
	"io"
	"net/http"

	"log"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/prometheus/client_golang/prometheus"
)

var eventLogger = log.New(os.Stdout, "ROUTER: ", log.Ldate|log.Ltime)

type EventRouter interface {
	UpdateStreamState(stream *model.StreamStateRecord)
	RemoveStream(sid string)
	HandleEvent(eventToken *goSet.SecurityEventToken, sid string) error
	//	PushStreamHandler(stream *model.StreamStateRecord, eventBuf *buffer.EventPushBuffer)
	PollStreamHandler(sid string, params model.PollParameters) (map[string]string, bool)
	Shutdown()
	SetEventCounter(inCounter, outCounter prometheus.Counter)
	GetPushStreamCnt() float64
	GetPollStreamCnt() float64
}

type router struct {
	pushStreams         map[string]*model.StreamStateRecord
	pollStreams         map[string]*model.StreamStateRecord
	ctx                 context.Context
	enabled             bool
	issuerKeys          map[string]*rsa.PrivateKey
	pollBuffers         map[string]*buffer.EventPollBuffer
	pushBuffers         map[string]*buffer.EventPushBuffer
	provider            dbProviders.DbProviderInterface
	eventsIn, eventsOut prometheus.Counter
}

func (r *router) GetPushStreamCnt() float64 {
	return float64(len(r.pushStreams))
}

func (r *router) GetPollStreamCnt() float64 {
	return float64(len(r.pollStreams))
}

func NewRouter(provider dbProviders.DbProviderInterface) EventRouter {
	router := router{
		provider:    provider,
		pushStreams: map[string]*model.StreamStateRecord{},
		pollStreams: map[string]*model.StreamStateRecord{},
		pushBuffers: map[string]*buffer.EventPushBuffer{},
		pollBuffers: map[string]*buffer.EventPollBuffer{},
		issuerKeys:  map[string]*rsa.PrivateKey{},
		enabled:     false,
		ctx:         context.WithValue(context.Background(), "provider", provider),
	}

	states := router.provider.GetStateMap()

	for _, state := range states {
		router.UpdateStreamState(&state)
	}
	router.enabled = true
	return &router
}

func (r *router) incrementEventsOut() {
	/*
			Note:  Because the event router must initialize before the server is initialized, the
		    event counter cannot be initialized immediately. To avoid a who goes first conflict,
			the counter may briefly be nil during startup.

		    TODO:  Should the incrementer wait until r.eventsOut is not nil?  This will block the outbound stream
	*/
	if r.eventsOut == nil {
		eventLogger.Println("WARNING: events counter not initialized.")
		return
	}
	eventLogger.Printf("EventOut [%s]: Type: PUSH ", r.provider.Name())
	r.eventsOut.Inc()
}

func (r *router) SetEventCounter(inCounter, outCounter prometheus.Counter) {
	r.eventsOut = outCounter
	r.eventsIn = inCounter
}

func (r *router) initPushStream(sid string, state *model.StreamStateRecord, jtis []string) {
	pushBuffer := buffer.CreateEventPushBuffer(jtis)
	r.pushBuffers[sid] = pushBuffer
	go r.PushStreamHandler(state, pushBuffer)
}

func (r *router) UpdateStreamState(stream *model.StreamStateRecord) {
	if !stream.Inbound {
		// Preload any outstanding pending events (because we may be re-starting)
		jtis, _ := r.provider.GetEventIds(stream.StreamConfiguration.Id, model.PollParameters{
			MaxEvents:         0,
			ReturnImmediately: true,
			Acks:              nil,
			SetErrs:           nil,
			TimeoutSecs:       10,
		})
		// Preload the issuer keys to avoid necessary provider lookups
		issuer := stream.StreamConfiguration.Iss
		_, ok := r.issuerKeys[issuer]
		if !ok {
			key, err := r.provider.GetIssuerPrivateKey(issuer)
			if err != nil {
				eventLogger.Printf("ERROR[%s]: Unable to locate key for issuer %s", stream.StreamConfiguration.Id, issuer)
			}
			r.issuerKeys[issuer] = key
		}

		switch stream.StreamConfiguration.Delivery.GetMethod() {
		case model.DeliveryPoll:
			r.pollStreams[stream.StreamConfiguration.Id] = stream
			_, ok := r.pollBuffers[stream.StreamConfiguration.Id]
			if !ok {
				// TODO:  might have to check for existing events!
				r.pollBuffers[stream.StreamConfiguration.Id] = buffer.CreateEventPollBuffer(jtis)
			}
		case model.DeliveryPush:
			currentState, ok := r.pushStreams[stream.StreamConfiguration.Id]
			if ok {
				currentState.Update(stream)
			} else {
				r.pushStreams[stream.StreamConfiguration.Id] = stream
				r.initPushStream(stream.StreamConfiguration.Id, stream, jtis)
			}
		default:
			streamJson, _ := json.MarshalIndent(stream, "", " ")
			eventLogger.Printf("Unknown delivery method below.\n%s", streamJson)
		}

	}
}

/*
HandleEvent takes a new event received and adds it to the local token store. It then looks at the event to
evaluates if it should be added to any streams for outgoing propagation
*/
func (r *router) HandleEvent(eventToken *goSet.SecurityEventToken, sid string) error {
	// eventLogger.Println("\n", event.Event.String())

	streamState, err := r.provider.GetStreamState(sid)
	if err != nil {
		return err
	}

	event := r.provider.AddEvent(eventToken, sid)
	r.eventsIn.Inc()

	if streamState.Inbound && streamState.Receiver.RouteMode == model.RouteModeImport {
		// nothing more to do
		return nil
	}
	for _, stream := range r.pushStreams {
		routeMode := stream.Receiver.RouteMode
		if isOutboundStreamMatch(stream, event) {

			eventLogger.Printf("ROUTER: Selected:  Stream: %s Jti: %s, Mode: %s, Types: %v", stream.StreamConfiguration.Id, event.Jti, routeMode, event.Types)

			// The transmitter API will forward or sign/encrypt the event based on route mode at delivery time!
			r.provider.AddEventToStream(event.Jti, stream.Id)
			// This will cause the PollStreamHandler assigned to deliver the event
			r.pushBuffers[stream.StreamConfiguration.Id].SubmitEvent(event.Jti)
		}
	}

	for _, stream := range r.pollStreams {
		routeMode := stream.Receiver.RouteMode
		if isOutboundStreamMatch(stream, event) {
			eventLogger.Printf("ROUTER: Selected:  Stream: %s Jti: %s, Mode: %s, Types: %v", stream.StreamConfiguration.Id, event.Jti, routeMode, event.Types)

			// The transmitter API will forward or sign/encrypt the event based on route mode at delivery time!
			r.provider.AddEventToStream(event.Jti, stream.Id)
			// This causes the event to be available on the next poll
			r.pollBuffers[stream.StreamConfiguration.Id].SubmitEvent(event.Jti)
		}
	}
	return nil
}

func (r *router) PollStreamHandler(sid string, params model.PollParameters) (map[string]string, bool) {
	state := r.pollStreams[sid]
	if state.Status != model.StreamStateActive {
		eventLogger.Printf("POLL-SRV[%s]: Error Poll request but stream is not active", sid)
		return nil, false
	}

	key, ok := r.issuerKeys[state.StreamConfiguration.Iss]
	if !ok || key == nil {
		eventLogger.Printf("POLL-SRV[%s]: Error no issuer key available for %s", sid, state.StreamConfiguration.Iss)
		return nil, false
	}

	pollBuffer := r.pollBuffers[sid]
	jtiSlice, more := pollBuffer.GetEvents(params)

	jtiSize := 0
	if jtiSlice != nil {
		jtiSize = len(*jtiSlice)
	}

	var err error
	if jtiSize > 0 {
		sets := make(map[string]string, jtiSize)

		tokens := r.provider.GetEvents(*jtiSlice)
		for _, jwtToken := range *tokens {
			token := jwtToken.(goSet.SecurityEventToken)
			token.Issuer = state.StreamConfiguration.Iss
			token.Audience = state.StreamConfiguration.Aud
			token.IssuedAt = jwt.NewNumericDate(time.Now())

			sets[token.ID], err = token.JWS(jwt.SigningMethodRS256, key)
			if err != nil {
				eventLogger.Printf("POLL-SRV[%s]: Error signing: ", sid, err.Error())
			}
		}
		return sets, more
	}
	return map[string]string{}, false
}

/*
PushStreamHandler is started as a separate thread during the initialization of the eventRouter. To stop the handler the buffer is closed.
*/
func (r *router) PushStreamHandler(stream *model.StreamStateRecord, eventBuf *buffer.EventPushBuffer) {
	eventLogger.Printf("PUSH-HANDLER[%s]: Starting..", stream.StreamConfiguration.Id)

	rsaKey, ok := r.issuerKeys[stream.StreamConfiguration.Iss]
	if !ok || rsaKey == nil {
		eventLogger.Printf("PUSH-SRV[%s]: Error no issuer key available for %s", stream.StreamConfiguration.Id, stream.StreamConfiguration.Iss)
		// TODO: What should be done about undelivered events?
	}

	out := eventBuf.Out
eventLoop:
	for v := range out {
		jti := v.(string)
		r.prepareAndSendEvent(jti, stream, rsaKey)
		if stream.Status != model.StreamStateActive {
			eventLogger.Printf("PUSH-SRV[%s] is no longer active. PushHandler exiting.", stream.Id.Hex())
			break eventLoop
		}
	}
	eventLogger.Printf("PUSH-SRV[%s]: Stopped.", stream.StreamConfiguration.Id)
}

func (r *router) prepareAndSendEvent(jti string, config *model.StreamStateRecord, rsaKey *rsa.PrivateKey) {
	events := r.provider.GetEvents([]string{jti}) // Get the event
	if events != nil && len(*events) > 0 {
		delivered := r.pushEvent(config.StreamConfiguration, *events, rsaKey)
		if delivered != nil {
			items := *delivered
			if len(items) > 0 {
				for _, jti := range items {
					r.provider.AckEvent(jti, config.StreamConfiguration.Id)
					r.incrementEventsOut()
				}

			}
		}
	}
}

// pushEvent implements the server push side (http client) of RFC8935 Push Based Delivery of SET Events
// Note: Moved from the api_transmitter.go in server package
func (r *router) pushEvent(configuration model.StreamConfiguration, events []jwt.Claims, key *rsa.PrivateKey) *[]string {
	jtis := make([]string, len(events))
	pushConfig := configuration.Delivery.PushDeliveryMethod

	client := http.Client{Timeout: 60 * time.Second}

	for i, jwtToken := range events {
		token := jwtToken.(goSet.SecurityEventToken)
		url := pushConfig.EndpointUrl

		token.Issuer = configuration.Iss
		token.Audience = configuration.Aud
		token.IssuedAt = jwt.NewNumericDate(time.Now())
		tokenString, err := token.JWS(jwt.SigningMethodRS256, key)
		if err != nil {
			eventLogger.Printf("PUSH-SRV[%s] Error signing event: ", configuration.Id, err.Error())
		}

		req, err := http.NewRequest("POST", url, strings.NewReader(tokenString))

		if pushConfig.AuthorizationHeader != "" {
			authz := pushConfig.AuthorizationHeader
			if strings.ToLower(authz[0:4]) != "bear" {
				authz = "Bearer " + authz
			}
			req.Header.Set("Authorization", authz)
		}
		req.Header.Set("Content-Type", "application/secevent+jwt")
		req.Header.Set("Accept", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			errMsg := fmt.Sprintf("PUSH-SRV[%s]Error sending: %s", configuration.Id, err.Error())
			eventLogger.Println(errMsg)
			return &jtis
		}
		if resp.StatusCode != http.StatusAccepted {
			if resp.StatusCode == http.StatusBadRequest {
				var errorMsg model.SetDeliveryErr
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					r.provider.PauseStream(configuration.Id, model.StreamStatePause, "Unable to read response")
					eventLogger.Println("PUSH-SRV[%s] Error reading response: ", configuration.Id, err.Error())
					return &jtis
				}
				err = json.Unmarshal(body, &errorMsg)
				if err != nil {
					eventLogger.Println("PUSH-SRV[%s] Error parsing error response: ", configuration.Id, err.Error())
					r.provider.PauseStream(configuration.Id, model.StreamStatePause, "Unable to parse JSON response")
					return &jtis
				}
				errMsg := fmt.Sprintf("PUSH-SRV[%s] %s", errorMsg.ErrCode, errorMsg.Description)
				eventLogger.Println(errMsg)
				r.provider.PauseStream(configuration.Id, model.StreamStatePause, errMsg)
				return &jtis
			}
			if resp.StatusCode > 400 {
				errMsg := fmt.Sprintf("PUSH-SRV[%s] HTTP Error: %s, POSTING to %s", configuration.Id, resp.Status, url)
				eventLogger.Println(errMsg)
				r.provider.PauseStream(configuration.Id, model.StreamStatePause, errMsg)
			}
		}

		jtis[i] = token.ID

	}

	eventLogger.Printf("PUSH-SRV[%s] JTIs delivered: %s", configuration.Id, jtis)
	return &jtis
}

func isOutboundStreamMatch(stream *model.StreamStateRecord, event *model.EventRecord) bool {
	// First check that the direction of the stream matches the event InBound = true means local consumption
	if stream.Inbound == true && stream.Receiver.RouteMode == model.RouteModeImport {
		return false
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
		delete(r.pollStreams, sid)
		delete(r.pollBuffers, sid)
	}
	eventLogger.Printf("STREAM [%s] Removed from router", sid)
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
