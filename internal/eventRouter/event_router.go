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
	"go.mongodb.org/mongo-driver/bson/primitive"
)

var eventLogger = log.New(os.Stdout, "ROUTER: ", log.Ldate|log.Ltime)

type EventRouter interface {
	UpdateStreamState(stream model.StreamStateRecord)
	RemoveStreamState(id primitive.ObjectID)
	HandleEvent(event model.EventRecord)
	//	PushStreamHandler(stream *model.StreamStateRecord, eventBuf *buffer.EventPushBuffer)
	PollStreamHandler(sid string, params model.PollParameters) (map[string]string, bool)
	Shutdown()
}

type router struct {
	pushStreams map[string]model.StreamStateRecord
	pollStreams map[string]model.StreamStateRecord
	ctx         context.Context
	enabled     bool
	issuerKeys  map[string]*rsa.PrivateKey
	pollBuffers map[string]*buffer.EventPollBuffer
	pushBuffers map[string]*buffer.EventPushBuffer
	provider    dbProviders.DbProviderInterface
}

func NewRouter(provider dbProviders.DbProviderInterface) EventRouter {
	router := router{
		provider:    provider,
		pushStreams: map[string]model.StreamStateRecord{},
		pollStreams: map[string]model.StreamStateRecord{},
		pushBuffers: map[string]*buffer.EventPushBuffer{},
		pollBuffers: map[string]*buffer.EventPollBuffer{},
		issuerKeys:  map[string]*rsa.PrivateKey{},
		enabled:     false,
		ctx:         context.WithValue(context.Background(), "provider", provider),
	}

	states := router.provider.GetStateMap()

	for k, state := range states {
		if state.Inbound == false {
			// Load any outstanding pending events (because we may be re-starting)
			jtis, _ := provider.GetEventIds(state.StreamConfiguration.Id, model.PollParameters{
				MaxEvents:         0,
				ReturnImmediately: true,
				Acks:              nil,
				SetErrs:           nil,
				TimeoutSecs:       10,
			})

			// Preload the issuer keys to avoid necessary provider lookups
			issuer := state.StreamConfiguration.Iss
			_, ok := router.issuerKeys[issuer]
			if !ok {
				key, err := provider.GetIssuerPrivateKey(issuer)
				if err != nil {
					eventLogger.Printf("INIT ERROR[%s]: Unable to locate key for issuer %s", state.StreamConfiguration.Id, issuer)
				}
				router.issuerKeys[issuer] = key
			}
			if state.StreamConfiguration.Delivery.PollDeliveryMethod.Method == model.DeliveryPoll {
				router.pollStreams[k] = state
				pollBuffer := buffer.CreateEventPollBuffer(jtis)
				router.pollBuffers[k] = pollBuffer
			} else {
				router.pushStreams[k] = state
				pushBuffer := buffer.CreateEventPushBuffer(jtis)
				router.pushBuffers[k] = pushBuffer
				go router.PushStreamHandler(&state, pushBuffer)
			}
		}
	}
	router.enabled = true
	return &router
}

func (r *router) UpdateStreamState(stream model.StreamStateRecord) {
	if stream.StreamConfiguration.Delivery.PollDeliveryMethod.Method == model.DeliveryPoll {
		r.pollStreams[stream.StreamConfiguration.Id] = stream
	} else {
		if stream.StreamConfiguration.Delivery.PushDeliveryMethod.Method == model.DeliveryPush {
			r.pushStreams[stream.StreamConfiguration.Id] = stream
		}
	}
}

func (r *router) RemoveStreamState(id primitive.ObjectID) {
	streamMap := r.pushStreams
	if _, ok := streamMap[id.Hex()]; ok {
		delete(streamMap, id.Hex())
	}
}

func (r *router) HandleEvent(event model.EventRecord) {
	// eventLogger.Println("\n", event.Event.String())

	for _, stream := range r.pushStreams {
		if isOutboundStreamMatch(stream, event) {

			eventLogger.Printf("ROUTER: Selected:  Stream: %s Jti: %s, Mode: %s, Types: %v", stream.StreamConfiguration.Id, event.Jti, "PUSH", event.Types)
			r.provider.AddEventToStream(event.Jti, stream.Id)
			// This will cause the PollStreamHandler assigned to deliver the event

			r.pushBuffers[stream.StreamConfiguration.Id].SubmitEvent(event.Jti)
		}
	}

	for _, stream := range r.pollStreams {
		if isOutboundStreamMatch(stream, event) {
			eventLogger.Printf("ROUTER: Selected:  Stream: %s Jti: %s, Mode: %s, Types: %v", stream.StreamConfiguration.Id, event.Jti, "POLL", event.Types)
			r.provider.AddEventToStream(event.Jti, stream.Id)
			// This causes the event to be available on the next poll
			r.pollBuffers[stream.StreamConfiguration.Id].SubmitEvent(event.Jti)
		}
	}
}

func (r *router) PollStreamHandler(sid string, params model.PollParameters) (map[string]string, bool) {
	state := r.pollStreams[sid]
	if state.Status != model.StreamStateActive {
		eventLogger.Printf("POLL-HANDLER[%s]: Error Poll request but stream is not active", sid)
		return nil, false
	}

	key, ok := r.issuerKeys[state.StreamConfiguration.Iss]
	if !ok || key == nil {
		eventLogger.Printf("POLL-HANDLER[%s]: Error no issuer key available for %s", sid, state.StreamConfiguration.Iss)
		return nil, false
	}

	pollBuffer := r.pollBuffers[sid]
	jtiSlice, more := pollBuffer.GetEvents(params)

	jtiSize := len(*jtiSlice)

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
				eventLogger.Printf("POLL-HANDLER[%s]: Error signing: ", sid, err.Error())
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
	rsaKey, err := r.provider.GetIssuerPrivateKey(stream.StreamConfiguration.Iss)
	if err != nil {
		eventLogger.Printf("PUSH-HANDLER[%s]: ERROR Loading issuer key: %s", stream.StreamConfiguration.Id, err.Error())
	}

	out := eventBuf.Out
eventLoop:
	for v := range out {
		jti := v.(string)
		r.sendEvent(jti, stream, rsaKey)
		if stream.Status != model.StreamStateActive {
			log.Printf("Stream %s is no longer active. PushHandler exiting.", stream.Id.Hex())
			break eventLoop
		}
	}
	eventLogger.Printf("PUSH-HANDLER[%s]: Stopped.", stream.StreamConfiguration.Id)
}

func (r *router) sendEvent(jti string, config *model.StreamStateRecord, rsaKey *rsa.PrivateKey) {
	events := r.provider.GetEvents([]string{jti}) // Get the event
	if events != nil && len(*events) > 0 {
		delivered := r.PushEvent(config.StreamConfiguration, *events, rsaKey)
		if delivered != nil {
			items := *delivered
			if len(items) > 0 {
				for _, jti := range items {
					r.provider.AckEvent(jti, config.StreamConfiguration.Id)
				}

			}
		}
	}
}

// PushEvent implements the server push side (http client) of RFC8935 Push Based Delivery of SET Events
// Note: Moved from the api_transmitter.go in server package
func (r *router) PushEvent(configuration model.StreamConfiguration, events []jwt.Claims, key *rsa.PrivateKey) *[]string {
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
					r.provider.PauseStream(configuration.Id, model.StreamStatePause, "Unable to read response")
					log.Println("TRANSMIT PUSH Error reading response: " + err.Error())
					return &jtis
				}
				err = json.Unmarshal(body, &errorMsg)
				if err != nil {
					log.Println("TRANSMIT PUSH Error parsing error response: " + err.Error())
					r.provider.PauseStream(configuration.Id, model.StreamStatePause, "Unable to parse JSON response")
					return &jtis
				}
				errMsg := fmt.Sprintf("TRANSMIT PUSH [%s] %s", errorMsg.ErrCode, errorMsg.Description)
				log.Println(errMsg)
				r.provider.PauseStream(configuration.Id, model.StreamStatePause, errMsg)
				return &jtis
			}
			if resp.StatusCode > 400 {
				errMsg := fmt.Sprintf("TRANSMIT PUSH HTTP Error: %s, POSTING to %s", resp.Status, url)
				log.Println(errMsg)
				r.provider.PauseStream(configuration.Id, model.StreamStatePause, errMsg)
			}
		}

		jtis[i] = token.ID

	}

	log.Printf("Events delivered: %s", jtis)
	return &jtis
}

func isOutboundStreamMatch(stream model.StreamStateRecord, event model.EventRecord) bool {
	// First check that the direction of the stream matches the event InBound = true means local consumption
	if stream.Inbound != event.Inbound {
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

// Shutdown closes all the PushHandlers. Events will continue to be routed but only delivered when server restarts
func (r *router) Shutdown() {
	// This will shut down the threads that are pushing events.
	r.enabled = false
	for _, pushBuffer := range r.pushBuffers {
		pushBuffer.Close()
	}

	// Nothing need to be done for polling because.
}
