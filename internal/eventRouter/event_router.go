package eventRouter

import (
	"context"
	"crypto/rsa"
	"i2goSignals/internal/eventRouter/buffer"
	"i2goSignals/internal/model"
	"i2goSignals/internal/providers/dbProviders/mongo_provider"
	"i2goSignals/pkg/goSSEF/server"
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
	HandleEvent(event mongo_provider.EventRecord)
	PushStreamHandler(stream *model.StreamStateRecord, eventBuf *buffer.EventPushBuffer)
	PollStreamHandler(sid string, params model.PollParameters) (map[string]string, bool)
}

type router struct {
	pushStreams map[string]model.StreamStateRecord
	pollStreams map[string]model.StreamStateRecord
	ctx         context.Context
	enabled     bool
	issuerKeys  map[string]*rsa.PrivateKey
	pollBuffers map[string]*buffer.EventPollBuffer
	pushBuffers map[string]*buffer.EventPushBuffer
	signalsApp  *server.SignalsApplication
}

func NewRouter(application *server.SignalsApplication) EventRouter {
	router := router{
		signalsApp:  application,
		pushStreams: map[string]model.StreamStateRecord{},
		pollStreams: map[string]model.StreamStateRecord{},
		pushBuffers: map[string]*buffer.EventPushBuffer{},
		pollBuffers: map[string]*buffer.EventPollBuffer{},
		issuerKeys:  map[string]*rsa.PrivateKey{},
		enabled:     false,
		ctx:         context.WithValue(context.Background(), "app", &application),
	}

	states := application.Provider.GetStateMap()

	for k, state := range states {
		if state.Inbound == false {
			// Load any outstanding pending events (because we may be re-starting)
			jtis, _ := application.Provider.GetEventIds(state.StreamConfiguration.Id, model.PollParameters{
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
				key, err := application.Provider.GetIssuerPrivateKey(issuer)
				if err != nil {
					eventLogger.Printf("INIT ERROR[%s]: Unable to locate key for issuer %s", state.StreamConfiguration.Id, issuer)
				}
				router.issuerKeys[issuer] = key
			}
			if state.StreamConfiguration.Delivery.PollDeliveryMethod.Method == model.DeliveryPoll {
				router.pollStreams[k] = state
				pollBuffer := buffer.CreateEventPollBuffer()
				if len(jtis) > 0 {
					pollBuffer.AddEvents(jtis)
				}
				router.pollBuffers[k] = pollBuffer
			} else {
				router.pushStreams[k] = state

				pushBuffer := buffer.CreateEventPushBuffer(jtis)
				router.pushBuffers[k] = pushBuffer
				go router.PushStreamHandler(&state, pushBuffer)
			}
		}
	}

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

func (r *router) HandleEvent(event mongo_provider.EventRecord) {
	// eventLogger.Println("\n", event.Event.String())
	for _, stream := range r.pushStreams {
		if isOutboundStreamMatch(stream, event) {
			dir := "OUT"

			eventLogger.Printf("ROUTER: Selected:  Stream: %s Jti: %s, Dir: %s, Types: %v", stream.StreamConfiguration.Id, event.Jti, dir, event.Types)
			r.signalsApp.Provider.AddEventToStream(event.Jti, stream.Id)
			r.pushBuffers[stream.StreamConfiguration.Id].SubmitEvent(event.Jti)
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

		tokens := r.signalsApp.Provider.GetEvents(*jtiSlice)
		for _, token := range *tokens {
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

func (r *router) PushStreamHandler(stream *model.StreamStateRecord, eventBuf *buffer.EventPushBuffer) {
	eventLogger.Printf("PUSH-HANDLER[%s]: Starting..", stream.StreamConfiguration.Id)
	rsaKey, err := r.signalsApp.Provider.GetIssuerPrivateKey(stream.StreamConfiguration.Iss)
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
	events := r.signalsApp.Provider.GetEvents([]string{jti}) // Get the event
	if events != nil && len(*events) > 0 {
		delivered := r.signalsApp.PushEvents(config.StreamConfiguration, *events, rsaKey)
		if delivered != nil {
			items := *delivered
			if len(items) > 0 {
				for _, jti := range items {
					r.signalsApp.Provider.AckEvent(jti, config.StreamConfiguration.Id)
				}

			}
		}
	}
}

func isOutboundStreamMatch(stream model.StreamStateRecord, event mongo_provider.EventRecord) bool {
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
