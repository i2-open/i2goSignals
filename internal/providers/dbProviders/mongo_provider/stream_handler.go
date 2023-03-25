package mongo_provider

import (
	"context"
	"i2goSignals/internal/model"
	"i2goSignals/pkg/goSSEF/server"
	"log"
	"sync"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

/*
InitializeStreams sets up the MongoDb Change streams to start Event Push streams (RFC8935) and support long polling
for new Events (RFC8936).
*/
func (m *MongoProvider) InitializeStreams() {
	eventStreams := m.ListStreams()
	if len(eventStreams) == 0 {
		log.Default().Println("No streams started. No stream configurations defined.")
		return
	}
	for _, stream := range eventStreams {
		delivery := stream.Delivery
		// push := delivery.PushDeliveryMethod
		poll := delivery.PollDeliveryMethod
		var err error
		if poll != nil {
			err = m.initializePollStream(stream)
		} else {
			err = m.initializePushStream(stream)
		}
		if err != nil {
			log.Printf("Error: Stream initialization error (stream %s): %v", stream.Id, err)
		}
	}
	return
}

func (m *MongoProvider) initializePollStream(configuration model.StreamConfiguration) error {

	return nil
}

func (m *MongoProvider) initializePushStream(configuration model.StreamConfiguration) error {
	streamState, err := m.getStreamState(configuration.Id)
	if err != nil {
		return err
	}

	if streamState.Status == CState_Inactive {
		log.Println("StreamId: " + configuration.Id + " is INACTIVE. Not started")
		return nil
	}

	var waitGroup sync.WaitGroup

	matchInserts := bson.D{
		{
			"$match", bson.D{
				{"operationType", "insert"},
				{"fullDocument.StreamId", streamState.Id}},
		},
	}

	eventStream, err := m.pendingCol.Watch(context.TODO(), mongo.Pipeline{matchInserts})
	if err != nil {
		log.Println("Error: Unable to initialize event stream: " + err.Error())
	}
	waitGroup.Add(1)

	routineCtx := context.WithValue(context.Background(), "streamid", configuration.Id)
	go m.iteratePendingPush(routineCtx, &waitGroup, eventStream, configuration)

	// waitGroup.Wait()
	return nil
}

func (m *MongoProvider) iteratePendingPush(ctx context.Context, group *sync.WaitGroup, stream *mongo.ChangeStream, configuration model.StreamConfiguration) {
	defer stream.Close(ctx)

	defer group.Done()

	jtis, _ := m.GetEventIds(configuration.Id, model.PollParameters{MaxEvents: CBatch_Size,
		ReturnImmediately: true})
	for len(jtis) > 0 {
		events := m.GetEvents(jtis)
		ackIds := server.PushEvents(configuration, *events)
		if ackIds != nil {
			for _, ack := range *ackIds {
				m.AckEvent(ack, configuration.Id)
			}
		}
		// Keep looping until all events sent
		jtis, _ = m.GetEventIds(configuration.Id, model.PollParameters{MaxEvents: CBatch_Size, ReturnImmediately: true})
	}
	// This will pause the steam if it is marked inactive
	m.checkStreamState(ctx, configuration) //

	for stream.Next(ctx) {
		// New events are available.  Get the next ones
		jtis, _ = m.GetEventIds(configuration.Id, model.PollParameters{MaxEvents: CBatch_Size, ReturnImmediately: true})
		if len(jtis) == 0 {
			// This loop will actually fire for each change. If events already processed, just ignore
			continue
		} else {
			events := m.GetEvents(jtis)
			ackIds := server.PushEvents(configuration, *events)
			if ackIds != nil {
				for _, ack := range *ackIds {
					m.AckEvent(ack, configuration.Id)
				}
			}
		}
		// Check that the stream hasn't paused
		m.checkStreamState(ctx, configuration) //
	}
}

func (m *MongoProvider) checkStreamState(ctx context.Context, configuration model.StreamConfiguration) bool {
	state, _ := m.getStreamState(configuration.Id)
	if state.Status == CState_Active {
		return true
	}
	// wait indefinitely for stream state to go active
	for state.Status != CState_Active {
		if !m.waitForStreamChange(ctx, state.Id) {
			return false
		}
		state, _ = m.getStreamState(configuration.Id)
	}
	return true
}

/*
waitForStreamChange waits until the stream state document has been updated to active (in order to effect a pause
*/
func (m *MongoProvider) waitForStreamChange(ctx context.Context, streamId primitive.ObjectID) bool {
	matchState := bson.D{
		{
			"$match", bson.D{
				{"operationType", "modify"},
				{"fullDocument.Id", streamId}},
		},
	}

	eventStream, err := m.streamCol.Watch(context.TODO(), mongo.Pipeline{matchState})
	if err != nil {
		log.Println("Error: Unable to initialize event stream: " + err.Error())
	}
	if eventStream.Next(ctx) {
		return true
	}
	return false
}

func processChangeEvent(ctx context.Context, stream *mongo.ChangeStream) *EventRecord {
	var changeEvent pendingChangeEvent
	if err := stream.Decode(&changeEvent); err != nil {
		log.Fatal(err)
	}
	stream.Decode(&changeEvent)

	return &changeEvent.FullDocument
}
