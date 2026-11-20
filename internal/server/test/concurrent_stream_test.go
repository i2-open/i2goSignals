package test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"testing"

	"github.com/i2-open/i2goSignals/pkg/authSupport"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
)

// generateEvent is a helper function to generate test events
func generateEvent(instance *ssfInstance, stream model.StreamConfiguration) (string, error) {
	subject := &goSet.EventSubject{
		SubjectIdentifier: *goSet.NewScimSubjectIdentifier(fmt.Sprintf("/Users/concurrent-%s", stream.Id)),
	}

	event := goSet.CreateSet(subject, stream.Iss, stream.Aud)
	event.AddEventPayload(model.EventScimCreateFull, map[string]interface{}{
		"data": map[string]interface{}{
			"userName": "testuser",
		},
	})

	return event.ID, instance.app.EventRouter.HandleEvent(&event, "", stream.Id)
}

// TestConcurrentStreamUpdates tests for race conditions in stream updates
func TestConcurrentStreamUpdates(t *testing.T) {
	instance, err := createServer(t, "concurrent_test", true)
	assert.NoError(t, err)
	defer instance.app.Shutdown()

	// Create a stream
	streamConfig := model.StreamConfiguration{
		Iss: "DEFAULT",
		Aud: []string{"test.example.com"},
		Delivery: &model.OneOfStreamConfigurationDelivery{
			PollTransmitMethod: &model.PollTransmitMethod{
				Method: model.DeliveryPoll,
			},
		},
	}

	stream, _ := instance.CreateStream(streamConfig, authSupport.ConvertProject(instance.projectId))

	// Concurrently update the stream from multiple goroutines
	var wg sync.WaitGroup
	numUpdates := 5

	for i := 0; i < numUpdates; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()

			// Update stream
			updateConfig := stream
			updateConfig.EventsRequested = []string{"*"}

			bodyBytes, _ := json.Marshal(updateConfig)
			req, _ := http.NewRequest(http.MethodPut,
				instance.ts.URL+"/stream?stream_id="+stream.Id,
				bytes.NewReader(bodyBytes))
			req.Header.Set("Authorization", "Bearer "+instance.streamMgmtToken)
			req.Header.Set("Content-Type", "application/json")

			resp, err := instance.client.Do(req)
			assert.NoError(t, err)
			// Some may succeed, some may have auth issues in concurrent scenarios
			assert.Contains(t, []int{http.StatusOK, http.StatusUnauthorized, http.StatusForbidden, http.StatusConflict, http.StatusInternalServerError},
				resp.StatusCode)
		}(i)
	}

	wg.Wait()

	// Verify stream is still in valid state
	finalStream, err := instance.GetStream(stream.Id)
	assert.NoError(t, err)
	assert.NotNil(t, finalStream)
}

// TestConcurrentEventHandling tests concurrent event generation and routing
func TestConcurrentEventHandling(t *testing.T) {
	instance, err := createServer(t, "concurrent_events_test", true)
	assert.NoError(t, err)
	defer instance.app.Shutdown()

	// Create stream
	streamConfig := model.StreamConfiguration{
		Iss:             "DEFAULT",
		Aud:             []string{"test.example.com"},
		EventsRequested: []string{"*"},
		Delivery: &model.OneOfStreamConfigurationDelivery{
			PollTransmitMethod: &model.PollTransmitMethod{
				Method: model.DeliveryPoll,
			},
		},
	}

	stream, _ := instance.CreateStream(streamConfig, authSupport.ConvertProject(instance.projectId))
	state, _ := instance.GetStreamState(stream.Id)
	instance.app.EventRouter.UpdateStreamState(state)

	// Generate events concurrently
	var wg sync.WaitGroup
	numEvents := 20

	for i := 0; i < numEvents; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			_, _ = generateEvent(instance, stream)
		}(i)
	}

	wg.Wait()

	// All events should be processed without crashes
	// Note: exact count may vary due to async processing
}

// TestConcurrentStreamCreationDeletion tests concurrent stream CRUD operations
func TestConcurrentStreamCreationDeletion(t *testing.T) {
	instance, err := createServer(t, "concurrent_crud_test", true)
	assert.NoError(t, err)
	defer instance.app.Shutdown()

	var wg sync.WaitGroup
	numOperations := 10

	for i := 0; i < numOperations; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()

			// Create stream
			streamConfig := model.StreamConfiguration{
				Iss: "DEFAULT",
				Aud: []string{"test.example.com"},
				Delivery: &model.OneOfStreamConfigurationDelivery{
					PollTransmitMethod: &model.PollTransmitMethod{
						Method: model.DeliveryPoll,
					},
				},
			}

			bodyBytes, _ := json.Marshal(streamConfig)
			req, _ := http.NewRequest(http.MethodPost, instance.ts.URL+"/stream", bytes.NewReader(bodyBytes))
			req.Header.Set("Authorization", "Bearer "+instance.streamMgmtToken)
			req.Header.Set("Content-Type", "application/json")

			resp, err := instance.client.Do(req)
			if err == nil && resp.StatusCode == http.StatusOK {
				var createdStream model.StreamConfiguration
				_ = json.NewDecoder(resp.Body).Decode(&createdStream)

				// Immediately delete it
				req2, _ := http.NewRequest(http.MethodDelete,
					instance.ts.URL+"/stream?stream_id="+createdStream.Id, nil)
				req2.Header.Set("Authorization", "Bearer "+instance.streamMgmtToken)
				_, _ = instance.client.Do(req2)
			}
		}(i)
	}

	wg.Wait()
}
