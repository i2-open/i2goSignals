package events

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCreateStatusUpdatedEvent(t *testing.T) {
	streamId := "test-stream-id"
	status := "enabled"
	reason := "test-reason"
	issuer := "https://transmitter.example.com"
	audience := []string{"https://receiver.example.com"}

	set := CreateStatusUpdatedEvent(streamId, status, reason, issuer, audience)

	assert.NotNil(t, set)
	assert.Equal(t, issuer, set.Issuer)
	assert.Equal(t, audience, []string(set.Audience))

	// Check subject
	assert.NotNil(t, set.SubjectId)
	assert.Equal(t, "opaque", set.SubjectId.Format)
	assert.Equal(t, streamId, set.SubjectId.Id)

	// Check event payload
	payloadInterface, ok := set.Events[StatusUpdatedEventUri]
	assert.True(t, ok)

	payload, ok := payloadInterface.(StreamUpdatePayload)
	assert.True(t, ok)
	assert.Equal(t, status, payload.Status)
	assert.NotNil(t, payload.Reason)
	assert.Equal(t, reason, *payload.Reason)

	// Verify JSON marshaling
	jsonBytes, err := json.Marshal(set)
	assert.NoError(t, err)

	var jsonMap map[string]interface{}
	err = json.Unmarshal(jsonBytes, &jsonMap)
	assert.NoError(t, err)

	// Check sub_id in JSON
	subId, ok := jsonMap["sub_id"].(map[string]interface{})
	assert.True(t, ok)
	assert.Equal(t, "opaque", subId["format"])
	assert.Equal(t, streamId, subId["id"])

	// Check events in JSON
	events, ok := jsonMap["events"].(map[string]interface{})
	assert.True(t, ok)
	updateEvent, ok := events[StatusUpdatedEventUri].(map[string]interface{})
	assert.True(t, ok)
	assert.Equal(t, status, updateEvent["status"])
	assert.Equal(t, reason, updateEvent["reason"])
}

func TestCreateStatusUpdatedEventNoStream(t *testing.T) {
	status := "disabled"
	reason := "test-reason"
	issuer := "https://transmitter.example.com"
	audience := []string{"https://receiver.example.com"}

	set := CreateStatusUpdatedEvent("", status, reason, issuer, audience)

	assert.NotNil(t, set)
	assert.Nil(t, set.SubjectId)
	assert.Empty(t, set.Subject)

	payloadInterface, ok := set.Events[StatusUpdatedEventUri]
	assert.True(t, ok)
	payload := payloadInterface.(StreamUpdatePayload)
	assert.Equal(t, status, payload.Status)
	assert.Equal(t, reason, *payload.Reason)
}

func TestCreateStatusUpdatedEventNoReason(t *testing.T) {
	streamId := "test-stream-id"
	status := "paused"
	issuer := "https://transmitter.example.com"
	audience := []string{"https://receiver.example.com"}

	set := CreateStatusUpdatedEvent(streamId, status, "", issuer, audience)

	assert.NotNil(t, set)
	payloadInterface, ok := set.Events[StatusUpdatedEventUri]
	assert.True(t, ok)
	payload := payloadInterface.(StreamUpdatePayload)
	assert.Equal(t, status, payload.Status)
	assert.Nil(t, payload.Reason)

	// Verify reason is omitted in JSON
	jsonBytes, err := json.Marshal(set)
	assert.NoError(t, err)

	var jsonMap map[string]interface{}
	err = json.Unmarshal(jsonBytes, &jsonMap)
	assert.NoError(t, err)

	events := jsonMap["events"].(map[string]interface{})
	updateEvent := events[StatusUpdatedEventUri].(map[string]interface{})
	_, ok = updateEvent["reason"]
	assert.False(t, ok, "reason should be omitted if empty")
	assert.Equal(t, status, updateEvent["status"])
}
