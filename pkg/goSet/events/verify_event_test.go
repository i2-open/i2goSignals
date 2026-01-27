package events

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCreateVerifyEvent(t *testing.T) {
	streamId := "test-stream-id"
	state := "test-state"
	issuer := "https://transmitter.example.com"
	audience := []string{"https://receiver.example.com"}

	set := CreateVerifyEvent(streamId, state, issuer, audience)

	assert.NotNil(t, set)
	assert.Equal(t, issuer, set.Issuer)
	assert.Equal(t, audience, []string(set.Audience))

	// Check subject
	assert.NotNil(t, set.SubjectId)
	assert.Equal(t, "opaque", set.SubjectId.Format)
	assert.Equal(t, streamId, set.SubjectId.Id)

	// Check event payload
	payloadInterface, ok := set.Events[VerificationEventUri]
	assert.True(t, ok)

	payload, ok := payloadInterface.(VerifyPayload)
	assert.True(t, ok)
	assert.Equal(t, state, payload.State)

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
	verifyEvent, ok := events[VerificationEventUri].(map[string]interface{})
	assert.True(t, ok)
	assert.Equal(t, state, verifyEvent["state"])
}

func TestCreateVerifyEventNoStream(t *testing.T) {
	state := "test-state"
	issuer := "https://transmitter.example.com"
	audience := []string{"https://receiver.example.com"}

	set := CreateVerifyEvent("", state, issuer, audience)

	assert.NotNil(t, set)
	assert.Nil(t, set.SubjectId)
	assert.Empty(t, set.Subject)

	payloadInterface, ok := set.Events[VerificationEventUri]
	assert.True(t, ok)
	payload := payloadInterface.(VerifyPayload)
	assert.Equal(t, state, payload.State)
}

func TestCreateVerifyEventNoState(t *testing.T) {
	streamId := "test-stream-id"
	issuer := "https://transmitter.example.com"
	audience := []string{"https://receiver.example.com"}

	set := CreateVerifyEvent(streamId, "", issuer, audience)

	assert.NotNil(t, set)
	payloadInterface, ok := set.Events[VerificationEventUri]
	assert.True(t, ok)
	payload := payloadInterface.(VerifyPayload)
	assert.Empty(t, payload.State)

	// Verify state is omitted in JSON
	jsonBytes, err := json.Marshal(set)
	assert.NoError(t, err)

	var jsonMap map[string]interface{}
	err = json.Unmarshal(jsonBytes, &jsonMap)
	assert.NoError(t, err)

	events := jsonMap["events"].(map[string]interface{})
	verifyEvent := events[VerificationEventUri].(map[string]interface{})
	_, ok = verifyEvent["state"]
	assert.False(t, ok, "state should be omitted if empty")
}
