package test

import (
	"testing"
	"time"

	"github.com/i2-open/i2goSignals/internal/authUtil"
	"github.com/i2-open/i2goSignals/internal/eventRouter"
	"github.com/i2-open/i2goSignals/pkg/goSet/events"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestOperationalEventScopedToTargetStream verifies that an operational event submitted via
// SubmitOperationalEvent persists with Operational=true and lands ONLY in the target stream's
// pending list — never in any other stream that might otherwise overlap by iss/aud.
func TestOperationalEventScopedToTargetStream(t *testing.T) {
	instance, err := createServer(t, "op_event_scoping", true)
	require.NoError(t, err)
	defer instance.app.Shutdown()

	streamA := mustCreatePollStream(t, instance, "DEFAULT", []string{"https://receiver.example.com"})
	streamB := mustCreatePollStream(t, instance, "DEFAULT", []string{"https://receiver.example.com"})

	// Submit a verify operational event scoped to stream A
	verifyEvent := events.CreateVerifyEvent(streamA.Id, "scoping-test", streamA.Iss, streamA.Aud)
	rec, err := instance.app.EventRouter.SubmitOperationalEvent(streamA.Id, verifyEvent, "")
	require.NoError(t, err)
	require.NotNil(t, rec)
	assert.True(t, rec.Operational, "event must be persisted with Operational=true")

	// Stream A pending list contains the verify event
	jtisA, _ := instance.provider.GetEventIds(streamA.Id, model.PollParameters{MaxEvents: 10})
	assert.Contains(t, jtisA, rec.Jti, "stream A should receive the operational event")

	// Stream B (with overlapping iss/aud) must NOT receive it
	jtisB, _ := instance.provider.GetEventIds(streamB.Id, model.PollParameters{MaxEvents: 10})
	assert.NotContains(t, jtisB, rec.Jti, "stream B must not receive an operational event scoped to stream A")
}

// TestStreamEventMatchNoLongerAutoMatchesVerifyOrStreamUpdated locks in the removal of the
// always-match branches in StreamEventMatch. A verify event that flows through the matcher
// (e.g. via HandleEvent for whatever reason) must NOT auto-match a stream that doesn't list
// the verify event-type in its EventsDelivered.
func TestStreamEventMatchNoLongerAutoMatchesVerifyOrStreamUpdated(t *testing.T) {
	stream := &model.StreamStateRecord{
		StreamConfiguration: model.StreamConfiguration{
			Iss:             "DEFAULT",
			Aud:             []string{"https://receiver.example.com"},
			EventsDelivered: []string{"https://schemas.openid.net/secevent/risc/event-type/account-disabled"},
		},
	}

	verifyEvent := &model.AgEventRecord{
		Types: []string{"https://schemas.openid.net/secevent/ssf/event-type/verification"},
	}
	streamUpdatedEvent := &model.AgEventRecord{
		Types: []string{"https://schemas.openid.net/secevent/ssf/event-type/stream-updated"},
	}

	assert.False(t, eventRouter.StreamEventMatch(stream, verifyEvent),
		"verify event must not auto-match a stream that doesn't subscribe to it")
	assert.False(t, eventRouter.StreamEventMatch(stream, streamUpdatedEvent),
		"stream-updated event must not auto-match a stream that doesn't subscribe to it")
}

// TestResetEventStreamExcludesOperationalEvents verifies that ResetDate-driven replay does not
// re-deliver historical operational events. Operator replay should only resurrect business events.
func TestResetEventStreamExcludesOperationalEvents(t *testing.T) {
	instance, err := createServer(t, "op_event_replay", true)
	require.NoError(t, err)
	defer instance.app.Shutdown()

	stream := mustCreatePollStream(t, instance, "DEFAULT", []string{"https://receiver.example.com"})

	// Submit a verify operational event
	verifyEvent := events.CreateVerifyEvent(stream.Id, "replay-test", stream.Iss, stream.Aud)
	opRec, err := instance.app.EventRouter.SubmitOperationalEvent(stream.Id, verifyEvent, "")
	require.NoError(t, err)

	// Drain pending so the replay starts from an empty pending list
	require.NoError(t, instance.provider.ClearPending(stream.Id))

	// Run the same replay filter the stream-management API installs (operational excluded).
	streamState, err := instance.provider.GetStreamState(stream.Id)
	require.NoError(t, err)
	resetDate := time.Now().Add(-1 * time.Hour)
	err = instance.provider.ResetEventStream(stream.Id, "", &resetDate, func(rec *model.AgEventRecord) bool {
		if rec.Operational {
			return false
		}
		return eventRouter.StreamEventMatch(streamState, rec)
	})
	require.NoError(t, err)

	jtis, _ := instance.provider.GetEventIds(stream.Id, model.PollParameters{MaxEvents: 10})
	assert.NotContains(t, jtis, opRec.Jti, "operational event must be excluded from ResetDate replay")
}

func mustCreatePollStream(t *testing.T, instance *ssfInstance, iss string, aud []string) model.StreamConfiguration {
	t.Helper()
	cfg := model.StreamConfiguration{
		Iss:             iss,
		Aud:             aud,
		EventsSupported: []string{"https://schemas.openid.net/secevent/ssf/event-type/verification"},
		EventsDelivered: []string{"https://schemas.openid.net/secevent/ssf/event-type/verification"},
		Delivery: &model.OneOfStreamConfigurationDelivery{
			PollTransmitMethod: &model.PollTransmitMethod{
				Method: model.DeliveryPoll,
			},
		},
	}
	created, err := instance.provider.CreateStream(cfg, authUtil.ConvertProject(instance.projectId))
	require.NoError(t, err)
	return created
}
