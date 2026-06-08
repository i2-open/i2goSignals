package eventRouter

import (
    "context"
    "testing"
    "time"

    "github.com/i2-open/i2goSignals/pkg/authSupport"
    model "github.com/i2-open/i2goSignals/pkg/ssfModels"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

// createPollStream creates a forward-mode POLL transmitter stream carrying the
// given defaultSubjects baseline and registers it with the router so
// PollStreamHandler can serve it.
func (h *filterPushHarness) createPollStream(t *testing.T, defaultSubjects string) *model.StreamStateRecord {
    t.Helper()
    projectId := projectIdFromHarness(t, &testHarness{
        router:        h.router,
        streamService: h.streamService,
        keyService:    h.keyService,
    })
    cfg := model.StreamConfiguration{
        Iss:             "DEFAULT",
        Aud:             []string{"https://receiver.example.com"},
        EventsDelivered: []string{"https://schemas.openid.net/secevent/risc/event-type/account-disabled"},
        RouteMode:       model.RouteModeForward,
        Delivery: &model.OneOfStreamConfigurationDelivery{
            PollTransmitMethod: &model.PollTransmitMethod{
                Method:      model.DeliveryPoll,
                EndpointUrl: "https://transmitter.example.com/events",
            },
        },
    }
    ctx := context.WithValue(context.Background(), authSupport.AuthContextKey, authSupport.ConvertProject(projectId))
    created, err := h.streamService.CreateStream(ctx, model.StreamStateRecord{
        StreamConfiguration: cfg,
        DefaultSubjects:     defaultSubjects,
    }, projectId, nil)
    require.NoError(t, err)
    state, err := h.streamService.GetStreamState(context.Background(), created.Id)
    require.NoError(t, err)
    h.router.UpdateStreamState(state)
    return state
}

// loadPollBuffer submits the given JTIs to the stream's poll buffer and waits
// until they are drained into the readable buffer, so a subsequent
// ReturnImmediately poll observes them deterministically.
func (h *filterPushHarness) loadPollBuffer(t *testing.T, sid string, jtis ...string) {
    t.Helper()
    h.router.mu.RLock()
    buf := h.router.pollBuffers[sid]
    h.router.mu.RUnlock()
    require.NotNil(t, buf, "poll buffer must exist for stream %s", sid)
    buf.SubmitEvents(jtis)
    require.Eventually(t, func() bool { return buf.Cnt() == len(jtis) }, 2*time.Second, 5*time.Millisecond,
        "submitted JTIs must drain into the poll buffer")
}

// pollImmediate serves a single non-blocking poll request for the stream.
func (h *filterPushHarness) pollImmediate(sid string) (map[string]string, int) {
    sets, _, status := h.router.PollStreamHandler(sid, model.PollParameters{
        MaxEvents:         100,
        ReturnImmediately: true,
    })
    return sets, status
}

// TestPollFilter_NoneStreamReturnsOnlyAddedSubjects verifies a poll response on
// a NONE stream returns only events for subjects that have been added to the
// filter (#93 acceptance criterion 1).
func TestPollFilter_NoneStreamReturnsOnlyAddedSubjects(t *testing.T) {
    t.Setenv("I2SIG_SUBJECT_FILTERING", "ENABLED")
    h := newFilterPushRouter(t)
    stream := h.createPollStream(t, model.DefaultSubjectsNone)
    sid := stream.StreamConfiguration.Id

    _, addErr := h.subjectFilter.AddSubject(context.Background(), stream, emailSubjectFor("alice@example.com"), false)
    require.NoError(t, addErr)

    addedJti := h.addPendingEvent(t, sid, emailSubjectFor("alice@example.com"), false)
    omittedJti := h.addPendingEvent(t, sid, emailSubjectFor("bob@example.com"), false)
    h.loadPollBuffer(t, sid, addedJti, omittedJti)

    sets, status := h.pollImmediate(sid)
    assert.Equal(t, 200, status)
    assert.Contains(t, sets, addedJti, "an added subject's event must be in the poll response")
    assert.NotContains(t, sets, omittedJti, "an unmatched subject's event must not be in the poll response")
}

// TestPollFilter_AllStreamOmitsRemovedSubjects verifies a poll response on an
// ALL stream omits events for subjects that have been removed (#93 criterion 2).
func TestPollFilter_AllStreamOmitsRemovedSubjects(t *testing.T) {
    t.Setenv("I2SIG_SUBJECT_FILTERING", "ENABLED")
    h := newFilterPushRouter(t)
    stream := h.createPollStream(t, model.DefaultSubjectsAll)
    sid := stream.StreamConfiguration.Id

    _, remErr := h.subjectFilter.RemoveSubject(context.Background(), stream, emailSubjectFor("bob@example.com"))
    require.NoError(t, remErr)

    keptJti := h.addPendingEvent(t, sid, emailSubjectFor("alice@example.com"), false)
    removedJti := h.addPendingEvent(t, sid, emailSubjectFor("bob@example.com"), false)
    h.loadPollBuffer(t, sid, keptJti, removedJti)

    sets, status := h.pollImmediate(sid)
    assert.Equal(t, 200, status)
    assert.Contains(t, sets, keptJti, "an ALL stream still delivers subjects that were not removed")
    assert.NotContains(t, sets, removedJti, "a removed subject's event must be omitted from the poll response")
}

// TestPollFilter_OperationalEventAlwaysReturned verifies operational events are
// returned by a poll regardless of the filter (#93 acceptance criterion 3).
func TestPollFilter_OperationalEventAlwaysReturned(t *testing.T) {
    t.Setenv("I2SIG_SUBJECT_FILTERING", "ENABLED")
    h := newFilterPushRouter(t)
    stream := h.createPollStream(t, model.DefaultSubjectsNone)
    sid := stream.StreamConfiguration.Id

    opJti := h.addPendingEvent(t, sid, emailSubjectFor("alice@example.com"), true)
    h.loadPollBuffer(t, sid, opJti)

    sets, status := h.pollImmediate(sid)
    assert.Equal(t, 200, status)
    assert.Contains(t, sets, opJti, "operational events must always be returned by a poll")
}
