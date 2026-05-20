package eventRouter

import (
    "context"
    "fmt"
    "testing"

    "github.com/i2-open/i2goSignals/internal/authUtil"
    "github.com/i2-open/i2goSignals/internal/eventRouter/delivery"
    "github.com/i2-open/i2goSignals/internal/providers/dbProviders"
    "github.com/i2-open/i2goSignals/internal/services"
    "github.com/i2-open/i2goSignals/pkg/goSet"
    "github.com/i2-open/i2goSignals/pkg/goSetPush"
    model "github.com/i2-open/i2goSignals/pkg/ssfModels"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

// filterPushHarness bundles a router wired with a deterministic MemoryAdapter
// push seam and a live SubjectFilterService, for exercising PUSH delivery-time
// subject filtering (#92).
type filterPushHarness struct {
    router        *router
    streamService *services.StreamService
    keyService    *services.KeyService
    eventService  *services.EventService
    subjectFilter *services.SubjectFilterService
    adapter       *delivery.MemoryAdapter
    jtiSeq        int
}

func newFilterPushRouter(t *testing.T) *filterPushHarness {
    t.Helper()
    t.Setenv("I2SIG_STORE_MEM_DIRECTORY", t.TempDir())
    persistence, err := dbProviders.OpenPersistence("memorydb:", "subject_filter_push_test")
    require.NoError(t, err)
    t.Cleanup(func() {
        if persistence.Storage != nil {
            _ = persistence.Storage.Close()
        }
    })

    // Every Deliver call reports 202 Accepted, so a non-zero call count means
    // the router chose to push rather than discard.
    adapter := delivery.NewMemoryAdapter(delivery.PushOutcome{
        Classification: goSetPush.Classification{Class: goSetPush.ClassAccepted},
    })

    r := NewRouter(RouterDeps{
        StreamService:        persistence.StreamService,
        KeyService:           persistence.KeyService,
        EventService:         persistence.EventService,
        Coordinator:          persistence.Coordinator,
        SubjectFilterService: persistence.SubjectFilterService,
        PushDelivery:         adapter,
    }, "node-filter-push").(*router)
    t.Cleanup(r.Shutdown)

    return &filterPushHarness{
        router:        r,
        streamService: persistence.StreamService,
        keyService:    persistence.KeyService,
        eventService:  persistence.EventService,
        subjectFilter: persistence.SubjectFilterService,
        adapter:       adapter,
    }
}

// createPushStream creates a PUSH transmitter stream carrying the given
// defaultSubjects baseline.
func (h *filterPushHarness) createPushStream(t *testing.T, defaultSubjects string) *model.StreamStateRecord {
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
        Delivery: &model.OneOfStreamConfigurationDelivery{
            PushTransmitMethod: &model.PushTransmitMethod{
                Method:      model.DeliveryPush,
                EndpointUrl: "https://receiver.example.com/events",
            },
        },
    }
    ctx := context.WithValue(context.Background(), authUtil.AuthContextKey, authUtil.ConvertProject(projectId))
    created, err := h.streamService.CreateStream(ctx, model.StreamStateRecord{
        StreamConfiguration: cfg,
        DefaultSubjects:     defaultSubjects,
    }, projectId, nil)
    require.NoError(t, err)
    state, err := h.streamService.GetStreamState(context.Background(), created.Id)
    require.NoError(t, err)
    return state
}

// addPendingEvent persists an event carrying subject and adds it to the
// stream's pending list, returning its JTI.
func (h *filterPushHarness) addPendingEvent(t *testing.T, sid string, subject *goSet.SubjectIdentifier, operational bool) string {
    t.Helper()
    h.jtiSeq++
    token := &goSet.SecurityEventToken{}
    token.ID = fmt.Sprintf("jti-%d", h.jtiSeq)
    token.SubjectId = subject

    ctx := context.Background()
    var rec *model.AgEventRecord
    var err error
    if operational {
        rec, err = h.eventService.AddOperationalEvent(ctx, token, sid, "")
    } else {
        rec, err = h.eventService.AddEvent(ctx, token, sid, "")
    }
    require.NoError(t, err)
    require.NoError(t, h.eventService.AddEventToStream(ctx, rec.Jti, sid))
    return rec.Jti
}

// pendingCount reports how many JTIs are still pending delivery for a stream.
func (h *filterPushHarness) pendingCount(sid string) int {
    jtis, _ := h.eventService.GetEventIds(context.Background(), sid, model.PollParameters{
        MaxEvents:         100,
        ReturnImmediately: true,
    })
    return len(jtis)
}

func emailSubjectFor(addr string) *goSet.SubjectIdentifier {
    s := &goSet.SubjectIdentifier{Format: "email"}
    return s.AddEmail(addr)
}

// TestPushFilter_NoneStreamDiscardsUnmatchedEvent verifies that on a NONE PUSH
// stream with an empty filter an event is not pushed and its JTI is discarded
// (acked), so the pending buffer stays bounded (#92 acceptance criteria 6, 1).
func TestPushFilter_NoneStreamDiscardsUnmatchedEvent(t *testing.T) {
    t.Setenv("I2SIG_SUBJECT_FILTERING", "ENABLED")
    h := newFilterPushRouter(t)
    stream := h.createPushStream(t, model.DefaultSubjectsNone)

    jti := h.addPendingEvent(t, stream.StreamConfiguration.Id, emailSubjectFor("alice@example.com"), false)
    require.Equal(t, 1, h.pendingCount(stream.StreamConfiguration.Id), "precondition: event is pending")

    cls, _, _ := h.router.prepareAndSendEvent(jti, stream, nil, "", 0)

    assert.Equal(t, 0, h.adapter.Calls(), "a filtered-out event must not be pushed")
    assert.Equal(t, goSetPush.ClassAccepted, cls.Class, "a discarded event advances the loop as a no-op success")
    assert.Equal(t, 0, h.pendingCount(stream.StreamConfiguration.Id),
        "a filtered-out JTI must be discarded (acked) so the buffer stays bounded")
}

// TestPushFilter_OperationalEventBypassesFilter verifies an operational event is
// always pushed, even on a NONE stream with an empty filter (#92 criterion 7).
func TestPushFilter_OperationalEventBypassesFilter(t *testing.T) {
    t.Setenv("I2SIG_SUBJECT_FILTERING", "ENABLED")
    h := newFilterPushRouter(t)
    stream := h.createPushStream(t, model.DefaultSubjectsNone)

    jti := h.addPendingEvent(t, stream.StreamConfiguration.Id, emailSubjectFor("alice@example.com"), true)

    cls, _, _ := h.router.prepareAndSendEvent(jti, stream, nil, "", 0)

    assert.Equal(t, 1, h.adapter.Calls(), "operational events must always be pushed regardless of the filter")
    assert.Equal(t, goSetPush.ClassAccepted, cls.Class)
}

// TestPushFilter_NoneStreamDeliversAfterAddSubject verifies that once a subject
// is added to a NONE stream's filter, a matching event is pushed (#92 criterion 1).
func TestPushFilter_NoneStreamDeliversAfterAddSubject(t *testing.T) {
    t.Setenv("I2SIG_SUBJECT_FILTERING", "ENABLED")
    h := newFilterPushRouter(t)
    stream := h.createPushStream(t, model.DefaultSubjectsNone)

    subject := emailSubjectFor("alice@example.com")
    _, addErr := h.subjectFilter.AddSubject(context.Background(), stream, subject, false)
    require.NoError(t, addErr)

    jti := h.addPendingEvent(t, stream.StreamConfiguration.Id, emailSubjectFor("alice@example.com"), false)

    cls, _, _ := h.router.prepareAndSendEvent(jti, stream, nil, "", 0)

    assert.Equal(t, 1, h.adapter.Calls(), "after Add Subject a matching event must be pushed")
    assert.Equal(t, goSetPush.ClassAccepted, cls.Class)
}
