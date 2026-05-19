package services

import (
    "bytes"
    "context"
    "errors"
    "log/slog"
    "strings"
    "testing"

    "github.com/i2-open/i2goSignals/internal/dao/interfaces"
    "github.com/i2-open/i2goSignals/internal/dao/memory"
    "github.com/i2-open/i2goSignals/pkg/ssfModels"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
    "go.mongodb.org/mongo-driver/v2/bson"
)

// newSubjectFilterTestService builds a StreamService backed by the in-memory
// DAO, the standard fixture for service-level subject-filtering tests.
func newSubjectFilterTestService() *StreamService {
    streamDAO := memory.NewStreamDAO()
    keyDAO := memory.NewKeyDAO()
    keyService := NewKeyService(keyDAO, "http://test", nil)
    return NewStreamService(streamDAO, keyService, "http://test")
}

// pushTransmitterRequest returns a minimal DeliveryPush transmitter stream
// creation request.
func pushTransmitterRequest() model.StreamStateRecord {
    return model.StreamStateRecord{
        StreamConfiguration: model.StreamConfiguration{
            Iss: "test-issuer",
            Delivery: &model.OneOfStreamConfigurationDelivery{
                PushTransmitMethod: &model.PushTransmitMethod{
                    Method:      model.DeliveryPush,
                    EndpointUrl: "https://rx.example/push",
                },
            },
        },
    }
}

// TestStreamService_SubjectFilterFieldsRoundTripOnCreate verifies that the
// subject-filtering configuration fields (defaultSubjects and the event-source
// descriptor) supplied on stream creation are persisted and read back intact
// when the feature is enabled.
func TestStreamService_SubjectFilterFieldsRoundTripOnCreate(t *testing.T) {
    t.Setenv("I2SIG_SUBJECT_FILTERING", "ENABLED")
    svc := newSubjectFilterTestService()
    ctx := context.Background()

    req := pushTransmitterRequest()
    req.DefaultSubjects = model.DefaultSubjectsNone
    req.EventSource = &model.EventSource{
        Type:            model.EventSourceExplicit,
        SourceStreamIds: []string{"src-1"},
    }

    created, err := svc.CreateStream(ctx, req, "test-project", nil)
    require.NoError(t, err)

    state, err := svc.GetStreamState(ctx, created.Id)
    require.NoError(t, err)
    assert.Equal(t, model.DefaultSubjectsNone, state.DefaultSubjects,
        "defaultSubjects must round-trip through create")
    require.NotNil(t, state.EventSource, "event source must round-trip through create")
    assert.Equal(t, model.EventSourceExplicit, state.EventSource.Type)
    assert.Equal(t, []string{"src-1"}, state.EventSource.SourceStreamIds)
}

// TestStreamService_SubjectRemovalGraceRoundTripsOnCreate verifies the SSF
// §9.3 per-transmitter-stream removal-grace override (PRD #97 issue #98) is
// persisted on the StreamStateRecord and read back intact through
// CreateStream/GetStreamState. The override is settable independently of
// I2SIG_SUBJECT_FILTERING in this slice since no enforcement is wired up yet.
func TestStreamService_SubjectRemovalGraceRoundTripsOnCreate(t *testing.T) {
    svc := newSubjectFilterTestService()
    ctx := context.Background()

    req := pushTransmitterRequest()
    req.SubjectRemovalGraceSeconds = 60

    created, err := svc.CreateStream(ctx, req, "test-project", nil)
    require.NoError(t, err)

    state, err := svc.GetStreamState(ctx, created.Id)
    require.NoError(t, err)
    assert.Equal(t, 60, state.SubjectRemovalGraceSeconds,
        "subjectRemovalGraceSeconds must round-trip through create")
}

// TestStreamService_DefaultSubjectsIgnoredWhenDisabled verifies that a
// defaultSubjects value supplied on stream creation is silently ignored while
// subject filtering is disabled server-wide, so an upgrade does not change
// delivery behavior for streams that set the knob.
func TestStreamService_DefaultSubjectsIgnoredWhenDisabled(t *testing.T) {
    t.Setenv("I2SIG_SUBJECT_FILTERING", "DISABLED")
    svc := newSubjectFilterTestService()
    ctx := context.Background()

    req := pushTransmitterRequest()
    req.DefaultSubjects = model.DefaultSubjectsNone

    created, err := svc.CreateStream(ctx, req, "test-project", nil)
    require.NoError(t, err)

    state, err := svc.GetStreamState(ctx, created.Id)
    require.NoError(t, err)
    assert.Empty(t, state.DefaultSubjects,
        "defaultSubjects must be ignored (left empty) when subject filtering is disabled")
}

// TestStreamService_SubjectFilterFieldsRoundTripOnUpdate verifies that the
// subject-filtering configuration fields can be patched on an existing stream
// and are persisted and read back intact when the feature is enabled.
func TestStreamService_SubjectFilterFieldsRoundTripOnUpdate(t *testing.T) {
    t.Setenv("I2SIG_SUBJECT_FILTERING", "ENABLED")
    svc := newSubjectFilterTestService()
    ctx := context.Background()

    created, err := svc.CreateStream(ctx, pushTransmitterRequest(), "test-project", nil)
    require.NoError(t, err)

    update := model.StreamStateRecord{
        StreamConfiguration: model.StreamConfiguration{Id: created.Id},
        DefaultSubjects:     model.DefaultSubjectsNone,
        SubjectFilterMode:   model.SubjectFilterModeHybrid,
        EventSource:         &model.EventSource{Type: model.EventSourceAudience},
    }
    _, err = svc.UpdateStream(ctx, created.Id, "test-project", update)
    require.NoError(t, err)

    state, err := svc.GetStreamState(ctx, created.Id)
    require.NoError(t, err)
    assert.Equal(t, model.DefaultSubjectsNone, state.DefaultSubjects,
        "defaultSubjects must round-trip through update")
    assert.Equal(t, model.SubjectFilterModeHybrid, state.SubjectFilterMode,
        "subjectFilterMode must round-trip through update")
    require.NotNil(t, state.EventSource, "event source must round-trip through update")
    assert.Equal(t, model.EventSourceAudience, state.EventSource.Type)
}

// captureLogs swaps slog.Default for one writing to a buffer for the duration
// of the test, returning the buffer. It exploits the fact that logger.Sub()
// uses a dynamicHandler that re-reads slog.Default() on every record.
func captureLogs(t *testing.T) *bytes.Buffer {
    t.Helper()
    var buf bytes.Buffer
    prev := slog.Default()
    slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
    t.Cleanup(func() { slog.SetDefault(prev) })
    return &buf
}

// seedReceiverStream writes a minimal ReceivePush stream straight to the DAO,
// bypassing the registration handshake CreateStream performs for receivers.
// Returns the assigned stream id.
func seedReceiverStream(t *testing.T, ctx context.Context, dao interfaces.StreamDAO) string {
    t.Helper()
    id := bson.NewObjectID()
    rec := &model.StreamStateRecord{
        Id:        id,
        ProjectId: "test-project",
        StreamConfiguration: model.StreamConfiguration{
            Id:  id.Hex(),
            Iss: "test-issuer",
            Delivery: &model.OneOfStreamConfigurationDelivery{
                PushReceiveMethod: &model.PushReceiveMethod{Method: model.ReceivePush},
            },
        },
        Status: model.StreamStateEnabled,
    }
    require.NoError(t, dao.Create(ctx, rec))
    return id.Hex()
}

// TestStreamService_SubjectRemovalGraceIgnoredOnReceiverStream verifies that
// when an operator sets the §9.3 grace override on a receiver stream
// (where the knob has no meaning), UpdateStream drops the value and logs a
// WARN — mirroring the issue #98 acceptance criterion.
func TestStreamService_SubjectRemovalGraceIgnoredOnReceiverStream(t *testing.T) {
    logs := captureLogs(t)
    streamDAO := memory.NewStreamDAO()
    keyDAO := memory.NewKeyDAO()
    keyService := NewKeyService(keyDAO, "http://test", nil)
    svc := NewStreamService(streamDAO, keyService, "http://test")
    ctx := context.Background()

    sid := seedReceiverStream(t, ctx, streamDAO)

    update := model.StreamStateRecord{
        StreamConfiguration:        model.StreamConfiguration{Id: sid},
        SubjectRemovalGraceSeconds: 90,
    }
    _, err := svc.UpdateStream(ctx, sid, "test-project", update)
    require.NoError(t, err)

    state, err := svc.GetStreamState(ctx, sid)
    require.NoError(t, err)
    assert.Equal(t, 0, state.SubjectRemovalGraceSeconds,
        "grace override on a receiver stream must be dropped (left at 0)")

    assert.Contains(t, logs.String(), "subject_removal_grace_seconds ignored on a receiver stream",
        "a WARN must be emitted when the grace override is set on a receiver stream")
    assert.True(t, strings.Contains(logs.String(), "level=WARN"),
        "the ignored-override log must be at WARN level")
}

// TestStreamService_SubjectRemovalGraceNegativeRejectedOnCreate verifies a
// negative grace override is rejected at CreateStream — the value cannot
// describe a window, so it is a configuration error.
func TestStreamService_SubjectRemovalGraceNegativeRejectedOnCreate(t *testing.T) {
    svc := newSubjectFilterTestService()
    ctx := context.Background()

    req := pushTransmitterRequest()
    req.SubjectRemovalGraceSeconds = -5

    _, err := svc.CreateStream(ctx, req, "test-project", nil)
    require.Error(t, err, "a negative grace override must be rejected")
    assert.Contains(t, err.Error(), "subject_removal_grace_seconds",
        "the error must name the invalid field")
}

// TestStreamService_SubjectRemovalGraceNegativeRejectedOnUpdate verifies the
// same validation applies on UpdateStream.
func TestStreamService_SubjectRemovalGraceNegativeRejectedOnUpdate(t *testing.T) {
    svc := newSubjectFilterTestService()
    ctx := context.Background()

    created, err := svc.CreateStream(ctx, pushTransmitterRequest(), "test-project", nil)
    require.NoError(t, err)

    update := model.StreamStateRecord{
        StreamConfiguration:        model.StreamConfiguration{Id: created.Id},
        SubjectRemovalGraceSeconds: -1,
    }
    _, err = svc.UpdateStream(ctx, created.Id, "test-project", update)
    require.Error(t, err, "a negative grace override must be rejected on update")
    assert.Contains(t, err.Error(), "subject_removal_grace_seconds")

    // The pre-existing record must be untouched on a rejected update.
    state, err := svc.GetStreamState(ctx, created.Id)
    require.NoError(t, err)
    assert.Equal(t, 0, state.SubjectRemovalGraceSeconds,
        "a rejected update must not mutate the persisted grace value")
}

// TestStreamService_SubjectRemovalGraceRoundTripsOnUpdate verifies the SSF
// §9.3 per-stream grace override can be patched onto an existing transmitter
// stream and is persisted intact (PRD #97 issue #98).
func TestStreamService_SubjectRemovalGraceRoundTripsOnUpdate(t *testing.T) {
    svc := newSubjectFilterTestService()
    ctx := context.Background()

    created, err := svc.CreateStream(ctx, pushTransmitterRequest(), "test-project", nil)
    require.NoError(t, err)

    update := model.StreamStateRecord{
        StreamConfiguration:        model.StreamConfiguration{Id: created.Id},
        SubjectRemovalGraceSeconds: 120,
    }
    _, err = svc.UpdateStream(ctx, created.Id, "test-project", update)
    require.NoError(t, err)

    state, err := svc.GetStreamState(ctx, created.Id)
    require.NoError(t, err)
    assert.Equal(t, 120, state.SubjectRemovalGraceSeconds,
        "subjectRemovalGraceSeconds must round-trip through update")
}

// TestStreamService_DefaultSubjectsFlipClearsFilter verifies that changing a
// live stream's defaultSubjects baseline clears its subject filter, so stale
// entries never carry the opposite meaning under the new baseline (#92
// acceptance criterion 5).
func TestStreamService_DefaultSubjectsFlipClearsFilter(t *testing.T) {
    t.Setenv("I2SIG_SUBJECT_FILTERING", "ENABLED")
    ctx := context.Background()

    svc := newSubjectFilterTestService()
    filterDAO := memory.NewSubjectFilterDAO()
    svc.SetSubjectFilterService(NewSubjectFilterService(filterDAO))

    req := pushTransmitterRequest()
    req.DefaultSubjects = model.DefaultSubjectsNone
    created, err := svc.CreateStream(ctx, req, "test-project", nil)
    require.NoError(t, err)

    // Seed the stream's filter with one entry.
    require.NoError(t, filterDAO.Add(ctx, &model.SubjectFilterEntry{
        StreamId:     created.Id,
        CanonicalKey: "email:alice@example.com",
        Kind:         model.SubjectKindSimple,
    }))

    // Flip the baseline NONE -> ALL.
    update := model.StreamStateRecord{
        StreamConfiguration: model.StreamConfiguration{Id: created.Id},
        DefaultSubjects:     model.DefaultSubjectsAll,
    }
    _, err = svc.UpdateStream(ctx, created.Id, "test-project", update)
    require.NoError(t, err)

    _, getErr := filterDAO.Get(ctx, created.Id, "email:alice@example.com")
    require.True(t, errors.Is(getErr, interfaces.ErrNotFound),
        "flipping defaultSubjects must clear the stream's subject filter")
}

// TestStreamService_DefaultSubjectsUnchangedKeepsFilter verifies an UpdateStream
// that does not change defaultSubjects leaves the filter intact.
func TestStreamService_DefaultSubjectsUnchangedKeepsFilter(t *testing.T) {
    t.Setenv("I2SIG_SUBJECT_FILTERING", "ENABLED")
    ctx := context.Background()

    svc := newSubjectFilterTestService()
    filterDAO := memory.NewSubjectFilterDAO()
    svc.SetSubjectFilterService(NewSubjectFilterService(filterDAO))

    req := pushTransmitterRequest()
    req.DefaultSubjects = model.DefaultSubjectsNone
    created, err := svc.CreateStream(ctx, req, "test-project", nil)
    require.NoError(t, err)

    require.NoError(t, filterDAO.Add(ctx, &model.SubjectFilterEntry{
        StreamId:     created.Id,
        CanonicalKey: "email:alice@example.com",
        Kind:         model.SubjectKindSimple,
    }))

    // Update something else; defaultSubjects stays NONE.
    update := model.StreamStateRecord{
        StreamConfiguration: model.StreamConfiguration{Id: created.Id, Description: "changed"},
        DefaultSubjects:     model.DefaultSubjectsNone,
    }
    _, err = svc.UpdateStream(ctx, created.Id, "test-project", update)
    require.NoError(t, err)

    _, getErr := filterDAO.Get(ctx, created.Id, "email:alice@example.com")
    require.NoError(t, getErr, "an unchanged defaultSubjects must leave the filter intact")
}
