package services

import (
    "context"
    "errors"
    "testing"

    "github.com/i2-open/i2goSignals/internal/dao/interfaces"
    "github.com/i2-open/i2goSignals/internal/dao/memory"
    "github.com/i2-open/i2goSignals/pkg/ssfModels"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
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
