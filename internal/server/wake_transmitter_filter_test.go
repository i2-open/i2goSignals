package server

import (
    "bytes"
    "context"
    "encoding/json"
    "net/http"
    "net/http/httptest"
    "testing"

    "github.com/i2-open/i2goSignals/internal/dao/memory"
    "github.com/i2-open/i2goSignals/internal/services"
    "github.com/i2-open/i2goSignals/pkg/authSupport"
    "github.com/i2-open/i2goSignals/pkg/goSet"
    model "github.com/i2-open/i2goSignals/pkg/ssfModels"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

// TestWakeTransmitter_FilterChangeInvalidatesCache verifies issue #94: a
// wake-transmitter call carrying reason "filter-change" invalidates the
// push-transmitter lease owner's subject-filter match-result cache, so a
// subject change applied on a peer node takes effect on the owner. Two
// SubjectFilterService instances over one shared DAO model the two nodes.
func TestWakeTransmitter_FilterChangeInvalidatesCache(t *testing.T) {
    t.Setenv("I2SIG_SUBJECT_FILTERING", "ENABLED")
    t.Setenv("I2SIG_CLUSTER_INTERNAL_TOKEN", "test-secret")
    ctx := context.Background()

    dao := memory.NewSubjectFilterDAO()
    ownerSvc := services.NewSubjectFilterService(dao)
    peerSvc := services.NewSubjectFilterService(dao)
    sa := &SignalsApplication{SubjectFilterService: ownerSvc}

    sid := "stream-cluster-94"
    stream := &model.StreamStateRecord{DefaultSubjects: model.DefaultSubjectsNone}
    stream.StreamConfiguration.Id = sid
    subject := &goSet.SubjectIdentifier{Format: "email"}
    subject.AddEmail("alice@example.com")
    event := &model.AgEventRecord{Event: goSet.SecurityEventToken{SubjectId: subject}}

    // The lease owner caches a "drop" decision (NONE stream, empty filter).
    require.False(t, ownerSvc.Allows(ctx, stream, event))

    // A peer node processes the Add Subject; the owner's cache is now stale.
    _, addErr := peerSvc.AddSubject(ctx, stream, subject, false)
    require.NoError(t, addErr)
    require.False(t, ownerSvc.Allows(ctx, stream, event),
        "precondition: the owner's cached decision is expected to be stale")

    // The peer notifies the owner via the cluster wake-transmitter call.
    body, _ := json.Marshal(map[string]string{"sid": sid, "mode": "push", "reason": "filter-change"})
    req := httptest.NewRequest(http.MethodPost, "/_cluster/wake-transmitter", bytes.NewReader(body))
    req.Header.Set("Authorization", "Bearer "+authSupport.GenerateClusterToken("test-secret", sid, "push"))
    w := httptest.NewRecorder()

    sa.WakeTransmitter(w, req)

    assert.Equal(t, http.StatusAccepted, w.Code)
    assert.True(t, ownerSvc.Allows(ctx, stream, event),
        "a filter-change wake-up must invalidate the owner's match-result cache")
}
