package eventRouter

import (
    "context"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "net/http/httptest"
    "testing"
    "time"

    "github.com/i2-open/i2goSignals/pkg/dao/memory"
    "github.com/i2-open/i2goSignals/internal/providers/dbProviders"
    "github.com/i2-open/i2goSignals/pkg/services"
    "github.com/i2-open/i2goSignals/pkg/authSupport"
    "github.com/i2-open/i2goSignals/pkg/goSet"
    model "github.com/i2-open/i2goSignals/pkg/ssfModels"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

// clusterFilterHarness wires a router whose SubjectFilterService shares its
// subject-filter DAO with a peerFilter service. The peer stands in for another
// cluster node: a change applied through peerFilter updates the shared filter
// store but leaves the router's match-result cache stale — the exact condition
// the issue #94 cluster reload notification must repair.
type clusterFilterHarness struct {
    router        *router
    streamService *services.StreamService
    keyService    *services.KeyService
    routerFilter  *services.SubjectFilterService
    peerFilter    *services.SubjectFilterService
}

func newClusterFilterHarness(t *testing.T, nodeId string) *clusterFilterHarness {
    t.Helper()
    t.Setenv("I2SIG_SUBJECT_FILTERING", "ENABLED")
    t.Setenv("I2SIG_STORE_MEM_DIRECTORY", t.TempDir())
    persistence, err := dbProviders.OpenPersistence("memorydb:", "subject_filter_cluster_test")
    require.NoError(t, err)
    t.Cleanup(func() {
        if persistence.Storage != nil {
            _ = persistence.Storage.Close()
        }
    })

    dao := memory.NewSubjectFilterDAO()
    routerFilter := services.NewSubjectFilterService(dao)
    peerFilter := services.NewSubjectFilterService(dao)

    r := NewRouter(RouterDeps{
        StreamService:        persistence.StreamService,
        KeyService:           persistence.KeyService,
        EventService:         persistence.EventService,
        Coordinator:          persistence.Coordinator,
        SubjectFilterService: routerFilter,
    }, nodeId).(*router)
    t.Cleanup(r.Shutdown)

    return &clusterFilterHarness{
        router:        r,
        streamService: persistence.StreamService,
        keyService:    persistence.KeyService,
        routerFilter:  routerFilter,
        peerFilter:    peerFilter,
    }
}

// createNoneStream creates a NONE-baseline PUSH transmitter stream.
func (h *clusterFilterHarness) createNoneStream(t *testing.T) *model.StreamStateRecord {
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
    ctx := context.WithValue(context.Background(), authSupport.AuthContextKey, authSupport.ConvertProject(projectId))
    created, err := h.streamService.CreateStream(ctx, model.StreamStateRecord{
        StreamConfiguration: cfg,
        DefaultSubjects:     model.DefaultSubjectsNone,
    }, projectId, nil)
    require.NoError(t, err)
    state, err := h.streamService.GetStreamState(context.Background(), created.Id)
    require.NoError(t, err)
    return state
}

// TestNotifySubjectFilterChange_LocalOwnerInvalidatesWithoutHop verifies issue
// #94 acceptance criterion 4: when the push-transmitter lease is held by the
// local node, NotifySubjectFilterChange invalidates the match-result cache
// directly, with no cluster wake-up call.
func TestNotifySubjectFilterChange_LocalOwnerInvalidatesWithoutHop(t *testing.T) {
    h := newClusterFilterHarness(t, "node-A")
    stream := h.createNoneStream(t)
    sid := stream.StreamConfiguration.Id
    ctx := context.Background()

    // node-A owns the push-transmitter lease for this stream.
    resource := fmt.Sprintf("push-transmitter:%s", sid)
    acquired, _, err := h.router.coordinator.TryAcquireOrRenewLease(resource, "node-A", 30*time.Second)
    require.NoError(t, err)
    require.True(t, acquired)

    subject := emailSubjectFor("alice@example.com")
    event := &model.AgEventRecord{Event: goSet.SecurityEventToken{SubjectId: subject}}

    // The owner caches a "drop" decision (NONE stream, empty filter).
    require.False(t, h.routerFilter.Allows(ctx, stream, event),
        "precondition: NONE stream with an empty filter must not deliver")

    // A peer node processes the Add Subject: the shared filter changes but the
    // owner's cache is left stale.
    _, addErr := h.peerFilter.AddSubject(ctx, stream, subject, false)
    require.NoError(t, addErr)
    require.False(t, h.routerFilter.Allows(ctx, stream, event),
        "precondition: the owner's cached decision is expected to be stale")

    h.router.NotifySubjectFilterChange(sid)

    assert.True(t, h.routerFilter.Allows(ctx, stream, event),
        "a local-owner notification must invalidate the cache so the change takes effect")
    assert.Empty(t, h.router.recentOutboundWakes,
        "a local-owner notification must not send a cluster wake-up call")
}

// capturedWake is one inbound /_cluster/wake-transmitter request observed by a
// stub peer node.
type capturedWake struct {
    body map[string]string
    auth string
}

// TestNotifySubjectFilterChange_RemoteOwnerSendsFilterChangeWake verifies issue
// #94 acceptance criteria 1 and 3: when the push-transmitter lease is held by a
// remote node, NotifySubjectFilterChange sends that node a wake-transmitter
// call carrying reason "filter-change" and the existing cluster auth token.
func TestNotifySubjectFilterChange_RemoteOwnerSendsFilterChangeWake(t *testing.T) {
    t.Setenv("I2SIG_CLUSTER_INTERNAL_TOKEN", "test-secret")
    h := newClusterFilterHarness(t, "node-A")
    stream := h.createNoneStream(t)
    sid := stream.StreamConfiguration.Id

    // Stub peer node: captures the inbound wake-transmitter request.
    wakes := make(chan capturedWake, 1)
    peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        raw, _ := io.ReadAll(r.Body)
        var body map[string]string
        _ = json.Unmarshal(raw, &body)
        wakes <- capturedWake{body: body, auth: r.Header.Get("Authorization")}
        w.WriteHeader(http.StatusAccepted)
    }))
    defer peer.Close()

    // node-B owns the push-transmitter lease and is reachable at the stub.
    require.NoError(t, h.router.coordinator.RegisterNode(model.ClusterNode{
        Id:      "node-B",
        Address: peer.URL,
    }))
    resource := fmt.Sprintf("push-transmitter:%s", sid)
    acquired, _, err := h.router.coordinator.TryAcquireOrRenewLease(resource, "node-B", 30*time.Second)
    require.NoError(t, err)
    require.True(t, acquired)

    h.router.NotifySubjectFilterChange(sid)

    select {
    case got := <-wakes:
        assert.Equal(t, sid, got.body["sid"], "the wake-up must target the changed stream")
        assert.Equal(t, "push", got.body["mode"])
        assert.Equal(t, "filter-change", got.body["reason"],
            "a remote-owner notification must carry the filter-change reason")
        require.True(t, len(got.auth) > 7 && got.auth[:7] == "Bearer ",
            "the wake-up must reuse the cluster bearer-token scheme")
        assert.True(t, authSupport.ValidateClusterToken("test-secret", got.auth[7:], sid, "push", 30*time.Second),
            "the wake-up token must validate under the existing cluster auth scheme")
    case <-time.After(3 * time.Second):
        t.Fatal("a remote-owner notification must send a wake-transmitter call")
    }
}
