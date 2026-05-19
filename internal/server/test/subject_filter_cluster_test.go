package test

import (
    "context"
    "encoding/json"
    "io"
    "net/http"
    "net/http/httptest"
    "strings"
    "testing"
    "time"

    "github.com/i2-open/i2goSignals/internal/authUtil"
    model "github.com/i2-open/i2goSignals/pkg/ssfModels"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

// TestAddSubjectNotifiesRemoteLeaseOwner verifies issue #94 acceptance criteria
// 1 and 5: an Add Subject request processed on a node that does not hold the
// stream's push-transmitter lease notifies the lease owner with a
// filter-change cluster wake-up, so the change takes effect on the owner.
func TestAddSubjectNotifiesRemoteLeaseOwner(t *testing.T) {
    t.Setenv("I2SIG_CLUSTER_INTERNAL_TOKEN", "test-secret")
    t.Setenv("I2SIG_SUBJECT_FILTERING", "ENABLED")

    instance, err := createServer(t, "subject_filter_cluster_test", true)
    require.NoError(t, err)
    defer instance.app.Shutdown()
    defer instance.ts.Close()

    // Stub lease-owner node: captures the inbound wake-transmitter request.
    wakes := make(chan map[string]string, 1)
    owner := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        raw, _ := io.ReadAll(r.Body)
        var body map[string]string
        _ = json.Unmarshal(raw, &body)
        wakes <- body
        w.WriteHeader(http.StatusAccepted)
    }))
    defer owner.Close()

    // Create a PUSH transmitter stream and a stream-scoped bearer token.
    ctx := context.WithValue(context.Background(), authUtil.AuthContextKey,
        &authUtil.AuthContext{ProjectId: instance.projectId})
    created, err := instance.streamSvc().CreateStream(ctx, model.StreamStateRecord{
        StreamConfiguration: model.StreamConfiguration{
            Iss: "DEFAULT",
            Aud: []string{"https://receiver.example.com"},
            Delivery: &model.OneOfStreamConfigurationDelivery{
                PushTransmitMethod: &model.PushTransmitMethod{
                    Method:      model.DeliveryPush,
                    EndpointUrl: "https://receiver.example.com/events",
                },
            },
        },
        DefaultSubjects: model.DefaultSubjectsNone,
    }, instance.projectId, nil)
    require.NoError(t, err)
    token, err := instance.GetAuthIssuer().IssueStreamToken(created.Id, instance.projectId, nil)
    require.NoError(t, err)

    // A different node owns the push-transmitter lease, reachable at the stub.
    require.NoError(t, instance.app.Coordinator.RegisterNode(model.ClusterNode{
        Id:      "remote-owner",
        Address: owner.URL,
    }))
    acquired, _, err := instance.app.Coordinator.TryAcquireOrRenewLease(
        "push-transmitter:"+created.Id, "remote-owner", 30*time.Second)
    require.NoError(t, err)
    require.True(t, acquired)

    // The Add Subject request lands on this (non-owner) node.
    body := `{"stream_id":"` + created.Id + `","subject":{"format":"email","email":"alice@example.com"}}`
    req, _ := http.NewRequest(http.MethodPost, instance.ts.URL+"/add-subject", strings.NewReader(body))
    req.Header.Set("Authorization", "Bearer "+token)
    req.Header.Set("Content-Type", "application/json")
    resp, err := instance.client.Do(req)
    require.NoError(t, err)
    require.Equal(t, http.StatusOK, resp.StatusCode, "Add Subject must succeed")

    select {
    case got := <-wakes:
        assert.Equal(t, created.Id, got["sid"], "the wake-up must target the changed stream")
        assert.Equal(t, "push", got["mode"])
        assert.Equal(t, "filter-change", got["reason"],
            "a non-owner node must notify the lease owner with a filter-change wake-up")
    case <-time.After(3 * time.Second):
        t.Fatal("an Add Subject on a non-owner node must notify the push-transmitter lease owner")
    }
}
