package eventRouter

import (
    "context"
    "encoding/json"
    "net/http"
    "net/http/httptest"
    "testing"

    "github.com/i2-open/i2goSignals/pkg/ssfModels"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

func TestDerivePushStatusURL_StandardLayout(t *testing.T) {
    got, err := derivePushStatusURL("https://receiver.example.com/events/abc123", "abc123")
    require.NoError(t, err)
    assert.Equal(t, "https://receiver.example.com/status?stream_id=abc123", got)
}

func TestDerivePushStatusURL_WithBasePath(t *testing.T) {
    got, err := derivePushStatusURL("https://receiver.example.com/api/v1/events/abc123", "abc123")
    require.NoError(t, err)
    assert.Equal(t, "https://receiver.example.com/api/v1/status?stream_id=abc123", got)
}

func TestDerivePushStatusURL_PreservesExistingQuery(t *testing.T) {
    got, err := derivePushStatusURL("https://receiver.example.com/events/abc123?stream_id=zzz", "abc123")
    require.NoError(t, err)
    // Existing stream_id is preserved (informational; receiver reads from auth token).
    assert.Equal(t, "https://receiver.example.com/status?stream_id=zzz", got)
}

func TestDerivePushStatusURL_NoEventsSegment(t *testing.T) {
    // Some custom receivers may not use /events/{id}; fall back to appending /status.
    got, err := derivePushStatusURL("https://receiver.example.com/push/abc123", "abc123")
    require.NoError(t, err)
    assert.Equal(t, "https://receiver.example.com/push/abc123/status?stream_id=abc123", got)
}

func TestDerivePushStatusURL_EmptyEndpoint(t *testing.T) {
    _, err := derivePushStatusURL("", "abc123")
    assert.Error(t, err)
}

func TestPushStatusFetcher_ReturnsStreamStatus(t *testing.T) {
    var capturedAuth string
    server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
        capturedAuth = req.Header.Get("Authorization")
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusOK)
        _ = json.NewEncoder(w).Encode(model.StreamStatus{Status: model.StreamStatePause, Reason: "remote paused"})
    }))
    defer server.Close()

    r := newTestRouter(t).router
    stream := &model.StreamStateRecord{}
    stream.StreamConfiguration = model.StreamConfiguration{
        Id: "abc123",
        Delivery: &model.OneOfStreamConfigurationDelivery{
            PushTransmitMethod: &model.PushTransmitMethod{
                Method:              model.DeliveryPush,
                EndpointUrl:         server.URL + "/events/abc123",
                AuthorizationHeader: "Bearer fake-token",
            },
        },
    }

    status, err := r.pushStatusFetcher()(context.Background(), stream)
    require.NoError(t, err)
    require.NotNil(t, status)
    assert.Equal(t, model.StreamStatePause, status.Status)
    assert.Equal(t, "remote paused", status.Reason)
    assert.Equal(t, "Bearer fake-token", capturedAuth, "fetcher must reuse pushConfig.AuthorizationHeader")
}

func TestPushStatusFetcher_NonOKReturnsError(t *testing.T) {
    server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
        w.WriteHeader(http.StatusUnauthorized)
    }))
    defer server.Close()

    r := newTestRouter(t).router
    stream := &model.StreamStateRecord{}
    stream.StreamConfiguration = model.StreamConfiguration{
        Id: "abc123",
        Delivery: &model.OneOfStreamConfigurationDelivery{
            PushTransmitMethod: &model.PushTransmitMethod{
                Method:      model.DeliveryPush,
                EndpointUrl: server.URL + "/events/abc123",
            },
        },
    }

    _, err := r.pushStatusFetcher()(context.Background(), stream)
    assert.Error(t, err)
}

func TestPushStatusFetcher_NilDelivery(t *testing.T) {
    r := newTestRouter(t).router
    stream := &model.StreamStateRecord{}
    stream.StreamConfiguration = model.StreamConfiguration{Id: "abc123"}
    _, err := r.pushStatusFetcher()(context.Background(), stream)
    assert.Error(t, err)
}
