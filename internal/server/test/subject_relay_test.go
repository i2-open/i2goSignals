package test

import (
    "context"
    "net/http"
    "net/http/httptest"
    "os"
    "strings"
    "sync/atomic"
    "testing"

    "github.com/i2-open/i2goSignals/internal/authUtil"
    "github.com/i2-open/i2goSignals/internal/services"
    model "github.com/i2-open/i2goSignals/pkg/ssfModels"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

// TestPassthruRelaysAddSubjectToUpstream verifies the PASSTHRU path of issue
// #95 end to end: an Add Subject on a PASSTHRU transmitter stream produces the
// corresponding relayed call to the upstream transmitter through the real HTTP
// handler, and no local subject filter is applied.
func TestPassthruRelaysAddSubjectToUpstream(t *testing.T) {
    _ = os.Setenv("I2SIG_SUBJECT_FILTERING", "ENABLED")
    defer func() { _ = os.Unsetenv("I2SIG_SUBJECT_FILTERING") }()

    instance, err := createServer(t, "passthru_relay_test", true)
    require.NoError(t, err)
    defer func() {
        instance.app.Shutdown()
        instance.ts.Close()
    }()

    const upstreamIss = "https://upstream.example"

    // Fake upstream transmitter that records relayed Add Subject calls.
    var relayed int32
    upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if r.URL.Path == "/add-subject" {
            atomic.AddInt32(&relayed, 1)
        }
        w.WriteHeader(http.StatusOK)
    }))
    defer upstream.Close()
    upstreamCfg := &model.TransmitterConfiguration{
        Issuer:                upstreamIss,
        AddSubjectEndpoint:    upstream.URL + "/add-subject",
        RemoveSubjectEndpoint: upstream.URL + "/remove-subject",
    }

    // A relay service whose resolver feeds the fake upstream. It is shared by
    // config-time validation (StreamService) and the runtime handler (app).
    var rxStream model.StreamStateRecord
    rxStream.StreamConfiguration.Id = "rx-upstream"
    rxStream.StreamConfiguration.Iss = upstreamIss
    fakeRelay := services.NewSubjectRelayService(
        func(context.Context) ([]model.StreamStateRecord, error) {
            return []model.StreamStateRecord{rxStream}, nil
        },
        func(context.Context, *model.StreamStateRecord) (*services.UpstreamConn, error) {
            return &services.UpstreamConn{Config: upstreamCfg, HttpClient: upstream.Client()}, nil
        },
    )
    instance.streamSvc().SetSubjectRelayService(fakeRelay)
    instance.app.SubjectRelayService = fakeRelay

    // Create a PASSTHRU transmitter stream feeding from the upstream issuer.
    ctx := context.WithValue(context.Background(), authUtil.AuthContextKey,
        &authUtil.AuthContext{ProjectId: instance.projectId})
    created, err := instance.streamSvc().CreateStream(ctx, model.StreamStateRecord{
        StreamConfiguration: model.StreamConfiguration{
            Iss: upstreamIss,
            Aud: []string{"https://receiver.example.com"},
            Delivery: &model.OneOfStreamConfigurationDelivery{
                PollTransmitMethod: &model.PollTransmitMethod{Method: model.DeliveryPoll},
            },
        },
        SubjectFilterMode: model.SubjectFilterModePassthru,
        EventSource:       &model.EventSource{Type: model.EventSourceAudience},
    }, instance.projectId, nil)
    require.NoError(t, err, "a PASSTHRU stream with a filtering-capable upstream must be accepted")

    token, err := instance.GetAuthIssuer().IssueStreamToken(created.Id, instance.projectId, nil)
    require.NoError(t, err)

    body := `{"stream_id":"` + created.Id + `","subject":{"format":"email","email":"alice@example.com"}}`
    req, _ := http.NewRequest(http.MethodPost, instance.ts.URL+"/add-subject", strings.NewReader(body))
    req.Header.Set("Authorization", "Bearer "+token)
    req.Header.Set("Content-Type", "application/json")
    resp, err := instance.client.Do(req)
    require.NoError(t, err)
    assert.Equal(t, http.StatusOK, resp.StatusCode, "PASSTHRU Add Subject must return 200")
    assert.Equal(t, int32(1), atomic.LoadInt32(&relayed), "Add Subject must be relayed 1:1 to the upstream")

    // No local filter entry was written: a PASSTHRU stream filters nothing
    // locally, so the upstream is the only place the subject is recorded.
    state, err := instance.GetStreamState(created.Id)
    require.NoError(t, err)
    assert.Equal(t, "", state.DefaultSubjects, "a PASSTHRU stream carries no local baseline")
}
