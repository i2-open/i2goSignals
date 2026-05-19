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
    "github.com/i2-open/i2goSignals/pkg/goSet"
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
        instance.streamSvc().ListTransmitterStreams,
        func(context.Context, *model.StreamStateRecord, *goSet.SubjectIdentifier) bool { return false },
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

// TestHybridRelaysAndFiltersLocally verifies the HYBRID path of issue #96 end
// to end: an Add Subject on a HYBRID transmitter stream both writes the local
// per-stream filter and — because it is the first interested downstream and
// the upstream is a NONE baseline — relays the add upstream (the 0→1
// transition).
func TestHybridRelaysAndFiltersLocally(t *testing.T) {
    _ = os.Setenv("I2SIG_SUBJECT_FILTERING", "ENABLED")
    defer func() { _ = os.Unsetenv("I2SIG_SUBJECT_FILTERING") }()

    instance, err := createServer(t, "hybrid_relay_test", true)
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

    // The relay-target receiver carries a NONE baseline, so HYBRID engages its
    // upstream relay. listTransmitters and interested are wired to the real
    // services so the interested-set 0↔1 decision runs against live state.
    var rxStream model.StreamStateRecord
    rxStream.StreamConfiguration.Id = "rx-upstream"
    rxStream.StreamConfiguration.Iss = upstreamIss
    rxStream.DefaultSubjects = model.DefaultSubjectsNone
    fakeRelay := services.NewSubjectRelayService(
        func(context.Context) ([]model.StreamStateRecord, error) {
            return []model.StreamStateRecord{rxStream}, nil
        },
        instance.streamSvc().ListTransmitterStreams,
        instance.app.SubjectFilterService.Selects,
        func(context.Context, *model.StreamStateRecord) (*services.UpstreamConn, error) {
            return &services.UpstreamConn{Config: upstreamCfg, HttpClient: upstream.Client()}, nil
        },
    )
    instance.streamSvc().SetSubjectRelayService(fakeRelay)
    instance.app.SubjectRelayService = fakeRelay

    // Create a HYBRID NONE-baseline transmitter stream feeding from the upstream.
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
        DefaultSubjects:   model.DefaultSubjectsNone,
        SubjectFilterMode: model.SubjectFilterModeHybrid,
        EventSource:       &model.EventSource{Type: model.EventSourceAudience},
    }, instance.projectId, nil)
    require.NoError(t, err, "a HYBRID stream with a filtering-capable upstream must be accepted")

    token, err := instance.GetAuthIssuer().IssueStreamToken(created.Id, instance.projectId, nil)
    require.NoError(t, err)

    body := `{"stream_id":"` + created.Id + `","subject":{"format":"email","email":"alice@example.com"}}`
    req, _ := http.NewRequest(http.MethodPost, instance.ts.URL+"/add-subject", strings.NewReader(body))
    req.Header.Set("Authorization", "Bearer "+token)
    req.Header.Set("Content-Type", "application/json")
    resp, err := instance.client.Do(req)
    require.NoError(t, err)
    assert.Equal(t, http.StatusOK, resp.StatusCode, "HYBRID Add Subject must return 200")
    assert.Equal(t, int32(1), atomic.LoadInt32(&relayed), "the first interested downstream must relay the add upstream")

    // The subject was also recorded in this stream's local filter: HYBRID
    // filters locally per downstream, unlike PASSTHRU.
    state, err := instance.GetStreamState(created.Id)
    require.NoError(t, err)
    subject := &goSet.SubjectIdentifier{Format: "email", EmailIdentifier: goSet.EmailIdentifier{Email: "alice@example.com"}}
    assert.True(t, instance.app.SubjectFilterService.Selects(context.Background(), state, subject),
        "a HYBRID Add Subject must also be written to the local per-stream filter")
}
