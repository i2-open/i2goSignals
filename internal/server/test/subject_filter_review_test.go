package test

import (
    "context"
    "encoding/json"
    "io"
    "net/http"
    "net/http/httptest"
    "os"
    "strings"
    "testing"
    "time"

    "github.com/i2-open/i2goSignals/internal/authUtil"
    "github.com/i2-open/i2goSignals/internal/services"
    "github.com/i2-open/i2goSignals/pkg/goSet"
    model "github.com/i2-open/i2goSignals/pkg/ssfModels"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
    "github.com/stretchr/testify/suite"
)

// SubjectFilterReviewSuite exercises the SSF §9 admin subject-filter review
// endpoint (PRD #97 issue #101): a point lookup by subject, aggregate counts,
// and the bounded pending-removal list. The endpoint is read-only, admin-scoped,
// and inert when subject filtering is disabled server-wide.
type SubjectFilterReviewSuite struct {
    suite.Suite
    instance *ssfInstance
}

func (suite *SubjectFilterReviewSuite) SetupSuite() {
    _ = os.Setenv("I2SIG_SUBJECT_FILTERING", "ENABLED")
    instance, err := createServer(suite.T(), "subject_filter_review_test", true)
    require.NoError(suite.T(), err)
    suite.instance = instance
}

func (suite *SubjectFilterReviewSuite) TearDownSuite() {
    _ = os.Unsetenv("I2SIG_SUBJECT_FILTERING")
    if suite.instance != nil {
        suite.instance.app.Shutdown()
        suite.instance.ts.Close()
    }
}

func TestSubjectFilterReviewSuite(t *testing.T) {
    suite.Run(t, new(SubjectFilterReviewSuite))
}

// newReviewStream creates a transmitter stream with the given baseline and
// (optional) subject-filter mode. Returns the stream id.
func (suite *SubjectFilterReviewSuite) newReviewStream(defaultSubjects, mode string) string {
    t := suite.T()
    instance := suite.instance
    ctx := context.WithValue(context.Background(), authUtil.AuthContextKey,
        &authUtil.AuthContext{ProjectId: instance.projectId})
    created, err := instance.streamSvc().CreateStream(ctx, model.StreamStateRecord{
        StreamConfiguration: model.StreamConfiguration{
            Iss: "DEFAULT",
            Aud: []string{"https://receiver.example.com"},
            Delivery: &model.OneOfStreamConfigurationDelivery{
                PollTransmitMethod: &model.PollTransmitMethod{Method: model.DeliveryPoll},
            },
        },
        DefaultSubjects:   defaultSubjects,
        SubjectFilterMode: mode,
    }, instance.projectId, nil)
    require.NoError(t, err)
    return created.Id
}

// postReview sends the admin review request body to /subject-filter/review with
// the given bearer token.
func (suite *SubjectFilterReviewSuite) postReview(token, body string) *http.Response {
    req, _ := http.NewRequest(http.MethodPost, suite.instance.ts.URL+"/subject-filter/review",
        strings.NewReader(body))
    req.Header.Set("Authorization", "Bearer "+token)
    req.Header.Set("Content-Type", "application/json")
    resp, err := suite.instance.client.Do(req)
    require.NoError(suite.T(), err)
    return resp
}

// TestPointLookupHit verifies a point lookup for a subject that has been
// Added to a NONE stream returns found=true and the entry's kind. This is the
// tracer-bullet behavior of the review endpoint.
func (suite *SubjectFilterReviewSuite) TestPointLookupHit() {
    t := suite.T()
    sid := suite.newReviewStream(model.DefaultSubjectsNone, model.SubjectFilterModeLocal)

    state, err := suite.instance.GetStreamState(sid)
    require.NoError(t, err)

    subject := &goSet.SubjectIdentifier{Format: "email"}
    subject.AddEmail("alice@example.com")
    _, err = suite.instance.persistence.SubjectFilterService.AddSubject(context.Background(), state, subject, true)
    require.NoError(t, err)

    body := `{"stream_id":"` + sid + `","subject":{"format":"email","email":"alice@example.com"}}`
    resp := suite.postReview(suite.instance.streamMgmtToken, body)
    require.Equal(t, http.StatusOK, resp.StatusCode, "admin review must return 200 for a known stream")

    var review reviewResponse
    raw, _ := io.ReadAll(resp.Body)
    require.NoError(t, json.Unmarshal(raw, &review), "response must be JSON: %s", string(raw))

    require.NotNil(t, review.Lookup, "response must include a lookup result when a subject was supplied")
    assert.True(t, review.Lookup.Found, "alice was Added to the NONE stream; lookup must report found=true")
    assert.Equal(t, model.SubjectKindSimple, review.Lookup.Kind, "an email subject is a simple kind")
    assert.True(t, review.Lookup.Delivers, "an active inclusion on a NONE stream must currently be delivering")
    assert.False(t, review.Lookup.Pending, "an active (non-grace) entry must not be reported as pending")
    assert.Equal(t, sid, review.StreamId, "stream_id must echo back")
    assert.Equal(t, model.DefaultSubjectsNone, review.DefaultSubjects, "baseline must reflect the stream's defaultSubjects")
    assert.Equal(t, model.SubjectFilterModeLocal, review.Mode, "mode must reflect the stream's subject-filter mode")
}

// TestPointLookupMiss verifies a point lookup for a subject that has never
// been Added to a NONE stream reports found=false and Delivers=false (the
// NONE baseline default). The endpoint must not 404 for a missing subject —
// "no entry" is a normal review result, not an error.
func (suite *SubjectFilterReviewSuite) TestPointLookupMiss() {
    t := suite.T()
    sid := suite.newReviewStream(model.DefaultSubjectsNone, model.SubjectFilterModeLocal)

    body := `{"stream_id":"` + sid + `","subject":{"format":"email","email":"ghost@example.com"}}`
    resp := suite.postReview(suite.instance.streamMgmtToken, body)
    require.Equal(t, http.StatusOK, resp.StatusCode, "missing-subject point lookup must return 200, not 404")

    var review reviewResponse
    raw, _ := io.ReadAll(resp.Body)
    require.NoError(t, json.Unmarshal(raw, &review))
    require.NotNil(t, review.Lookup, "subject in body must produce a lookup result")
    assert.False(t, review.Lookup.Found, "ghost was never added; lookup must report found=false")
    assert.False(t, review.Lookup.Delivers, "NONE baseline + no entry must not deliver")
    assert.False(t, review.Lookup.Pending, "a non-existent entry cannot be pending")
}

// TestAggregateCountsReportTotalAndPending verifies the summary response
// includes counts.total (every entry for the stream) and counts.pending (the
// subset currently inside the §9.3 grace window). The pending subset is built
// by stamping a per-stream grace override and Removing one of three subjects;
// the other two stay active.
func (suite *SubjectFilterReviewSuite) TestAggregateCountsReportTotalAndPending() {
    t := suite.T()
    sid := suite.newReviewStream(model.DefaultSubjectsNone, model.SubjectFilterModeLocal)

    state, err := suite.instance.GetStreamState(sid)
    require.NoError(t, err)
    // A non-trivial grace so the Remove below stamps EnforceAt rather than
    // hard-deleting the entry. The service reads the grace from the passed
    // state record (resolveGrace), so an in-memory mutation suffices for the
    // test — no DAO write is needed.
    state.SubjectRemovalGraceSeconds = 60

    addr := func(local string) *goSet.SubjectIdentifier {
        s := &goSet.SubjectIdentifier{Format: "email"}
        s.AddEmail(local)
        return s
    }
    for _, who := range []string{"alice@example.com", "bob@example.com", "carol@example.com"} {
        _, err = suite.instance.persistence.SubjectFilterService.AddSubject(context.Background(), state, addr(who), true)
        require.NoError(t, err)
    }
    _, err = suite.instance.persistence.SubjectFilterService.RemoveSubject(context.Background(), state, addr("alice@example.com"))
    require.NoError(t, err)

    body := `{"stream_id":"` + sid + `"}`
    resp := suite.postReview(suite.instance.streamMgmtToken, body)
    require.Equal(t, http.StatusOK, resp.StatusCode)

    var review reviewResponse
    raw, _ := io.ReadAll(resp.Body)
    require.NoError(t, json.Unmarshal(raw, &review))
    require.NotNil(t, review.Counts, "summary response must include counts")
    assert.Equal(t, int64(3), review.Counts.Total, "all three Added entries must count toward total")
    assert.Equal(t, int64(1), review.Counts.Pending, "only the pending-removal entry must count toward pending")
    assert.Nil(t, review.Lookup, "no subject in body must yield no lookup result")
}

// TestPendingListEnumeratesGraceWindowEntries verifies the bounded pending
// list contains only entries currently inside their §9.3 grace window —
// canonical key, kind, and EnforceAt populated — and excludes active
// (EnforceAt zero) entries.
func (suite *SubjectFilterReviewSuite) TestPendingListEnumeratesGraceWindowEntries() {
    t := suite.T()
    sid := suite.newReviewStream(model.DefaultSubjectsNone, model.SubjectFilterModeLocal)

    state, err := suite.instance.GetStreamState(sid)
    require.NoError(t, err)
    state.SubjectRemovalGraceSeconds = 60

    addr := func(local string) *goSet.SubjectIdentifier {
        s := &goSet.SubjectIdentifier{Format: "email"}
        s.AddEmail(local)
        return s
    }
    for _, who := range []string{"alice@example.com", "bob@example.com"} {
        _, err = suite.instance.persistence.SubjectFilterService.AddSubject(context.Background(), state, addr(who), true)
        require.NoError(t, err)
    }
    _, err = suite.instance.persistence.SubjectFilterService.RemoveSubject(context.Background(), state, addr("alice@example.com"))
    require.NoError(t, err)

    body := `{"stream_id":"` + sid + `"}`
    resp := suite.postReview(suite.instance.streamMgmtToken, body)
    require.Equal(t, http.StatusOK, resp.StatusCode)

    var review reviewResponse
    raw, _ := io.ReadAll(resp.Body)
    require.NoError(t, json.Unmarshal(raw, &review))
    require.Len(t, review.Pending, 1, "exactly one entry must be mid-removal")
    only := review.Pending[0]
    assert.Contains(t, only.CanonicalKey, "alice@example.com", "alice is the entry currently in grace")
    assert.Equal(t, model.SubjectKindSimple, only.Kind, "alice's email is a simple-kind subject")
    assert.False(t, only.EnforceAt.IsZero(), "a pending entry must carry a non-zero EnforceAt")
}

// TestPassthruReportsNoLocalFilter verifies a PASSTHRU stream returns 200
// with passthru_no_local_filter=true and no counts/pending — goSignals keeps
// no local filter table for PASSTHRU, so "no local data" is unambiguous
// rather than an error response.
func (suite *SubjectFilterReviewSuite) TestPassthruReportsNoLocalFilter() {
    t := suite.T()
    instance := suite.instance

    // PASSTHRU stream creation requires a relay-capable upstream so #89's
    // validation accepts it. A fake upstream + relay service is wired in for
    // the duration of this test.
    const upstreamIss = "https://upstream.example"
    upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
        w.WriteHeader(http.StatusOK)
    }))
    defer upstream.Close()
    upstreamCfg := &model.TransmitterConfiguration{
        Issuer:                upstreamIss,
        AddSubjectEndpoint:    upstream.URL + "/add-subject",
        RemoveSubjectEndpoint: upstream.URL + "/remove-subject",
    }

    var rxStream model.StreamStateRecord
    rxStream.StreamConfiguration.Id = "rx-upstream-review"
    rxStream.StreamConfiguration.Iss = upstreamIss
    prevRelay := instance.app.SubjectRelayService
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
    defer func() {
        instance.streamSvc().SetSubjectRelayService(prevRelay)
        instance.app.SubjectRelayService = prevRelay
    }()

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

    body := `{"stream_id":"` + created.Id + `"}`
    resp := suite.postReview(suite.instance.streamMgmtToken, body)
    require.Equal(t, http.StatusOK, resp.StatusCode, "PASSTHRU stream must return 200, not error")

    var review reviewResponse
    raw, _ := io.ReadAll(resp.Body)
    require.NoError(t, json.Unmarshal(raw, &review))
    assert.True(t, review.PassthruNoLocalFilter, "PASSTHRU stream must report passthru_no_local_filter=true")
    assert.Nil(t, review.Counts, "PASSTHRU has no local table, so no counts")
    assert.Empty(t, review.Pending, "PASSTHRU has no local table, so no pending list")
    assert.Equal(t, model.SubjectFilterModePassthru, review.Mode, "mode must echo PASSTHRU")
}

// TestReceiverScopedTokenIsRejected verifies the review endpoint refuses a
// per-stream receiver token (the SSF event-delivery scope used by Add/Remove
// Subject). Subject review needs an operator privilege — admin or stream-mgmt
// — distinct from the receiver scope.
func (suite *SubjectFilterReviewSuite) TestReceiverScopedTokenIsRejected() {
    t := suite.T()
    sid := suite.newReviewStream(model.DefaultSubjectsNone, model.SubjectFilterModeLocal)

    receiverToken, err := suite.instance.GetAuthIssuer().IssueStreamToken(sid, suite.instance.projectId, nil)
    require.NoError(t, err)

    body := `{"stream_id":"` + sid + `"}`
    resp := suite.postReview(receiverToken, body)
    assert.True(t, resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden,
        "a receiver-scoped token must be rejected (401/403), got %d", resp.StatusCode)
}

// TestReviewReturns404WhenFilteringDisabled verifies the §9 admin review
// endpoint is inert when subject filtering is disabled server-wide — the
// "disabled by default" stance of PRD #89 covers the §9 layer too. The
// suite default has filtering enabled; this test toggles it off and back on.
func (suite *SubjectFilterReviewSuite) TestReviewReturns404WhenFilteringDisabled() {
    t := suite.T()
    _ = os.Unsetenv("I2SIG_SUBJECT_FILTERING")
    defer func() { _ = os.Setenv("I2SIG_SUBJECT_FILTERING", "ENABLED") }()

    body := `{"stream_id":"any-id"}`
    resp := suite.postReview(suite.instance.streamMgmtToken, body)
    assert.Equal(t, http.StatusNotFound, resp.StatusCode,
        "review endpoint must 404 when subject filtering is disabled")
}

// reviewResponse mirrors the wire shape of the admin review endpoint. It is
// kept inside the test package so the test pins the JSON contract independently
// of the server's internal types.
type reviewResponse struct {
    StreamId              string             `json:"stream_id"`
    Mode                  string             `json:"mode"`
    DefaultSubjects       string             `json:"default_subjects"`
    PassthruNoLocalFilter bool               `json:"passthru_no_local_filter"`
    Counts                *reviewCounts      `json:"counts,omitempty"`
    Pending               []reviewEntry      `json:"pending,omitempty"`
    Lookup                *reviewLookup      `json:"lookup,omitempty"`
}

type reviewCounts struct {
    Total   int64 `json:"total"`
    Pending int64 `json:"pending"`
}

type reviewEntry struct {
    Subject      *goSet.SubjectIdentifier `json:"subject"`
    CanonicalKey string                   `json:"canonical_key"`
    Kind         string                   `json:"kind"`
    EnforceAt    time.Time                `json:"enforce_at"`
}

type reviewLookup struct {
    Subject      *goSet.SubjectIdentifier `json:"subject"`
    Found        bool                     `json:"found"`
    Kind         string                   `json:"kind"`
    CanonicalKey string                   `json:"canonical_key"`
    EnforceAt    time.Time                `json:"enforce_at"`
    Pending      bool                     `json:"pending"`
    Delivers     bool                     `json:"delivers"`
}
