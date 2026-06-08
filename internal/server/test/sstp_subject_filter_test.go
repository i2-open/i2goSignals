package test

import (
    "context"
    "io"
    "net/http"
    "os"
    "strings"
    "testing"

    "github.com/i2-open/i2goSignals/pkg/goSet"
    "github.com/i2-open/i2goSignals/pkg/ssfModels"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
    "go.mongodb.org/mongo-driver/v2/bson"
)

// SSTP slice 11 (PRD #154 Q45): each end of an SSTP pair manages its OWN
// outbound (transmit-side) subject filter. SSF §8.1.3 Add/Remove Subject calls
// must target the transmit direction; a call against an SSTP record's rxSid
// (the inbound/receive direction) is rejected with a 4xx that points the
// operator at the peer's transmit-side API, because inbound events are trusted
// to be pre-filtered by the peer and there is no local ingest-time filter site.

// newSstpFilterPair provisions a transmitter-shaped SSTP pair record and mints
// the matching pair bearer (StreamIds=[txSid, rxSid]). The primary
// StreamConfiguration is the transmit (outbound) side carrying a real PollTransmit
// delivery + DefaultSubjects so the txSid case exercises a live subject filter;
// SstpInbound carries the receive-side SID.
func newSstpFilterPair(t *testing.T, instance *ssfInstance, defaultSubjects string) (txSid, rxSid, bearer string) {
    t.Helper()

    txSid = bson.NewObjectID().Hex()
    rxSid = bson.NewObjectID().Hex()
    pairId := bson.NewObjectID().Hex()

    rec := &model.StreamStateRecord{
        StreamConfiguration: model.StreamConfiguration{
            Id:  txSid,
            Iss: "DEFAULT",
            Aud: []string{"peer.example.com"},
            Delivery: &model.OneOfStreamConfigurationDelivery{
                PollTransmitMethod: &model.PollTransmitMethod{Method: model.DeliveryPoll},
            },
        },
        SstpInbound: &model.StreamConfiguration{
            Id:  rxSid,
            Iss: "peer.example.com",
            Aud: []string{"DEFAULT"},
        },
        SstpMethod: &model.SstpMethod{
            Role: "responder",
        },
        PairId:          pairId,
        ProjectId:       instance.projectId,
        Status:          model.StreamStateEnabled,
        DefaultSubjects: defaultSubjects,
    }
    err := instance.streamSvc().PersistStreamStateRecord(context.Background(), rec)
    require.NoError(t, err, "persist SSTP pair record")

    bearer, err = instance.GetAuthIssuer().IssueSstpPairToken(txSid, rxSid, instance.projectId, false, nil)
    require.NoError(t, err, "mint SSTP pair token")
    return txSid, rxSid, bearer
}

// postSubjectReq sends an Add/Remove Subject request for the given SID + bearer.
func postSubjectReq(t *testing.T, instance *ssfInstance, path, bearer, sid, email string) *http.Response {
    t.Helper()
    body := `{"stream_id":"` + sid + `","subject":{"format":"email","email":"` + email + `"}}`
    req, err := http.NewRequest(http.MethodPost, instance.ts.URL+path, strings.NewReader(body))
    require.NoError(t, err)
    req.Header.Set("Authorization", "Bearer "+bearer)
    req.Header.Set("Content-Type", "application/json")
    resp, err := instance.client.Do(req)
    require.NoError(t, err)
    return resp
}

func TestSstpSubjectFilter(t *testing.T) {
    _ = os.Setenv("I2SIG_SUBJECT_FILTERING", "ENABLED")
    defer func() { _ = os.Unsetenv("I2SIG_SUBJECT_FILTERING") }()

    instance, err := createServer(t, "sstp-subject-filter", true)
    require.NoError(t, err)
    defer func() {
        if instance.ts != nil {
            instance.ts.Close()
        }
        instance.app.Shutdown()
    }()

    t.Run("AddSubjectOnRxSidReturns4xxWithPeerGuidance", func(t *testing.T) {
        _, rxSid, bearer := newSstpFilterPair(t, instance, model.DefaultSubjectsNone)
        resp := postSubjectReq(t, instance, "/add-subject", bearer, rxSid, "alice@example.com")
        defer resp.Body.Close()

        assert.GreaterOrEqual(t, resp.StatusCode, 400, "rxSid add-subject must be a 4xx")
        assert.Less(t, resp.StatusCode, 500, "rxSid add-subject must be a 4xx, not 5xx")
        body, _ := io.ReadAll(resp.Body)
        lower := strings.ToLower(string(body))
        assert.True(t, strings.Contains(lower, "peer") || strings.Contains(lower, "transmit") || strings.Contains(lower, "upstream"),
            "error body must point the operator at the peer/transmit-side API, got: %s", string(body))
    })

    t.Run("RemoveSubjectOnRxSidReturns4xxWithPeerGuidance", func(t *testing.T) {
        _, rxSid, bearer := newSstpFilterPair(t, instance, model.DefaultSubjectsAll)
        resp := postSubjectReq(t, instance, "/remove-subject", bearer, rxSid, "bob@example.com")
        defer resp.Body.Close()

        assert.GreaterOrEqual(t, resp.StatusCode, 400, "rxSid remove-subject must be a 4xx")
        assert.Less(t, resp.StatusCode, 500, "rxSid remove-subject must be a 4xx, not 5xx")
        body, _ := io.ReadAll(resp.Body)
        lower := strings.ToLower(string(body))
        assert.True(t, strings.Contains(lower, "peer") || strings.Contains(lower, "transmit") || strings.Contains(lower, "upstream"),
            "error body must point the operator at the peer/transmit-side API, got: %s", string(body))
    })

    t.Run("AddSubjectOnTxSidConsultsTxFilter", func(t *testing.T) {
        txSid, _, bearer := newSstpFilterPair(t, instance, model.DefaultSubjectsNone)
        resp := postSubjectReq(t, instance, "/add-subject", bearer, txSid, "carol@example.com")
        defer resp.Body.Close()
        assert.Equal(t, http.StatusOK, resp.StatusCode, "txSid add-subject behaves normally (200)")

        // Outbound from the SSTP pair consults the tx-side subject filter: after
        // Add on a NONE baseline the subject becomes deliverable.
        state, err := instance.GetStreamState(txSid)
        require.NoError(t, err)
        subject := &goSet.SubjectIdentifier{Format: "email"}
        subject.AddEmail("carol@example.com")
        event := &model.AgEventRecord{Event: goSet.SecurityEventToken{SubjectId: subject}}
        assert.True(t, instance.persistence.SubjectFilterService.Allows(context.Background(), state, event),
            "after Add Subject on txSid the SSTP pair's outbound filter must deliver the added subject")
    })

    t.Run("RemoveSubjectOnTxSidReturns204", func(t *testing.T) {
        txSid, _, bearer := newSstpFilterPair(t, instance, model.DefaultSubjectsAll)
        resp := postSubjectReq(t, instance, "/remove-subject", bearer, txSid, "dave@example.com")
        defer resp.Body.Close()
        assert.Equal(t, http.StatusNoContent, resp.StatusCode, "txSid remove-subject behaves normally (204)")
    })
}
