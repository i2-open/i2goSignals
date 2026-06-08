package services

import (
    "context"
    "net/http"
    "testing"

    "github.com/i2-open/i2goSignals/pkg/goSet"
    model "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// noneUpstreamReceiver builds a receiver stream that feeds a HYBRID downstream
// and whose upstream applies a defaultSubjects=NONE baseline — the only
// baseline against which HYBRID engages its upstream relay (issue #96).
func noneUpstreamReceiver(id, iss, remoteId string) model.StreamStateRecord {
    rx := relayReceiverWithRemoteId(id, iss, remoteId)
    rx.DefaultSubjects = model.DefaultSubjectsNone
    return rx
}

// hybridDownstream builds an AUDIENCE-routed HYBRID transmitter stream with the
// given id and issuer.
func hybridDownstream(id, iss string) *model.StreamStateRecord {
    st := relayDownstream(iss, &model.EventSource{Type: model.EventSourceAudience})
    st.StreamConfiguration.Id = id
    st.SubjectFilterMode = model.SubjectFilterModeHybrid
    return st
}

// hybridRelayService wires a SubjectRelayService for HYBRID relay tests: a
// fixed receiver and downstream-stream list, an upstream connection, and an
// interested-set predicate evaluated per downstream stream.
func hybridRelayService(receivers, transmitters []model.StreamStateRecord, conn *UpstreamConn, interested func(*model.StreamStateRecord) bool) *SubjectRelayService {
    return &SubjectRelayService{
        listReceivers:    func(context.Context) ([]model.StreamStateRecord, error) { return receivers, nil },
        resolve:          func(context.Context, *model.StreamStateRecord) (*UpstreamConn, error) { return conn, nil },
        listTransmitters: func(context.Context) ([]model.StreamStateRecord, error) { return transmitters, nil },
        interested: func(_ context.Context, st *model.StreamStateRecord, _ *goSet.SubjectIdentifier) bool {
            return interested(st)
        },
    }
}

// TestRelayHybrid_AddRelaysOnZeroToOneTransition is the tracer bullet for issue
// #96: a HYBRID add against a NONE upstream, when no other downstream is yet
// interested in the subject, relays the add upstream (the 0→1 transition).
func TestRelayHybrid_AddRelaysOnZeroToOneTransition(t *testing.T) {
    srv, got := upstreamRelayServer(t, http.StatusOK)
    upstream := &model.TransmitterConfiguration{
        AddSubjectEndpoint:    srv.URL + "/add-subject",
        RemoveSubjectEndpoint: srv.URL + "/remove-subject",
    }
    receivers := []model.StreamStateRecord{noneUpstreamReceiver("rx-1", "https://issuer.example", "remote-7")}
    downstream := hybridDownstream("tx-1", "https://issuer.example")
    transmitters := []model.StreamStateRecord{*downstream}
    relaySvc := hybridRelayService(receivers, transmitters,
        &UpstreamConn{Config: upstream, HttpClient: srv.Client()},
        func(*model.StreamStateRecord) bool { return false })

    if err := relaySvc.RelayHybrid(context.Background(), downstream, emailSubject("alice@example.com"), true, true); err != nil {
        t.Fatalf("RelayHybrid: %v", err)
    }
    if got.path != "/add-subject" {
        t.Fatalf("expected a 0→1 add to relay POST /add-subject, got %q", got.path)
    }
    if got.body["stream_id"] != "remote-7" {
        t.Fatalf("expected the relay to carry the upstream stream id remote-7, got %v", got.body["stream_id"])
    }
}

// TestRelayHybrid_AddSuppressedWhenSiblingInterested verifies that a HYBRID add
// does not relay upstream when another downstream fed by the same subject
// handler is already interested in the subject — the interested-set was
// already ≥1, so this is not a 0→1 transition.
func TestRelayHybrid_AddSuppressedWhenSiblingInterested(t *testing.T) {
    srv, got := upstreamRelayServer(t, http.StatusOK)
    upstream := &model.TransmitterConfiguration{
        AddSubjectEndpoint:    srv.URL + "/add-subject",
        RemoveSubjectEndpoint: srv.URL + "/remove-subject",
    }
    receivers := []model.StreamStateRecord{noneUpstreamReceiver("rx-1", "https://issuer.example", "remote-7")}
    downstream := hybridDownstream("tx-1", "https://issuer.example")
    sibling := hybridDownstream("tx-2", "https://issuer.example")
    transmitters := []model.StreamStateRecord{*downstream, *sibling}
    // The sibling tx-2 already selects the subject.
    relaySvc := hybridRelayService(receivers, transmitters,
        &UpstreamConn{Config: upstream, HttpClient: srv.Client()},
        func(st *model.StreamStateRecord) bool { return st.StreamConfiguration.Id == "tx-2" })

    if err := relaySvc.RelayHybrid(context.Background(), downstream, emailSubject("alice@example.com"), true, true); err != nil {
        t.Fatalf("RelayHybrid: %v", err)
    }
    if got.path != "" {
        t.Fatalf("expected no relay when a sibling is already interested, got POST %q", got.path)
    }
}

// TestRelayHybrid_RemoveRelaysOnOneToZeroTransition verifies that a HYBRID
// remove relays upstream when no other downstream remains interested in the
// subject — the last interested downstream dropping it (the 1→0 transition).
func TestRelayHybrid_RemoveRelaysOnOneToZeroTransition(t *testing.T) {
    srv, got := upstreamRelayServer(t, http.StatusNoContent)
    upstream := &model.TransmitterConfiguration{
        AddSubjectEndpoint:    srv.URL + "/add-subject",
        RemoveSubjectEndpoint: srv.URL + "/remove-subject",
    }
    receivers := []model.StreamStateRecord{noneUpstreamReceiver("rx-1", "https://issuer.example", "remote-7")}
    downstream := hybridDownstream("tx-1", "https://issuer.example")
    transmitters := []model.StreamStateRecord{*downstream}
    // downstream's own filter entry has already been removed by the caller, so
    // no downstream remains interested.
    relaySvc := hybridRelayService(receivers, transmitters,
        &UpstreamConn{Config: upstream, HttpClient: srv.Client()},
        func(*model.StreamStateRecord) bool { return false })

    if err := relaySvc.RelayHybrid(context.Background(), downstream, emailSubject("alice@example.com"), false, false); err != nil {
        t.Fatalf("RelayHybrid: %v", err)
    }
    if got.path != "/remove-subject" {
        t.Fatalf("expected a 1→0 remove to relay POST /remove-subject, got %q", got.path)
    }
}

// TestRelayHybrid_RemoveSuppressedWhenSiblingInterested verifies that a HYBRID
// remove does not relay upstream while another downstream fed by the same
// subject handler is still interested — one downstream's remove must never
// starve another (issue #96 acceptance criterion 4).
func TestRelayHybrid_RemoveSuppressedWhenSiblingInterested(t *testing.T) {
    srv, got := upstreamRelayServer(t, http.StatusNoContent)
    upstream := &model.TransmitterConfiguration{
        AddSubjectEndpoint:    srv.URL + "/add-subject",
        RemoveSubjectEndpoint: srv.URL + "/remove-subject",
    }
    receivers := []model.StreamStateRecord{noneUpstreamReceiver("rx-1", "https://issuer.example", "remote-7")}
    downstream := hybridDownstream("tx-1", "https://issuer.example")
    sibling := hybridDownstream("tx-2", "https://issuer.example")
    transmitters := []model.StreamStateRecord{*downstream, *sibling}
    relaySvc := hybridRelayService(receivers, transmitters,
        &UpstreamConn{Config: upstream, HttpClient: srv.Client()},
        func(st *model.StreamStateRecord) bool { return st.StreamConfiguration.Id == "tx-2" })

    if err := relaySvc.RelayHybrid(context.Background(), downstream, emailSubject("alice@example.com"), false, false); err != nil {
        t.Fatalf("RelayHybrid: %v", err)
    }
    if got.path != "" {
        t.Fatalf("expected no relay while a sibling is still interested, got POST %q", got.path)
    }
}

// TestRelayHybrid_AllUpstreamNeverRelays verifies that against an ALL upstream
// HYBRID performs no relay at all — it behaves as pure local filtering, since
// relaying a remove could starve a not-yet-created downstream (issue #96
// acceptance criterion 5).
func TestRelayHybrid_AllUpstreamNeverRelays(t *testing.T) {
    srv, got := upstreamRelayServer(t, http.StatusOK)
    upstream := &model.TransmitterConfiguration{
        AddSubjectEndpoint:    srv.URL + "/add-subject",
        RemoveSubjectEndpoint: srv.URL + "/remove-subject",
    }
    // An ALL upstream: the relay-target receiver carries no NONE baseline.
    receivers := []model.StreamStateRecord{relayReceiverWithRemoteId("rx-1", "https://issuer.example", "remote-7")}
    receivers[0].DefaultSubjects = model.DefaultSubjectsAll
    downstream := hybridDownstream("tx-1", "https://issuer.example")
    transmitters := []model.StreamStateRecord{*downstream}
    relaySvc := hybridRelayService(receivers, transmitters,
        &UpstreamConn{Config: upstream, HttpClient: srv.Client()},
        func(*model.StreamStateRecord) bool { return false })

    if err := relaySvc.RelayHybrid(context.Background(), downstream, emailSubject("alice@example.com"), true, true); err != nil {
        t.Fatalf("RelayHybrid: %v", err)
    }
    if got.path != "" {
        t.Fatalf("expected no relay against an ALL upstream, got POST %q", got.path)
    }
}
