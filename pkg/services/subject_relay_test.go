package services

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/i2-open/i2goSignals/pkg/dao/memory"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// relayReceiver builds a receiver stream record carrying only the fields the
// relay-target resolver reads: the stream id and the upstream issuer.
func relayReceiver(id, iss string) model.StreamStateRecord {
	var st model.StreamStateRecord
	st.StreamConfiguration.Id = id
	st.StreamConfiguration.Iss = iss
	return st
}

// relayDownstream builds a downstream transmitter stream with the given
// issuer and event source.
func relayDownstream(iss string, src *model.EventSource) *model.StreamStateRecord {
	st := &model.StreamStateRecord{EventSource: src}
	st.StreamConfiguration.Iss = iss
	return st
}

// TestResolveRelayTarget_AudienceSingleIssuerMatch is the tracer bullet for
// issue #95: an AUDIENCE-routed transmitter stream resolves its relay target
// by matching its issuer to exactly one receiver stream's issuer.
func TestResolveRelayTarget_AudienceSingleIssuerMatch(t *testing.T) {
	receivers := []model.StreamStateRecord{
		relayReceiver("rx-1", "https://issuer.example/a"),
		relayReceiver("rx-2", "https://issuer.example/b"),
	}
	downstream := relayDownstream("https://issuer.example/b", &model.EventSource{Type: model.EventSourceAudience})

	target, err := ResolveRelayTarget(downstream, receivers)
	if err != nil {
		t.Fatalf("ResolveRelayTarget: %v", err)
	}
	if target.StreamConfiguration.Id != "rx-2" {
		t.Fatalf("expected relay target rx-2, got %q", target.StreamConfiguration.Id)
	}
}

// TestResolveRelayTarget_AudienceAmbiguous verifies that when several receiver
// streams share the downstream issuer the relay target is ambiguous and config
// must be rejected (#95 acceptance criterion 4).
func TestResolveRelayTarget_AudienceAmbiguous(t *testing.T) {
	receivers := []model.StreamStateRecord{
		relayReceiver("rx-1", "https://issuer.example/shared"),
		relayReceiver("rx-2", "https://issuer.example/shared"),
	}
	downstream := relayDownstream("https://issuer.example/shared", &model.EventSource{Type: model.EventSourceAudience})

	_, err := ResolveRelayTarget(downstream, receivers)
	if !errors.Is(err, ErrRelayTargetAmbiguous) {
		t.Fatalf("expected ErrRelayTargetAmbiguous, got %v", err)
	}
}

// TestResolveRelayTarget_ExplicitHandlerSidWins verifies that an explicitly
// named Subject handler SID (EventSource.SourceStreamIds) resolves the relay
// target directly, even when the issuer match would otherwise be ambiguous
// (#95 acceptance criterion 2).
func TestResolveRelayTarget_ExplicitHandlerSidWins(t *testing.T) {
	receivers := []model.StreamStateRecord{
		relayReceiver("rx-1", "https://issuer.example/shared"),
		relayReceiver("rx-2", "https://issuer.example/shared"),
	}
	downstream := relayDownstream("https://issuer.example/shared", &model.EventSource{
		Type:            model.EventSourceExplicit,
		SourceStreamIds: []string{"rx-2"},
	})

	target, err := ResolveRelayTarget(downstream, receivers)
	if err != nil {
		t.Fatalf("ResolveRelayTarget: %v", err)
	}
	if target.StreamConfiguration.Id != "rx-2" {
		t.Fatalf("expected explicitly named relay target rx-2, got %q", target.StreamConfiguration.Id)
	}
}

// TestResolveRelayTarget_NoMatch verifies that a downstream issuer with no
// matching receiver stream yields ErrRelayTargetNotFound.
func TestResolveRelayTarget_NoMatch(t *testing.T) {
	receivers := []model.StreamStateRecord{
		relayReceiver("rx-1", "https://issuer.example/a"),
	}
	downstream := relayDownstream("https://issuer.example/unknown", &model.EventSource{Type: model.EventSourceAudience})

	_, err := ResolveRelayTarget(downstream, receivers)
	if !errors.Is(err, ErrRelayTargetNotFound) {
		t.Fatalf("expected ErrRelayTargetNotFound, got %v", err)
	}
}

// TestClassifyUpstreamSupport_PassthruNoEndpointsRejected verifies that a
// PASSTHRU stream against an upstream that advertises no subject endpoints is
// rejected at config time (#95 acceptance criterion 3).
func TestClassifyUpstreamSupport_PassthruNoEndpointsRejected(t *testing.T) {
	upstream := &model.TransmitterConfiguration{Issuer: "https://issuer.example"}

	verdict := ClassifyUpstreamSupport(model.SubjectFilterModePassthru, upstream)
	if verdict.Err == nil {
		t.Fatal("PASSTHRU against an upstream with no subject endpoints must be rejected")
	}
}

// upstreamWithEndpoints builds an upstream discovery record that advertises the
// add and remove subject endpoints.
func upstreamWithEndpoints() *model.TransmitterConfiguration {
	return &model.TransmitterConfiguration{
		Issuer:                "https://issuer.example",
		AddSubjectEndpoint:    "https://issuer.example/add-subject",
		RemoveSubjectEndpoint: "https://issuer.example/remove-subject",
	}
}

// TestClassifyUpstreamSupport_PassthruWithEndpointsAccepted verifies that a
// PASSTHRU stream against an upstream that advertises both subject endpoints is
// accepted with no error and no warning.
func TestClassifyUpstreamSupport_PassthruWithEndpointsAccepted(t *testing.T) {
	verdict := ClassifyUpstreamSupport(model.SubjectFilterModePassthru, upstreamWithEndpoints())
	if verdict.Err != nil {
		t.Fatalf("PASSTHRU against a filtering-capable upstream must be accepted: %v", verdict.Err)
	}
	if verdict.Warn != "" {
		t.Fatalf("expected no warning, got %q", verdict.Warn)
	}
}

// TestClassifyUpstreamSupport_LocalNoEndpointsWarns verifies that a LOCAL
// stream against an upstream with no subject endpoints is survivable: it earns
// a WARN, not a rejection (#95 acceptance criterion 5).
func TestClassifyUpstreamSupport_LocalNoEndpointsWarns(t *testing.T) {
	upstream := &model.TransmitterConfiguration{Issuer: "https://issuer.example"}

	verdict := ClassifyUpstreamSupport(model.SubjectFilterModeLocal, upstream)
	if verdict.Err != nil {
		t.Fatalf("LOCAL must never be rejected at config time: %v", verdict.Err)
	}
	if verdict.Warn == "" {
		t.Fatal("LOCAL against a non-filtering upstream must produce a WARN")
	}
}

// capturedRelay records what an upstream subject endpoint received.
type capturedRelay struct {
	method string
	path   string
	auth   string
	body   map[string]interface{}
}

// upstreamRelayServer starts a fake upstream that records add/remove-subject
// calls and replies with status.
func upstreamRelayServer(t *testing.T, status int) (*httptest.Server, *capturedRelay) {
	t.Helper()
	got := &capturedRelay{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.method = r.Method
		got.path = r.URL.Path
		got.auth = r.Header.Get("Authorization")
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &got.body)
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	return srv, got
}

// TestRelaySubjectChange_AddPostsToAddEndpoint is the tracer bullet for the
// PASSTHRU relay (#95 acceptance criterion 1): an Add Subject relays a POST to
// the upstream's add_subject_endpoint carrying the remote stream id, subject
// and verified flag, with the upstream credential.
func TestRelaySubjectChange_AddPostsToAddEndpoint(t *testing.T) {
	srv, got := upstreamRelayServer(t, http.StatusOK)
	upstream := &model.TransmitterConfiguration{
		AddSubjectEndpoint:    srv.URL + "/add-subject",
		RemoveSubjectEndpoint: srv.URL + "/remove-subject",
	}
	subject := emailSubject("alice@example.com")

	err := RelaySubjectChange(context.Background(), srv.Client(), upstream, "Bearer up-token", "remote-99", subject, true, true)
	if err != nil {
		t.Fatalf("RelaySubjectChange: %v", err)
	}
	if got.method != http.MethodPost || got.path != "/add-subject" {
		t.Fatalf("expected POST /add-subject, got %s %s", got.method, got.path)
	}
	if got.auth != "Bearer up-token" {
		t.Fatalf("expected upstream credential to be forwarded, got %q", got.auth)
	}
	if got.body["stream_id"] != "remote-99" {
		t.Fatalf("expected relayed stream_id remote-99, got %v", got.body["stream_id"])
	}
	if got.body["verified"] != true {
		t.Fatalf("expected verified=true relayed, got %v", got.body["verified"])
	}
	if got.body["subject"] == nil {
		t.Fatal("expected the subject identifier to be relayed")
	}
}

// TestRelaySubjectChange_RemovePostsToRemoveEndpoint verifies a Remove Subject
// relays a POST to the upstream's remove_subject_endpoint.
func TestRelaySubjectChange_RemovePostsToRemoveEndpoint(t *testing.T) {
	srv, got := upstreamRelayServer(t, http.StatusNoContent)
	upstream := &model.TransmitterConfiguration{
		AddSubjectEndpoint:    srv.URL + "/add-subject",
		RemoveSubjectEndpoint: srv.URL + "/remove-subject",
	}

	err := RelaySubjectChange(context.Background(), srv.Client(), upstream, "Bearer up-token", "remote-99", emailSubject("alice@example.com"), false, false)
	if err != nil {
		t.Fatalf("RelaySubjectChange: %v", err)
	}
	if got.method != http.MethodPost || got.path != "/remove-subject" {
		t.Fatalf("expected POST /remove-subject, got %s %s", got.method, got.path)
	}
}

// TestRelaySubjectChange_UpstreamErrorStatusReturnsError verifies that a
// non-2xx upstream response surfaces as an error so the caller can refuse the
// subject change rather than silently dropping the relay.
func TestRelaySubjectChange_UpstreamErrorStatusReturnsError(t *testing.T) {
	srv, _ := upstreamRelayServer(t, http.StatusBadRequest)
	upstream := &model.TransmitterConfiguration{
		AddSubjectEndpoint:    srv.URL + "/add-subject",
		RemoveSubjectEndpoint: srv.URL + "/remove-subject",
	}

	err := RelaySubjectChange(context.Background(), srv.Client(), upstream, "Bearer up-token", "remote-99", emailSubject("alice@example.com"), false, true)
	if err == nil {
		t.Fatal("a non-2xx upstream response must surface as an error")
	}
}

// relayServiceWith builds a SubjectRelayService over a fixed receiver-stream
// list and upstream connection — the fixture for service-level relay tests.
func relayServiceWith(receivers []model.StreamStateRecord, conn *UpstreamConn) *SubjectRelayService {
	return &SubjectRelayService{
		listReceivers: func(context.Context) ([]model.StreamStateRecord, error) {
			return receivers, nil
		},
		resolve: func(context.Context, *model.StreamStateRecord) (*UpstreamConn, error) {
			return conn, nil
		},
	}
}

// relayReceiverWithRemoteId builds a receiver stream carrying the upstream's
// assigned stream id.
func relayReceiverWithRemoteId(id, iss, remoteId string) model.StreamStateRecord {
	rx := relayReceiver(id, iss)
	rx.StreamConfiguration.RemoteStreamId = &remoteId
	return rx
}

// TestSubjectRelayService_Relay_PassthruPostsUpstream verifies that Relay
// resolves the feeding receiver stream and posts the subject change to the
// upstream carrying the upstream's assigned stream id (#95 criterion 1).
func TestSubjectRelayService_Relay_PassthruPostsUpstream(t *testing.T) {
	srv, got := upstreamRelayServer(t, http.StatusOK)
	upstream := &model.TransmitterConfiguration{
		AddSubjectEndpoint:    srv.URL + "/add-subject",
		RemoveSubjectEndpoint: srv.URL + "/remove-subject",
	}
	receivers := []model.StreamStateRecord{relayReceiverWithRemoteId("rx-1", "https://issuer.example", "remote-7")}
	relaySvc := relayServiceWith(receivers, &UpstreamConn{Config: upstream, HttpClient: srv.Client()})

	downstream := relayDownstream("https://issuer.example", &model.EventSource{Type: model.EventSourceAudience})
	if err := relaySvc.Relay(context.Background(), downstream, emailSubject("alice@example.com"), false, true); err != nil {
		t.Fatalf("Relay: %v", err)
	}
	if got.path != "/add-subject" {
		t.Fatalf("expected relay to POST /add-subject, got %s", got.path)
	}
	if got.body["stream_id"] != "remote-7" {
		t.Fatalf("expected relay to carry the upstream stream id remote-7, got %v", got.body["stream_id"])
	}
}

// TestSubjectRelayService_ValidateConfig_PassthruAmbiguousRejected verifies
// that a PASSTHRU stream whose relay target is ambiguous is rejected at config
// time (#95 acceptance criterion 4).
func TestSubjectRelayService_ValidateConfig_PassthruAmbiguousRejected(t *testing.T) {
	receivers := []model.StreamStateRecord{
		relayReceiver("rx-1", "https://issuer.example/shared"),
		relayReceiver("rx-2", "https://issuer.example/shared"),
	}
	relaySvc := relayServiceWith(receivers, nil)

	downstream := relayDownstream("https://issuer.example/shared", &model.EventSource{Type: model.EventSourceAudience})
	downstream.SubjectFilterMode = model.SubjectFilterModePassthru

	verdict := relaySvc.ValidateConfig(context.Background(), downstream)
	if !errors.Is(verdict.Err, ErrRelayTargetAmbiguous) {
		t.Fatalf("expected an ambiguous PASSTHRU target to be rejected, got %v", verdict.Err)
	}
}

// TestSubjectRelayService_ValidateConfig_LocalNoEndpointsWarns verifies a
// LOCAL stream against an upstream that advertises no subject endpoints is
// survivable: a WARN, not a rejection (#95 acceptance criterion 5).
func TestSubjectRelayService_ValidateConfig_LocalNoEndpointsWarns(t *testing.T) {
	receivers := []model.StreamStateRecord{relayReceiver("rx-1", "https://issuer.example")}
	upstream := &model.TransmitterConfiguration{Issuer: "https://issuer.example"}
	relaySvc := relayServiceWith(receivers, &UpstreamConn{Config: upstream})

	downstream := relayDownstream("https://issuer.example", &model.EventSource{Type: model.EventSourceAudience})
	downstream.SubjectFilterMode = model.SubjectFilterModeLocal

	verdict := relaySvc.ValidateConfig(context.Background(), downstream)
	if verdict.Err != nil {
		t.Fatalf("LOCAL must never be rejected at config time: %v", verdict.Err)
	}
	if verdict.Warn == "" {
		t.Fatal("LOCAL against a non-filtering upstream must produce a WARN")
	}
}

// nonFilteringRelayService builds a SubjectRelayService whose single upstream
// advertises no subject endpoints — the fixture for config-time CreateStream
// validation tests.
func nonFilteringRelayService() *SubjectRelayService {
	receivers := []model.StreamStateRecord{relayReceiver("rx-1", "test-issuer")}
	return &SubjectRelayService{
		listReceivers: func(context.Context) ([]model.StreamStateRecord, error) {
			return receivers, nil
		},
		resolve: func(context.Context, *model.StreamStateRecord) (*UpstreamConn, error) {
			return &UpstreamConn{Config: &model.TransmitterConfiguration{Issuer: "test-issuer"}}, nil
		},
	}
}

// TestStreamService_CreatePassthruRejectedWhenUpstreamLacksEndpoints verifies
// that CreateStream rejects a PASSTHRU transmitter stream whose upstream
// advertises no subject endpoints (#95 acceptance criterion 3).
func TestStreamService_CreatePassthruRejectedWhenUpstreamLacksEndpoints(t *testing.T) {
	t.Setenv("I2SIG_SUBJECT_FILTERING", "ENABLED")
	svc := newSubjectFilterTestService()
	svc.SetSubjectRelayService(nonFilteringRelayService())

	req := pushTransmitterRequest()
	req.SubjectFilterMode = model.SubjectFilterModePassthru
	req.EventSource = &model.EventSource{Type: model.EventSourceAudience}

	_, err := svc.CreateStream(context.Background(), req, "test-project", nil)
	if err == nil {
		t.Fatal("CreateStream must reject PASSTHRU against a non-filtering upstream")
	}
	// The caller's configuration to fix, so a 400 (#305).
	if !errors.Is(err, ErrInvalidRequest) || !errors.Is(err, ErrUpstreamNoSubjectFiltering) {
		t.Fatalf("expected ErrInvalidRequest wrapping ErrUpstreamNoSubjectFiltering, got %v", err)
	}
}

// TestStreamService_CreateLocalSurvivesNonFilteringUpstream verifies that a
// LOCAL transmitter stream against a non-filtering upstream is still created —
// the misconfiguration is survivable (#95 acceptance criterion 5).
func TestStreamService_CreateLocalSurvivesNonFilteringUpstream(t *testing.T) {
	t.Setenv("I2SIG_SUBJECT_FILTERING", "ENABLED")
	svc := newSubjectFilterTestService()
	svc.SetSubjectRelayService(nonFilteringRelayService())

	req := pushTransmitterRequest()
	req.SubjectFilterMode = model.SubjectFilterModeLocal
	req.EventSource = &model.EventSource{Type: model.EventSourceAudience}

	created, err := svc.CreateStream(context.Background(), req, "test-project", nil)
	if err != nil {
		t.Fatalf("CreateStream must still create a LOCAL stream: %v", err)
	}
	state, err := svc.GetStreamState(context.Background(), created.Id)
	if err != nil {
		t.Fatalf("GetStreamState: %v", err)
	}
	if state.SubjectFilterMode != model.SubjectFilterModeLocal {
		t.Fatalf("expected the LOCAL stream to persist, got mode %q", state.SubjectFilterMode)
	}
}

// ssfConfigurationServer starts a fake source transmitter that serves SSF
// discovery metadata advertising add and remove subject endpoints at
// discoveryPath only (404 elsewhere), and records the Authorization header the
// discovery fetch carried.
func ssfConfigurationServer(t *testing.T, discoveryPath string) (*httptest.Server, *string) {
	t.Helper()
	auth := new(string)
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != discoveryPath {
			http.NotFound(w, r)
			return
		}
		*auth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(model.TransmitterConfiguration{
			Issuer:                srv.URL,
			AddSubjectEndpoint:    srv.URL + "/add-subject",
			RemoveSubjectEndpoint: srv.URL + "/remove-subject",
		})
	}))
	t.Cleanup(srv.Close)
	return srv, auth
}

// closedServerURL returns the URL of a server that is no longer listening: a
// source transmitter that cannot be reached.
func closedServerURL() string {
	srv := httptest.NewServer(http.NotFoundHandler())
	srv.Close()
	return srv.URL
}

// TestDefaultUpstreamResolver_DiscoversSourceTransmitterFromIss verifies that a
// receiver stream with neither tx_alias nor tx_well_known_url still reaches its
// source transmitter: the resolver inserts the SSF well-known component into the
// receiver stream's iss (RFC 8615, SSF §7.2), as the receiver's own status and
// verify discovery does, and fetches with the receiver's tx_token.
func TestDefaultUpstreamResolver_DiscoversSourceTransmitterFromIss(t *testing.T) {
	for _, tc := range []struct {
		name          string
		issuerPath    string
		discoveryPath string
	}{
		{name: "issuer at the host root", issuerPath: "", discoveryPath: "/.well-known/ssf-configuration"},
		{name: "issuer with a path", issuerPath: "/issuer1", discoveryPath: "/.well-known/ssf-configuration/issuer1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, auth := ssfConfigurationServer(t, tc.discoveryPath)
			token := "rx-token"
			receiver := relayReceiver("rx-1", srv.URL+tc.issuerPath)
			receiver.StreamConfiguration.TxToken = &token

			conn, err := NewDefaultUpstreamResolver(nil)(context.Background(), &receiver)
			if err != nil {
				t.Fatalf("resolver must discover the source transmitter from iss: %v", err)
			}
			defer conn.release()
			if conn.Config.AddSubjectEndpoint != srv.URL+"/add-subject" ||
				conn.Config.RemoveSubjectEndpoint != srv.URL+"/remove-subject" {
				t.Fatalf("expected the discovered subject endpoints, got add=%q remove=%q",
					conn.Config.AddSubjectEndpoint, conn.Config.RemoveSubjectEndpoint)
			}
			if *auth != "Bearer rx-token" {
				t.Fatalf("expected discovery to carry the receiver's tx_token, got %q", *auth)
			}
		})
	}
}

// TestDefaultUpstreamResolver_UnusableSourcesFallThroughToIss verifies the
// receiver path's precedence and fall-through: a tx_alias that names no
// registered server, then a tx_well_known_url that cannot be fetched, each give
// way to the next source, ending at the iss-derived well-known URL.
func TestDefaultUpstreamResolver_UnusableSourcesFallThroughToIss(t *testing.T) {
	srv, _ := ssfConfigurationServer(t, "/.well-known/ssf-configuration")
	alias := "unregistered"
	wellKnown := closedServerURL() + "/.well-known/ssf-configuration"
	receiver := relayReceiver("rx-1", srv.URL)
	receiver.StreamConfiguration.TxAlias = &alias
	receiver.StreamConfiguration.TxWellKnownUrl = &wellKnown

	conn, err := NewDefaultUpstreamResolver(NewServerService(memory.NewServerDAO()))(context.Background(), &receiver)
	if err != nil {
		t.Fatalf("unusable tx_alias and tx_well_known_url must fall through to iss: %v", err)
	}
	defer conn.release()
	if conn.Config.AddSubjectEndpoint != srv.URL+"/add-subject" {
		t.Fatalf("expected the iss-derived source transmitter, got add=%q", conn.Config.AddSubjectEndpoint)
	}
}

// TestDefaultUpstreamResolver_MetadataWithoutSubjectEndpoints verifies that
// metadata advertising no subject endpoints gives way to a later source that
// advertises them, and is returned for classification when no source does.
func TestDefaultUpstreamResolver_MetadataWithoutSubjectEndpoints(t *testing.T) {
	bare := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(model.TransmitterConfiguration{Issuer: "https://bare.example"})
	}))
	t.Cleanup(bare.Close)
	bareWellKnown := bare.URL + "/.well-known/ssf-configuration"
	capable, _ := ssfConfigurationServer(t, "/.well-known/ssf-configuration")

	t.Run("a later source advertising subject endpoints wins", func(t *testing.T) {
		receiver := relayReceiver("rx-1", capable.URL)
		receiver.StreamConfiguration.TxWellKnownUrl = &bareWellKnown

		conn, err := NewDefaultUpstreamResolver(nil)(context.Background(), &receiver)
		if err != nil {
			t.Fatalf("resolver: %v", err)
		}
		defer conn.release()
		if conn.Config.AddSubjectEndpoint != capable.URL+"/add-subject" {
			t.Fatalf("expected the iss-derived source advertising subject endpoints, got add=%q", conn.Config.AddSubjectEndpoint)
		}
	})

	t.Run("no source advertises them", func(t *testing.T) {
		receiver := relayReceiver("rx-1", closedServerURL())
		receiver.StreamConfiguration.TxWellKnownUrl = &bareWellKnown

		conn, err := NewDefaultUpstreamResolver(nil)(context.Background(), &receiver)
		if err != nil {
			t.Fatalf("fetched metadata must be returned for classification: %v", err)
		}
		defer conn.release()
		verdict := ClassifyUpstreamSupport(model.SubjectFilterModePassthru, conn.Config)
		if !errors.Is(verdict.Err, ErrUpstreamNoSubjectFiltering) {
			t.Fatalf("expected ErrUpstreamNoSubjectFiltering, got %v", verdict.Err)
		}
	})
}

// TestDefaultUpstreamResolver_NothingToDiscover verifies that a receiver stream
// with no tx_alias, no tx_well_known_url and no iss yields
// ErrUpstreamNotDiscoverable — a configuration the caller can fix — and not
// ErrRelayTargetNotFound, because a receiver stream does feed the stream.
func TestDefaultUpstreamResolver_NothingToDiscover(t *testing.T) {
	receiver := relayReceiver("rx-1", "")

	_, err := NewDefaultUpstreamResolver(nil)(context.Background(), &receiver)
	if !errors.Is(err, ErrUpstreamNotDiscoverable) {
		t.Fatalf("expected ErrUpstreamNotDiscoverable, got %v", err)
	}
	if errors.Is(err, ErrRelayTargetNotFound) {
		t.Fatalf("a receiver stream feeds the stream, so the error must not be ErrRelayTargetNotFound: %v", err)
	}
}

// TestDefaultUpstreamResolver_UnreachableSourceTransmitter verifies that a
// source transmitter that cannot be reached at its iss-derived well-known URL
// is a failure, not a configuration error: validation leaves it unwrapped, so
// it is not ErrInvalidRequest (a 500, not a 400).
func TestDefaultUpstreamResolver_UnreachableSourceTransmitter(t *testing.T) {
	t.Setenv("I2SIG_SUBJECT_FILTERING", "ENABLED")
	receiver := relayReceiver("rx-1", closedServerURL())

	_, err := NewDefaultUpstreamResolver(nil)(context.Background(), &receiver)
	if err == nil {
		t.Fatal("an unreachable source transmitter must fail resolution")
	}
	if errors.Is(err, ErrUpstreamNotDiscoverable) || errors.Is(err, ErrRelayTargetNotFound) {
		t.Fatalf("an unreachable source transmitter is not a configuration error: %v", err)
	}

	svc := newSubjectFilterTestService()
	svc.SetSubjectRelayService(NewSubjectRelayService(
		func(context.Context) ([]model.StreamStateRecord, error) {
			return []model.StreamStateRecord{receiver}, nil
		},
		nil, nil, NewDefaultUpstreamResolver(nil),
	))
	downstream := relayDownstream("test-issuer", &model.EventSource{
		Type:            model.EventSourceExplicit,
		SourceStreamIds: []string{"rx-1"},
	})
	downstream.SubjectFilterMode = model.SubjectFilterModePassthru
	err = svc.validateSubjectFilterMode(context.Background(), downstream)
	if err == nil {
		t.Fatal("validation must refuse a PASSTHRU stream whose source transmitter cannot be reached")
	}
	if errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("an unreachable source transmitter must not be ErrInvalidRequest: %v", err)
	}
}
