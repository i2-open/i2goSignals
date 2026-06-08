package services

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/i2-open/i2goSignals/pkg/dao/memory"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockPeer stands in for a remote goSignals node's SSF surface: a well-known
// endpoint advertising a stream configuration_endpoint, and that endpoint which
// accepts the mirrored SstpPairBootstrap. failStream toggles a 500 on the stream
// endpoint to exercise the cascade-failure path. lastBootstrap captures what the
// peer received so the test can assert the mirror shape.
type mockPeer struct {
	ts            *httptest.Server
	lastBootstrap model.SstpPairBootstrap
	got           bool
}

func newMockPeer(t *testing.T, failStream bool) *mockPeer {
	t.Helper()
	mp := &mockPeer{}
	mux := http.NewServeMux()
	var streamEndpoint string
	mux.HandleFunc("/.well-known/ssf-configuration", func(w http.ResponseWriter, r *http.Request) {
		cfg := model.TransmitterConfiguration{
			Issuer:                "https://peer.example",
			ConfigurationEndpoint: streamEndpoint,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(cfg)
	})
	mux.HandleFunc("/streams", func(w http.ResponseWriter, r *http.Request) {
		if failStream {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		var b model.SstpPairBootstrap
		_ = json.NewDecoder(r.Body).Decode(&b)
		mp.lastBootstrap = b
		mp.got = true
		// Echo a minimal created record with the peer's own PairId.
		resp := model.StreamStateRecord{
			PairId: "peer-pair-id-123",
			SstpMethod: &model.SstpMethod{
				Role:        b.Role,
				EndpointUrl: "https://peer.example/sstp/peer-pair-id-123",
			},
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(resp)
	})
	mp.ts = httptest.NewServer(mux)
	streamEndpoint = mp.ts.URL + "/streams"
	t.Cleanup(mp.ts.Close)
	return mp
}

// sstpFixture builds a StreamService wired with memory DAOs, an initialized
// token key (so the responder bearer can be minted), and a BaseUrl so the
// responder EndpointUrl is derived as an absolute https URL.
func sstpFixture(t *testing.T) (*StreamService, *ServerService) {
	t.Helper()
	streamDAO := memory.NewStreamDAO()
	keyDAO := memory.NewKeyDAO()
	keyService := NewKeyService(keyDAO, "https://local.example", nil, nil)
	require.NoError(t, keyService.InitializeTokenKey(context.Background(), "https://local.example"))

	serverDAO := memory.NewServerDAO()
	serverService := NewServerService(serverDAO)

	svc := NewStreamService(streamDAO, keyService, "https://local.example", StreamServiceConfig{})
	svc.SetServerService(serverService)
	baseUrl, _ := url.Parse("https://local.example")
	svc.SetBaseUrl(baseUrl)
	return svc, serverService
}

func responderBootstrap() model.SstpPairBootstrap {
	return model.SstpPairBootstrap{
		Role:        model.SstpRoleResponder,
		Description: "pair A",
		Primary: model.SstpDirection{
			Iss:  "https://local.example",
			Aud:  []string{"https://peer.example"},
			Mode: model.SstpModePublish,
		},
		Inbound: model.SstpDirection{
			Iss:  "https://peer.example",
			Aud:  []string{"https://local.example"},
			Mode: model.SstpModeImport,
		},
	}
}

// TestCreateSstpPair_ResponderExpandsBidirectionalRecord is the tracer bullet:
// a responder bootstrap with no peer alias produces a populated bidirectional
// StreamStateRecord with both directions, a server-derived EndpointUrl, a
// server-minted bearer, and the PairId == tx-side Id == Mongo _id invariant.
func TestCreateSstpPair_ResponderExpandsBidirectionalRecord(t *testing.T) {
	svc, _ := sstpFixture(t)

	rec, err := svc.CreateSstpPair(context.Background(), responderBootstrap(), "proj-1", nil)
	require.NoError(t, err)

	// Bidirectional shape.
	assert.Equal(t, model.DeliverySstpPair, rec.GetType())
	require.NotNil(t, rec.SstpInbound)
	require.NotNil(t, rec.SstpMethod)
	assert.True(t, rec.HasInbound())
	assert.True(t, rec.HasOutbound())

	// Aliasing invariant: PairId == tx-side StreamConfiguration.Id == _id hex.
	assert.NotEmpty(t, rec.PairId)
	assert.Equal(t, rec.PairId, rec.StreamConfiguration.Id)
	assert.Equal(t, rec.Id.Hex(), rec.StreamConfiguration.Id)
	// Inbound side has its own SID, distinct from the tx side.
	assert.NotEmpty(t, rec.SstpInbound.Id)
	assert.NotEqual(t, rec.StreamConfiguration.Id, rec.SstpInbound.Id)

	// Responder server-derives the EndpointUrl as /sstp/<PairId>.
	assert.Equal(t, "https://local.example/sstp/"+rec.PairId, rec.SstpMethod.EndpointUrl)

	// Responder server-mints a bearer.
	assert.True(t, strings.HasPrefix(rec.SstpMethod.AuthorizationHeader, "Bearer "),
		"responder should mint a Bearer, got %q", rec.SstpMethod.AuthorizationHeader)

	// Business-plane iss/aud ride per direction.
	assert.Equal(t, "https://local.example", rec.StreamConfiguration.Iss)
	assert.Equal(t, []string{"https://peer.example"}, rec.StreamConfiguration.Aud)
	assert.Equal(t, "https://peer.example", rec.SstpInbound.Iss)
	assert.Equal(t, []string{"https://local.example"}, rec.SstpInbound.Aud)

	// Mode maps to RouteMode per direction.
	assert.Equal(t, model.RouteModePublish, rec.StreamConfiguration.RouteMode)
	assert.Equal(t, model.RouteModeImport, rec.SstpInbound.RouteMode)

	// Markers carry only the method URN.
	require.NotNil(t, rec.StreamConfiguration.Delivery.SstpTransmitMarker)
	require.NotNil(t, rec.SstpInbound.Delivery.SstpReceiveMarker)

	// Status is Enabled at create on both directions.
	assert.Equal(t, model.StreamStateEnabled, rec.Status)
	assert.Equal(t, model.StreamStateEnabled, rec.InboundStatus)

	// Persisted and retrievable by PairId.
	got, err := svc.GetStreamStateByPairId(context.Background(), rec.PairId)
	require.NoError(t, err)
	assert.Equal(t, rec.PairId, got.PairId)
}

func TestCreateSstpPair_RoleRequired(t *testing.T) {
	svc, _ := sstpFixture(t)

	b := responderBootstrap()
	b.Role = ""
	_, err := svc.CreateSstpPair(context.Background(), b, "proj-1", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "role")

	b.Role = "gateway"
	_, err = svc.CreateSstpPair(context.Background(), b, "proj-1", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "role")
}

func TestCreateSstpPair_ResponderRejectsOperatorEndpointAndBearer(t *testing.T) {
	svc, _ := sstpFixture(t)

	b := responderBootstrap()
	b.EndpointUrl = "https://attacker.example/sstp/x"
	_, err := svc.CreateSstpPair(context.Background(), b, "proj-1", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "endpoint_url")

	b = responderBootstrap()
	b.AuthorizationHeader = "Bearer operator-supplied"
	_, err = svc.CreateSstpPair(context.Background(), b, "proj-1", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "authorization_header")
}

func initiatorBootstrap() model.SstpPairBootstrap {
	b := responderBootstrap()
	b.Role = model.SstpRoleInitiator
	b.AuthorizationHeader = "Bearer peer-minted"
	b.EndpointUrl = "https://peer.example/sstp/abc"
	return b
}

func TestCreateSstpPair_InitiatorRequiresOperatorBearer(t *testing.T) {
	svc, _ := sstpFixture(t)

	b := initiatorBootstrap()
	b.AuthorizationHeader = ""
	_, err := svc.CreateSstpPair(context.Background(), b, "proj-1", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "authorization_header")
}

func TestCreateSstpPair_InitiatorKeepsOperatorEndpointAndBearer(t *testing.T) {
	svc, _ := sstpFixture(t)

	rec, err := svc.CreateSstpPair(context.Background(), initiatorBootstrap(), "proj-1", nil)
	require.NoError(t, err)
	require.NotNil(t, rec.SstpMethod)
	assert.Equal(t, model.SstpRoleInitiator, rec.SstpMethod.Role)
	assert.Equal(t, "https://peer.example/sstp/abc", rec.SstpMethod.EndpointUrl)
	assert.Equal(t, "Bearer peer-minted", rec.SstpMethod.AuthorizationHeader)
}

func TestCreateSstpPair_EndpointUrlValidation(t *testing.T) {
	t.Run("http rejected by default", func(t *testing.T) {
		svc, _ := sstpFixture(t)
		b := initiatorBootstrap()
		b.EndpointUrl = "http://peer.example/sstp/abc"
		_, err := svc.CreateSstpPair(context.Background(), b, "proj-1", nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "endpoint_url")
	})

	t.Run("http accepted when insecure flag set", func(t *testing.T) {
		t.Setenv("I2SIG_INSECURE_SSTP_HTTP", "true")
		svc, _ := sstpFixture(t)
		b := initiatorBootstrap()
		b.EndpointUrl = "http://peer.example/sstp/abc"
		rec, err := svc.CreateSstpPair(context.Background(), b, "proj-1", nil)
		require.NoError(t, err)
		assert.Equal(t, "http://peer.example/sstp/abc", rec.SstpMethod.EndpointUrl)
	})

	t.Run("query rejected", func(t *testing.T) {
		svc, _ := sstpFixture(t)
		b := initiatorBootstrap()
		b.EndpointUrl = "https://peer.example/sstp/abc?x=1"
		_, err := svc.CreateSstpPair(context.Background(), b, "proj-1", nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "query")
	})

	t.Run("fragment rejected", func(t *testing.T) {
		svc, _ := sstpFixture(t)
		b := initiatorBootstrap()
		b.EndpointUrl = "https://peer.example/sstp/abc#frag"
		_, err := svc.CreateSstpPair(context.Background(), b, "proj-1", nil)
		require.Error(t, err)
	})

	t.Run("missing host rejected", func(t *testing.T) {
		svc, _ := sstpFixture(t)
		b := initiatorBootstrap()
		b.EndpointUrl = "https:///sstp/abc"
		_, err := svc.CreateSstpPair(context.Background(), b, "proj-1", nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "host")
	})
}

func TestCreateSstpPair_AsymmetricIssAudAccepted(t *testing.T) {
	svc, _ := sstpFixture(t)
	b := responderBootstrap()
	// Deliberately non-reciprocal: primary.iss differs from inbound.aud, etc.
	b.Primary.Iss = "https://hopA.example"
	b.Primary.Aud = []string{"https://hopB.example"}
	b.Inbound.Iss = "https://hopC.example"
	b.Inbound.Aud = []string{"https://hopD.example"}
	rec, err := svc.CreateSstpPair(context.Background(), b, "proj-1", nil)
	require.NoError(t, err)
	assert.Equal(t, "https://hopA.example", rec.StreamConfiguration.Iss)
	assert.Equal(t, "https://hopC.example", rec.SstpInbound.Iss)
}

// storePeerServer injects a Server with a static token credential pointing at
// the mock peer's host, mirroring the txalias prior art.
func storePeerServer(t *testing.T, ss *ServerService, host string) string {
	t.Helper()
	token := "peer-token"
	srv := &model.Server{
		Alias:       "peer-node",
		Type:        model.ServerTypeGosignals,
		Host:        host,
		ClientToken: &token,
		ProjectId:   "proj-1",
	}
	require.NoError(t, ss.serverDAO.Create(context.Background(), srv))
	return srv.Alias
}

func TestCreateSstpPair_ResponderCascadeSucceeds(t *testing.T) {
	svc, ss := sstpFixture(t)
	peer := newMockPeer(t, false)
	alias := storePeerServer(t, ss, peer.ts.URL)

	b := responderBootstrap()
	b.PeerServerAlias = alias
	rec, err := svc.CreateSstpPair(context.Background(), b, "proj-1", nil)
	require.NoError(t, err)

	// Local row exists.
	got, err := svc.GetStreamStateByPairId(context.Background(), rec.PairId)
	require.NoError(t, err)
	assert.Equal(t, model.SstpRoleResponder, got.SstpMethod.Role)

	// Peer received a mirrored bootstrap: opposite role, directions swapped,
	// carrying this responder's endpoint + bearer.
	require.True(t, peer.got, "peer should have received the mirrored bootstrap")
	assert.Equal(t, model.SstpRoleInitiator, peer.lastBootstrap.Role)
	assert.Equal(t, rec.SstpMethod.EndpointUrl, peer.lastBootstrap.EndpointUrl)
	assert.Equal(t, rec.SstpMethod.AuthorizationHeader, peer.lastBootstrap.AuthorizationHeader)
	assert.Equal(t, rec.PairId, peer.lastBootstrap.PeerPairId)
	// directions swapped: peer.primary.iss == our inbound.iss
	assert.Equal(t, b.Inbound.Iss, peer.lastBootstrap.Primary.Iss)
	assert.Equal(t, b.Primary.Iss, peer.lastBootstrap.Inbound.Iss)

	// Local record learned the peer's PairId.
	assert.Equal(t, "peer-pair-id-123", got.SstpMethod.PeerPairId)
}

func TestCreateSstpPair_ResponderRollsBackOnCascadeFailure(t *testing.T) {
	svc, ss := sstpFixture(t)
	peer := newMockPeer(t, true) // peer returns 500
	alias := storePeerServer(t, ss, peer.ts.URL)

	b := responderBootstrap()
	b.PeerServerAlias = alias
	_, err := svc.CreateSstpPair(context.Background(), b, "proj-1", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cascade")

	// No local row should remain (responder rolls back, ReceivePush-style).
	all := svc.ListStreams(context.Background())
	assert.Empty(t, all, "responder should have rolled back its local half")
}

func TestCreateSstpPair_InitiatorNoRollbackOnCascadeFailure(t *testing.T) {
	svc, ss := sstpFixture(t)
	peer := newMockPeer(t, true) // peer returns 500
	alias := storePeerServer(t, ss, peer.ts.URL)

	b := initiatorBootstrap()
	b.PeerServerAlias = alias
	_, err := svc.CreateSstpPair(context.Background(), b, "proj-1", nil)
	require.Error(t, err)

	// Initiator never wrote a local row, so nothing to roll back and nothing left.
	all := svc.ListStreams(context.Background())
	assert.Empty(t, all, "initiator should not have written any local row")
}
