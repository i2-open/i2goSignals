package services

import (
	"context"
	"errors"
	"net/url"
	"testing"

	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/dao/memory"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCreateSstpPair_BootstrapRefusalsAreCallerErrors pins which CreateSstpPair
// refusals the caller can fix. Each one must carry ErrInvalidRequest, because
// that sentinel is the only thing standing between a bad bootstrap and the
// catch-all 500 the handler otherwise answers (RFC 9110 s15.6.1); SSF s8.1.1.1
// gives 400 for a request the transmitter cannot accept.
func TestCreateSstpPair_BootstrapRefusalsAreCallerErrors(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(b *model.SstpPairBootstrap)
		wantMsg string
	}{
		{
			name:    "unrecognized role",
			mutate:  func(b *model.SstpPairBootstrap) { b.Role = "gateway" },
			wantMsg: "role",
		},
		{
			name:    "missing role",
			mutate:  func(b *model.SstpPairBootstrap) { b.Role = "" },
			wantMsg: "role",
		},
		{
			name:    "primary direction has no iss",
			mutate:  func(b *model.SstpPairBootstrap) { b.Primary.Iss = "" },
			wantMsg: "primary.iss",
		},
		{
			name:    "inbound direction has no aud",
			mutate:  func(b *model.SstpPairBootstrap) { b.Inbound.Aud = nil },
			wantMsg: "inbound.aud",
		},
		{
			name:    "unrecognized direction mode",
			mutate:  func(b *model.SstpPairBootstrap) { b.Primary.Mode = "RELAY" },
			wantMsg: "primary.mode",
		},
		{
			name:    "events pattern will not compile",
			mutate:  func(b *model.SstpPairBootstrap) { b.Primary.Events = []string{"urn:[typo"} },
			wantMsg: "primary.events",
		},
		{
			name:    "responder supplies an endpoint_url",
			mutate:  func(b *model.SstpPairBootstrap) { b.EndpointUrl = "https://attacker.example/sstp/x" },
			wantMsg: "endpoint_url",
		},
		{
			name:    "responder supplies a bearer",
			mutate:  func(b *model.SstpPairBootstrap) { b.AuthorizationHeader = "Bearer operator-supplied" },
			wantMsg: "authorization_header",
		},
		{
			name: "initiator supplies no bearer",
			mutate: func(b *model.SstpPairBootstrap) {
				b.Role = model.SstpRoleInitiator
				b.AuthorizationHeader = ""
			},
			wantMsg: "authorization_header",
		},
		{
			name: "initiator supplies an unusable endpoint_url",
			mutate: func(b *model.SstpPairBootstrap) {
				b.Role = model.SstpRoleInitiator
				b.AuthorizationHeader = "Bearer peer-minted"
				b.EndpointUrl = "ftp://peer.example/sstp/abc"
			},
			wantMsg: "endpoint_url",
		},
		{
			name:    "peer_server_alias names no registered server",
			mutate:  func(b *model.SstpPairBootstrap) { b.PeerServerAlias = "no-such-peer" },
			wantMsg: "peer_server_alias",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc, _ := sstpFixture(t)
			b := responderBootstrap()
			tc.mutate(&b)

			_, err := svc.CreateSstpPair(context.Background(), b, "proj-1", nil)
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrInvalidRequest,
				"the caller can fix this bootstrap, so it must be a 400 and not the server-broke 500")
			assert.Contains(t, err.Error(), tc.wantMsg,
				"the refusal must name the field the caller has to change")
		})
	}
}

// failingServerDAO answers every alias lookup with a store failure. It stands in
// for a Mongo that is down: the caller's bootstrap is fine, so the refusal must
// NOT read as a caller error.
type failingServerDAO struct {
	interfaces.ServerDAO
	err error
}

func (d *failingServerDAO) FindByAlias(_ context.Context, _ string) (*model.Server, error) {
	return nil, d.err
}

// TestCreateSstpPair_AliasStoreFailureIsServerFault separates the two ways an
// alias lookup fails. An alias nobody registered is the caller's to fix (400);
// a store that cannot answer is not, and reporting it as 400 tells the operator
// to correct a bootstrap that was already correct.
func TestCreateSstpPair_AliasStoreFailureIsServerFault(t *testing.T) {
	svc, _ := sstpFixture(t)
	boom := errors.New("connection refused")
	svc.SetServerService(NewServerService(&failingServerDAO{ServerDAO: memory.NewServerDAO(), err: boom}))

	b := responderBootstrap()
	b.PeerServerAlias = "peer-a"

	_, err := svc.CreateSstpPair(context.Background(), b, "proj-1", nil)
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrInvalidRequest,
		"a store that cannot answer is an unexpected server condition, not a bad request")
	assert.ErrorIs(t, err, boom, "the store's own error stays in the chain")
	assert.Contains(t, err.Error(), "peer_server_alias")
}

// TestCreateSstpPair_UnregisteredAliasIsNotAStreamNotFound guards a leak on the
// path that DOES answer 400: the memory and Mongo server DAOs both report an
// unregistered alias as interfaces.ErrNotFound, and passing that through would
// turn a bad alias into a 404 about a stream nobody named.
func TestCreateSstpPair_UnregisteredAliasIsNotAStreamNotFound(t *testing.T) {
	svc, _ := sstpFixture(t)

	b := responderBootstrap()
	b.PeerServerAlias = "no-such-peer"

	_, err := svc.CreateSstpPair(context.Background(), b, "proj-1", nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidRequest)
	assert.NotErrorIs(t, err, interfaces.ErrNotFound)
}

// TestCreateSstpPair_PeerCascadeFailureIsServerFault pins the remaining half of
// the split. The bootstrap is valid and the alias resolves; the peer this server
// was told to provision is the thing that failed. Nothing in the request can be
// corrected to make it succeed, so it stays a 500 — this server does not
// translate a peer's verdict into its own (SSF s8.1.1.1 lists 400 only for a
// request this transmitter cannot accept).
func TestCreateSstpPair_PeerCascadeFailureIsServerFault(t *testing.T) {
	svc, ss := sstpFixture(t)
	peer := newMockPeer(t, true) // peer returns 500
	alias := storePeerServer(t, ss, peer.ts.URL)

	b := responderBootstrap()
	b.PeerServerAlias = alias

	_, err := svc.CreateSstpPair(context.Background(), b, "proj-1", nil)
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrInvalidRequest,
		"an unreachable peer is not something the caller can fix in the bootstrap")
	assert.Contains(t, err.Error(), "cascade")
}

// TestCreateSstpPair_InitiatorPeerCascadeFailureIsServerFault covers the other
// cascade ordering: an initiator cascades before any local write, so its
// failure returns from a different branch than the responder's. It is still
// nothing the caller can fix in the bootstrap, so it stays a 500.
func TestCreateSstpPair_InitiatorPeerCascadeFailureIsServerFault(t *testing.T) {
	svc, ss := sstpFixture(t)
	peer := newMockPeer(t, true) // peer returns 500
	alias := storePeerServer(t, ss, peer.ts.URL)

	b := initiatorBootstrap()
	b.PeerServerAlias = alias

	_, err := svc.CreateSstpPair(context.Background(), b, "proj-1", nil)
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrInvalidRequest,
		"an unreachable peer is not something the caller can fix in the bootstrap")
	assert.Contains(t, err.Error(), "cascade")
}

// TestCreateSstpPair_DerivedResponderEndpointIsServerFault: a responder's
// endpoint_url is built from this server's own base URL, never from the
// bootstrap, so a base URL that yields an unusable endpoint is this server
// misconfigured — a 500, not a 400 telling the caller to change a field they
// never sent.
func TestCreateSstpPair_DerivedResponderEndpointIsServerFault(t *testing.T) {
	svc, _ := sstpFixture(t)
	badBase, err := url.Parse("ftp://local.example")
	require.NoError(t, err)
	svc.SetBaseUrl(badBase)

	_, err = svc.CreateSstpPair(context.Background(), responderBootstrap(), "proj-1", nil)
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrInvalidRequest,
		"the caller supplied no endpoint_url, so there is nothing for them to fix")
	assert.Contains(t, err.Error(), "base URL")
}
