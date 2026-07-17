// PRD #49 slice 2b (issue #242) — table-driven coverage for the transmitter
// credential-selection chain (Security-Protocol-Architecture §5, ADR-0049
// r5). Exercises both the SSTP business-pair branch (new in this slice)
// and the extracted push/poll chain, and locks the AC 3 per-pair-bearer
// precedence rule.
package server

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/dao/memory"
	"github.com/i2-open/i2goSignals/pkg/services"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// newCredentialChainTestApp builds a minimal SignalsApplication with only a
// ServerService (memory-backed) wired — that is the only field the credential-
// chain helper touches beyond the stream record. Returns the underlying DAO
// so tests can insert Server rows directly (bypassing CreateServer's live
// well-known probe).
func newCredentialChainTestApp(t *testing.T) (*SignalsApplication, interfaces.ServerDAO) {
	t.Helper()
	serverDAO := memory.NewServerDAO()
	serverService := services.NewServerService(serverDAO)
	return &SignalsApplication{ServerService: serverService}, serverDAO
}

// storeServer inserts a Server row directly via the DAO, bypassing
// CreateServer's network-side validation so the credential-chain test can
// exercise the resolver's alias-lookup branch without a live peer.
func storeServer(t *testing.T, dao interfaces.ServerDAO, alias string, tlsSkip bool, clientToken *string) {
	t.Helper()
	require.NoError(t, dao.Create(context.Background(), &model.Server{
		Alias:         alias,
		Host:          "https://peer.example",
		TLSSkipVerify: tlsSkip,
		ClientToken:   clientToken,
	}))
}

func strPtr(s string) *string { return &s }

// TestResolveTransmitterClient_ChainSelection is the table-driven per-branch
// coverage AC calls for. Each row names one branch of the chain and asserts
// the resolver picks it (and only it).
func TestResolveTransmitterClient_ChainSelection(t *testing.T) {
	sa, dao := newCredentialChainTestApp(t)

	// Push/poll fixtures.
	pushAlias := "push-tx"
	storeServer(t, dao, pushAlias, false, strPtr("push-static-token"))

	sstpAlias := "sstp-peer"
	storeServer(t, dao, sstpAlias, true /*TLSSkipVerify*/, nil)

	pairBearer := "Bearer per-pair-secret"

	cases := []struct {
		name          string
		stream        *model.StreamStateRecord
		wantAuth      string
		wantAuthEmpty bool // when the resolver defers Authorization to the client itself
	}{
		{
			name: "sstp-pair with peer_server_alias and per-pair bearer -> bearer wins",
			stream: &model.StreamStateRecord{
				PairId: "pair-1",
				SstpMethod: &model.SstpMethod{
					Role:                model.SstpRoleInitiator,
					EndpointUrl:         "https://peer.example/sstp/pair-1",
					AuthorizationHeader: pairBearer,
					PeerServerAlias:     sstpAlias,
				},
			},
			wantAuth: pairBearer,
		},
		{
			name: "sstp-pair without alias -> per-pair bearer, default transport",
			stream: &model.StreamStateRecord{
				PairId: "pair-2",
				SstpMethod: &model.SstpMethod{
					Role:                model.SstpRoleInitiator,
					EndpointUrl:         "https://peer.example/sstp/pair-2",
					AuthorizationHeader: pairBearer,
				},
			},
			wantAuth: pairBearer,
		},
		{
			name: "sstp-pair with unknown alias -> fallback to default, bearer still returned",
			stream: &model.StreamStateRecord{
				PairId: "pair-3",
				SstpMethod: &model.SstpMethod{
					Role:                model.SstpRoleInitiator,
					EndpointUrl:         "https://peer.example/sstp/pair-3",
					AuthorizationHeader: pairBearer,
					PeerServerAlias:     "does-not-exist",
				},
			},
			wantAuth: pairBearer,
		},
		{
			name: "push/poll TxAlias -> client handles auth (empty header returned)",
			stream: &model.StreamStateRecord{
				StreamConfiguration: model.StreamConfiguration{
					Id:      "push-sid-1",
					TxAlias: strPtr(pushAlias),
				},
			},
			wantAuthEmpty: true,
		},
		{
			name: "push/poll TxToken back-compat -> client handles auth",
			stream: &model.StreamStateRecord{
				StreamConfiguration: model.StreamConfiguration{
					Id:      "push-sid-2",
					TxToken: strPtr("legacy-static-token"),
				},
			},
			wantAuthEmpty: true,
		},
		{
			name: "push/poll no alias / no token -> default client, no auth",
			stream: &model.StreamStateRecord{
				StreamConfiguration: model.StreamConfiguration{
					Id: "push-sid-3",
				},
			},
			wantAuthEmpty: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, auth, closeClient, err := sa.ResolveTransmitterClient(context.Background(), tc.stream)
			require.NoError(t, err)
			require.NotNil(t, client, "resolver must never return a nil *http.Client")
			require.NotNil(t, closeClient, "resolver must never return a nil close func")
			defer closeClient()

			if tc.wantAuthEmpty {
				assert.Empty(t, auth, "push/poll branches defer Authorization to the client")
			} else {
				assert.Equal(t, tc.wantAuth, auth)
			}
		})
	}
}

// TestResolveTransmitterClient_SstpPairBearerPrecedence pins AC 3 precedence:
// when both a per-pair bearer AND a resolvable Server credential (via
// PeerServerAlias) exist, the per-pair bearer wins the Authorization header
// — the Server's own credential is NOT double-applied. The Server still
// contributes transport POSTURE.
func TestResolveTransmitterClient_SstpPairBearerPrecedence(t *testing.T) {
	sa, dao := newCredentialChainTestApp(t)

	alias := "peer-with-token"
	// Store a Server that WOULD supply its own client credential (static
	// token) if the SSTP branch let it drive Authorization.
	storeServer(t, dao, alias, false, strPtr("SHOULD-NOT-APPEAR-IN-AUTH"))

	pairBearer := "Bearer per-pair-wins"
	stream := &model.StreamStateRecord{
		PairId: "pair-precedence",
		SstpMethod: &model.SstpMethod{
			Role:                model.SstpRoleInitiator,
			EndpointUrl:         "https://peer.example/sstp/pair-precedence",
			AuthorizationHeader: pairBearer,
			PeerServerAlias:     alias,
		},
	}

	client, auth, closeClient, err := sa.ResolveTransmitterClient(context.Background(), stream)
	require.NoError(t, err)
	defer closeClient()

	// AC 3: per-pair bearer wins the header verbatim.
	assert.Equal(t, pairBearer, auth,
		"per-pair bearer must win Authorization even when PeerServerAlias resolves a credentialed Server (AC 3)")

	// The Server's ClientToken must not appear anywhere on the returned auth.
	assert.NotContains(t, auth, "SHOULD-NOT-APPEAR-IN-AUTH",
		"Server credential must NOT be materialized into Authorization when a per-pair bearer is present (ADR-0066)")

	// Transport is real (not nil) — Server contributes posture even in the
	// bearer-wins case.
	assert.NotNil(t, client)
}

// TestResolveTransmitterClient_SstpAliasFallsBackWhenNoBearer covers AC 3's
// "its own credential only when no pair bearer is stored" clause: an SSTP
// pair record with a resolvable PeerServerAlias but NO per-pair bearer
// (edge case — normal responder/initiator paths always have one) lets the
// Server's credential drive Authorization via oauthClient.GetClientForServer
// (which handles the header client-side, so the returned header is empty).
func TestResolveTransmitterClient_SstpAliasFallsBackWhenNoBearer(t *testing.T) {
	sa, dao := newCredentialChainTestApp(t)

	alias := "peer-server-credential"
	storeServer(t, dao, alias, false, strPtr("server-static-token"))

	stream := &model.StreamStateRecord{
		PairId: "pair-no-bearer",
		SstpMethod: &model.SstpMethod{
			Role:            model.SstpRoleInitiator,
			EndpointUrl:     "https://peer.example/sstp/pair-no-bearer",
			PeerServerAlias: alias,
			// AuthorizationHeader intentionally empty.
		},
	}

	client, auth, closeClient, err := sa.ResolveTransmitterClient(context.Background(), stream)
	require.NoError(t, err)
	defer closeClient()

	// Server credential drove the client, so the returned header is empty
	// (client injects Authorization internally per oauthClient contract).
	assert.Empty(t, auth,
		"when no per-pair bearer is stored, the Server credential drives Authorization via the client (AC 3 fallback)")
	assert.NotNil(t, client)
}

// TestResolveTransmitterClient_NilServerService covers the boot-order safety
// path: if a caller reaches the helper before ServerService is wired, an
// SSTP branch with a PeerServerAlias must still return a usable default
// client and the per-pair bearer — never panic.
func TestResolveTransmitterClient_NilServerService(t *testing.T) {
	sa := &SignalsApplication{} // ServerService intentionally nil

	pairBearer := "Bearer resilient"
	stream := &model.StreamStateRecord{
		PairId: "pair-nil-ss",
		SstpMethod: &model.SstpMethod{
			Role:                model.SstpRoleInitiator,
			EndpointUrl:         "https://peer.example/sstp/pair-nil-ss",
			AuthorizationHeader: pairBearer,
			PeerServerAlias:     "irrelevant",
		},
	}

	client, auth, closeClient, err := sa.ResolveTransmitterClient(context.Background(), stream)
	require.NoError(t, err)
	defer closeClient()

	assert.Equal(t, pairBearer, auth)
	assert.NotNil(t, client)
}

// TestGetHTTPClientForStream_DelegatesToResolver proves the historical
// entrypoint is now a thin wrapper over ResolveTransmitterClient — so
// pre-slice call sites automatically pick up the SSTP-aware branch. Uses a
// stream with SstpMethod to demonstrate the delegation: the wrapper must
// return the per-pair bearer, which the pre-slice implementation could not
// do (it only knew about TxAlias/TxToken/TxTLS).
func TestGetHTTPClientForStream_DelegatesToResolver(t *testing.T) {
	sa, _ := newCredentialChainTestApp(t)

	pairBearer := "Bearer wrapper-delegates"
	stream := &model.StreamStateRecord{
		PairId: "pair-wrapper",
		SstpMethod: &model.SstpMethod{
			Role:                model.SstpRoleInitiator,
			EndpointUrl:         "https://peer.example/sstp/pair-wrapper",
			AuthorizationHeader: pairBearer,
		},
	}

	client, auth, closeClient, err := sa.getHTTPClientForStream(context.Background(), stream)
	require.NoError(t, err)
	defer closeClient()

	assert.Equal(t, pairBearer, auth,
		"getHTTPClientForStream must delegate to ResolveTransmitterClient so SSTP records get the per-pair bearer")
	assert.NotNil(t, client)
	// Sanity: it's a real http.Client, not a sentinel.
	_ = (*http.Client)(client)
}
