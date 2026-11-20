// Issue #289 — the server-side SSTP outbound clients must share one pooled
// transport.
//
// Two construction sites used to hand back an unpooled client on every SSTP
// dial cycle:
//
//   - SstpDialerConfig.fillDefaults built `&http.Client{Timeout: 60s}` with a
//     nil Transport, i.e. http.DefaultTransport's 2-idle-conns-per-host cap.
//   - resolveSstpBusinessClient's no-alias fallback built `&http.Client{}` and
//     handed it to tlsSupport.CheckCaInstalled, which — seeing a nil Transport
//     — installed a BRAND NEW *http.Transport on it. That gave every cycle a
//     fresh, empty connection pool and a fresh CA-PEM read off disk, so the
//     production SSTP path re-handshaked TLS on literally every exchange.
//
// These tests pin the shared pool and the unchanged posture branches.
package server

import (
	"context"
	"crypto/tls"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// TestSstpPooledTransportIsSharedAndSized pins the pool itself: one process-wide
// transport, sized past net/http's 2-idle-connections-per-host default, on a
// hardened TLS floor.
func TestSstpPooledTransportIsSharedAndSized(t *testing.T) {
	transport := sstpPooledTransport()
	require.NotNil(t, transport)
	assert.Same(t, transport, sstpPooledTransport(), "the SSTP transport is rebuilt per call; the pool never warms")
	assert.Greater(t, transport.MaxIdleConnsPerHost, http.DefaultMaxIdleConnsPerHost,
		"the SSTP transport still uses the 2-idle-conn default")

	require.NotNil(t, transport.TLSClientConfig)
	assert.GreaterOrEqual(t, transport.TLSClientConfig.MinVersion, uint16(tls.VersionTLS12))
	assert.False(t, transport.TLSClientConfig.InsecureSkipVerify,
		"the shared SSTP transport must verify certificates; skip-verify is a per-stream posture")
}

// TestSstpDialerDefaultClientIsPooled covers construction site 1: the dialer's
// safety-net client keeps its 60s timeout but now rides the shared pool.
func TestSstpDialerDefaultClientIsPooled(t *testing.T) {
	var first, second SstpDialerConfig
	first.fillDefaults()
	second.fillDefaults()

	require.NotNil(t, first.HTTPClient)
	assert.Same(t, first.HTTPClient, second.HTTPClient,
		"each SstpDialerConfig gets its own fallback client, so each gets its own connection pool")
	assert.Equal(t, 60*time.Second, first.HTTPClient.Timeout,
		"the dialer safety-net timeout changed")
	assert.Same(t, sstpPooledTransport(), first.HTTPClient.Transport,
		"the dialer safety-net client is not on the shared pooled transport")

	// An explicitly supplied client still wins outright.
	injected := &http.Client{Timeout: time.Second}
	cfg := SstpDialerConfig{HTTPClient: injected}
	cfg.fillDefaults()
	assert.Same(t, injected, cfg.HTTPClient, "fillDefaults overwrote a caller-supplied client")
}

// TestResolveSstpBusinessClientFallbackIsPooled covers construction site 3 —
// the production hot path. With no PeerServerAlias the credential chain used
// to mint a fresh client (and a fresh transport) per cycle.
func TestResolveSstpBusinessClientFallbackIsPooled(t *testing.T) {
	app, _ := newCredentialChainTestApp(t)
	stream := &model.StreamStateRecord{
		PairId: "pair-pool",
		SstpMethod: &model.SstpMethod{
			EndpointUrl:         "https://peer.example/sstp/pair-pool",
			AuthorizationHeader: "Bearer per-pair-token",
		},
	}

	firstClient, firstAuth, firstClose, err := app.ResolveTransmitterClient(context.Background(), stream)
	require.NoError(t, err)
	require.NotNil(t, firstClose)
	firstClose()

	secondClient, secondAuth, secondClose, err := app.ResolveTransmitterClient(context.Background(), stream)
	require.NoError(t, err)
	require.NotNil(t, secondClose)
	secondClose()

	assert.Same(t, firstClient, secondClient,
		"the SSTP credential-chain fallback still builds a client per cycle; every dial re-handshakes TLS")
	assert.Same(t, sstpPooledTransport(), firstClient.Transport,
		"the SSTP credential-chain fallback is not on the shared pooled transport")

	// AC 3 precedence is untouched: the per-pair bearer still wins.
	assert.Equal(t, "Bearer per-pair-token", firstAuth)
	assert.Equal(t, firstAuth, secondAuth)
}

// TestResolveSstpBusinessClientAliasPostureUnchanged guards the boundary of
// this slice: when PeerServerAlias resolves, the per-server posture client is
// still built by oauthClient and is NOT replaced by the shared pool (the
// stored Server's TLS trust / skip-verify posture must keep applying).
func TestResolveSstpBusinessClientAliasPostureUnchanged(t *testing.T) {
	app, dao := newCredentialChainTestApp(t)
	storeServer(t, dao, "peer-alias", true, nil)

	stream := &model.StreamStateRecord{
		PairId: "pair-alias",
		SstpMethod: &model.SstpMethod{
			EndpointUrl:         "https://peer.example/sstp/pair-alias",
			AuthorizationHeader: "Bearer per-pair-token",
			PeerServerAlias:     "peer-alias",
		},
	}

	client, auth, closeClient, err := app.ResolveTransmitterClient(context.Background(), stream)
	require.NoError(t, err)
	require.NotNil(t, closeClient)
	closeClient()

	assert.Equal(t, "Bearer per-pair-token", auth, "the per-pair bearer must still win (ADR-0066, AC 3)")
	assert.NotSame(t, sstpPooledTransport(), client.Transport,
		"the alias branch was collapsed onto the shared pool; per-server TLS posture would be lost")

	transport, ok := client.Transport.(*http.Transport)
	require.True(t, ok)
	require.NotNil(t, transport.TLSClientConfig)
	assert.True(t, transport.TLSClientConfig.InsecureSkipVerify,
		"the stored Server's per-stream skip-verify posture stopped being honoured")
}
