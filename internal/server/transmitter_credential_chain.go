// PRD #49 slice 2b — transmitter credential-selection chain (single named
// helper). Extracted from api_receiver.go:227-289 pre-slice so every
// outbound dial-out path in the server uses ONE resolver. Push delivery
// and poll long-poll get the extraction verbatim; the SSTP business-stream
// dialer gets a new branch that honors PeerServerAlias for TRANSPORT
// POSTURE while the per-pair bearer wins the Authorization header. Control
// streams do NOT call this — they use mTLS-only per ADR-0063.
//
// Canon: Security-Protocol-Architecture §5 "Transmitter credential
// selection"; ADR-0049 r5 (helper stays INTERNAL — no cross-repo export);
// ADR-0066 (bearer is the business-stream L2 menu; per-pair bearer wins);
// ADR-0063 (control streams excluded).
package server

import (
	"context"
	"net/http"

	"github.com/i2-open/i2goSignals/pkg/oauthClient"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/i2-open/i2goSignals/pkg/tlsSupport"
)

// ResolveTransmitterClient is THE transmitter credential-selection chain
// (canon: Security-Protocol-Architecture §5). Every outbound dial-out path
// that must authenticate to a transmitter or the peer end of an SSTP
// business-stream pair calls this helper. Push delivery, poll long-poll,
// SSTP business dialer — all call this. Control streams do NOT (they are
// mTLS-only per ADR-0063 and never carry SstpMethod on the record they
// dial with).
//
// Chain, in order:
//
//  1. SSTP business pair (stream.SstpMethod != nil):
//     a. The per-pair bearer (SstpMethod.AuthorizationHeader) ALWAYS wins
//     the returned Authorization header. It authenticates the
//     business channel end-to-end (ADR-0066: bearer is the L2 menu).
//     b. When SstpMethod.PeerServerAlias resolves a stored Server, the
//     returned client uses that Server's TRANSPORT POSTURE only —
//     TLS trust roots, hostname-mismatch override, OAuth transport,
//     mTLS. The Server's own credential is NOT applied here (would
//     double up on the per-pair bearer, breaking ADR-0066 precedence).
//     c. When PeerServerAlias is empty or does not resolve, the transport
//     is the default http.Client with a system-CA check.
//
//  2. Push / poll (stream.SstpMethod == nil): verbatim extraction of the
//     pre-slice logic — TxAlias → TxToken → per-stream TxTLS → polling
//     legacy AuthorizationHeader → default.
//
// Returns (client, authorizationHeader, closeClient, err). closeClient is
// always non-nil and safe to call — most branches return a no-op.
func (sa *SignalsApplication) ResolveTransmitterClient(ctx context.Context, stream *model.StreamStateRecord) (*http.Client, string, func(), error) {
	if stream.SstpMethod != nil {
		return sa.resolveSstpBusinessClient(ctx, stream)
	}
	return sa.resolveTransmitterClientPushPoll(ctx, stream)
}

// resolveSstpBusinessClient is the SSTP business-pair branch of the chain
// (AC 3 precedence):
//   - The per-pair bearer WINS the Authorization header when present. When
//     PeerServerAlias also resolves, that Server contributes transport
//     POSTURE only — its own credential is NOT materialized into the
//     Authorization header (would double up on the per-pair bearer,
//     breaking ADR-0066 precedence).
//   - When no per-pair bearer is stored, a resolved Server's credential
//     drives the Authorization header (via oauthClient.GetClientForServer,
//     which handles the header client-side).
//   - When neither a bearer nor a resolvable alias is present, the
//     transport is the default http.Client + system-CA check.
func (sa *SignalsApplication) resolveSstpBusinessClient(ctx context.Context, stream *model.StreamStateRecord) (*http.Client, string, func(), error) {
	noop := func() {}
	method := stream.SstpMethod
	auth := method.AuthorizationHeader

	if method.PeerServerAlias != "" && sa.ServerService != nil {
		server, err := sa.ServerService.GetServerByAlias(ctx, method.PeerServerAlias)
		if err != nil || server == nil {
			serverLog.Warn("SSTP: peer_server_alias did not resolve; falling back to default client transport",
				"pair_id", stream.PairId, "alias", method.PeerServerAlias, "error", err)
		} else if auth != "" {
			// Posture-only build: TLS trust / hostname-skip / OAuth transport
			// from the stored Server, but the Server's own credential is NOT
			// materialized into the Authorization header — the per-pair
			// bearer is authoritative (ADR-0066, AC 3).
			client := oauthClient.GetBaseHTTPClientForServer(server)
			return client, auth, noop, nil
		} else {
			// AC 3 fallback: no per-pair bearer is stored, so the Server
			// credential drives Authorization (posture + credential). The
			// oauthClient handles the header client-side.
			//
			// Guard: a Server with no ClientToken, no OAuthClientConfig, and
			// no SpiffeConfig has no auth mechanism at all — GetClientForServer
			// would still return a plain TLS client with no Authorization
			// injection, and the dialer would POST with no bearer at all.
			// Detect that explicitly so operators see a clear "credential
			// missing" WARN instead of silent 401 loops at the peer.
			if !hasAuthMechanism(server) {
				serverLog.Warn("SSTP: peer_server_alias resolves to a Server with no credential and no per-pair bearer; outbound will be unauthenticated",
					"pair_id", stream.PairId, "alias", method.PeerServerAlias)
				return oauthClient.GetBaseHTTPClientForServer(server), "", noop, nil
			}
			client, closeClient, cerr := oauthClient.GetClientForServer(ctx, server)
			if cerr == nil {
				return client, "", closeClient, nil
			}
			serverLog.Warn("SSTP: server credential unavailable; posture-only fallback",
				"pair_id", stream.PairId, "alias", method.PeerServerAlias, "error", cerr)
			return oauthClient.GetBaseHTTPClientForServer(server), "", noop, nil
		}
	}

	client := &http.Client{}
	tlsSupport.CheckCaInstalled(client)
	return client, auth, noop, nil
}

// hasAuthMechanism reports whether the Server carries at least one credential
// source (bearer token, OAuth client, or SPIFFE identity). A Server with only
// TLS trust roots configured returns false.
func hasAuthMechanism(server *model.Server) bool {
	if server == nil {
		return false
	}
	if server.ClientToken != nil && *server.ClientToken != "" {
		return true
	}
	if server.OAuthClientConfig != nil {
		return true
	}
	if server.SpiffeConfig != nil {
		return true
	}
	return false
}

// resolveTransmitterClientPushPoll is the push / poll credential chain,
// extracted verbatim from api_receiver.go:227-289 pre-slice. Strict
// behavior-preserving extraction (AC 5 push-delivery parity): every branch
// and log line is unchanged in meaning; only the enclosing method name
// moved. The pre-slice getHTTPClientForStream is now a one-line wrapper
// that dispatches through ResolveTransmitterClient so the SSTP-aware
// branch above is picked up automatically for any caller that already
// used the old name against an SSTP pair record.
func (sa *SignalsApplication) resolveTransmitterClientPushPoll(ctx context.Context, stream *model.StreamStateRecord) (*http.Client, string, func(), error) {
	noop := func() {}
	conf := stream.StreamConfiguration
	var server *model.Server
	var err error

	// 1. Try TxAlias (New preferred method) - get server configuration first.
	server, err = sa.getServerForStream(ctx, stream)
	if err != nil {
		alias := ""
		if conf.TxAlias != nil {
			alias = *conf.TxAlias
		}
		serverLog.Warn("RCV: Server not found for alias", "alias", alias, "error", err)
	}

	// 2. Backward compatibility: TxToken (no server object). Carry the per-
	// stream transmitter-TLS settings so the inline static-token path honors
	// a self-signed / hostname-mismatched transmitter cert.
	if server == nil && conf.TxToken != nil && *conf.TxToken != "" {
		server = &model.Server{
			ClientToken:    conf.TxToken,
			TLSCertificate: conf.TxTLSCertificate,
			TLSSkipVerify:  conf.TxTLSSkipVerify,
		}
	}

	// Use unified client acquisition if server is available.
	if server != nil {
		client, closeClient, err := oauthClient.GetClientForServer(ctx, server)
		if err == nil {
			return client, "", closeClient, nil // Client handles Authorization header
		}
		alias := ""
		if conf.TxAlias != nil {
			alias = *conf.TxAlias
		}
		serverLog.Error("RCV: Failed to get client for server", "alias", alias, "error", err)
	}

	// 3. Per-stream transmitter-TLS settings (no TxAlias / no TxToken): honor
	// TxTLSSkipVerify / TxTLSCertificate set on the stream itself.
	if conf.TxTLSSkipVerify || conf.TxTLSCertificate != "" {
		srv := &model.Server{TLSSkipVerify: conf.TxTLSSkipVerify, TLSCertificate: conf.TxTLSCertificate}
		client, closeClient, err := oauthClient.GetClientForServer(ctx, srv)
		if err == nil {
			return client, "", closeClient, nil
		}
		serverLog.Warn("RCV: failed to build TLS-skip client for stream; falling back", "sid", conf.Id, "error", err)
	}

	// 4. Fallback for Polling Receiver (legacy delivery method auth).
	if stream.GetType() == model.ReceivePoll && stream.Delivery.PollReceiveMethod != nil && stream.Delivery.PollReceiveMethod.AuthorizationHeader != "" {
		serverLog.Warn("RCV: polling service authentication information missing. Defaulting to TLS config only", "sid", conf.Id)
		client := &http.Client{}
		tlsSupport.CheckCaInstalled(client)
		return client, stream.Delivery.PollReceiveMethod.AuthorizationHeader, noop, nil
	}

	// Default client without extra authorization.
	client := &http.Client{}
	tlsSupport.CheckCaInstalled(client)
	return client, "", noop, nil
}
