package services

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/i2-open/i2goSignals/internal/authUtil"
	"github.com/i2-open/i2goSignals/pkg/httpSupport"
	"github.com/i2-open/i2goSignals/pkg/oauthClient"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/i2-open/i2goSignals/pkg/wellKnownSupport"
	"go.mongodb.org/mongo-driver/v2/bson"
)

// insecureSstpHttpEnabled reports whether plain-http SSTP EndpointUrls are
// permitted. Controlled by the I2SIG_INSECURE_SSTP_HTTP env var (default false,
// PRD #154 Q28). Read per-call so tests can flip it with t.Setenv.
func insecureSstpHttpEnabled() bool {
	return strings.EqualFold(os.Getenv("I2SIG_INSECURE_SSTP_HTTP"), "true")
}

// validateSstpEndpointUrl performs the create-time syntactic validation of an
// SSTP EndpointUrl (PRD #154 Q28): require scheme=https (http only when
// I2SIG_INSECURE_SSTP_HTTP=true), reject query/fragment, require a non-empty
// host. No network probe is performed.
func validateSstpEndpointUrl(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid endpoint_url: %v", err)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !insecureSstpHttpEnabled() {
			return errors.New("invalid endpoint_url: http scheme requires I2SIG_INSECURE_SSTP_HTTP=true")
		}
	default:
		return fmt.Errorf("invalid endpoint_url: scheme must be https, got %q", u.Scheme)
	}
	if u.Host == "" {
		return errors.New("invalid endpoint_url: host must be non-empty")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return errors.New("invalid endpoint_url: query and fragment are not allowed")
	}
	return nil
}

// validateSstpDirection enforces the minimal structural validation on a single
// half of an SSTP pair (PRD #154 Q27, Q29): non-empty URI-shaped Iss and Aud,
// and a recognized mode. Events are accepted loosely (no registry check, empty
// allowed). No reciprocity is enforced against the other half.
func validateSstpDirection(name string, d model.SstpDirection) error {
	if err := requireUriShaped(name+".iss", d.Iss); err != nil {
		return err
	}
	if len(d.Aud) == 0 {
		return fmt.Errorf("invalid %s.aud: must be non-empty", name)
	}
	for _, a := range d.Aud {
		if err := requireUriShaped(name+".aud", a); err != nil {
			return err
		}
	}
	if _, ok := model.SstpModeToRouteMode(d.Mode); !ok {
		return fmt.Errorf("invalid %s.mode: must be one of FORWARD, PUBLISH, IMPORT", name)
	}
	return nil
}

// requireUriShaped rejects an empty or non-URI-shaped value. URI-shaped means a
// parseable absolute URI with a scheme — matching the SSF iss/aud convention.
func requireUriShaped(field, value string) error {
	if value == "" {
		return fmt.Errorf("invalid %s: must be non-empty", field)
	}
	u, err := url.Parse(value)
	if err != nil || u.Scheme == "" {
		return fmt.Errorf("invalid %s: must be URI-shaped, got %q", field, value)
	}
	return nil
}

// CreateSstpPair expands an SstpPairBootstrap into one node's half of a
// bidirectional SSTP StreamStateRecord and persists it (PRD #154 slice #161,
// ADR 0019). It is the discriminator branch of POST /stream for SSTP bodies.
//
// Role drives the order of operations and the credential/endpoint source:
//   - responder: server-derives EndpointUrl and server-mints the bearer; the
//     local row is written first, then the mirrored bootstrap is cascaded to the
//     peer. A peer-cascade failure rolls back the local row (ReceivePush-style).
//   - initiator: the operator supplies the bearer (the peer responder minted
//     it); no local row exists until the peer returns, so a peer-cascade failure
//     writes nothing (ReceivePoll-style).
//
// peerServer may be pre-resolved by the caller; otherwise it is resolved from
// bootstrap.PeerServerAlias via the ServerService. When no peer alias is given,
// only the local half is provisioned (Q31).
func (s *StreamService) CreateSstpPair(ctx context.Context, bootstrap model.SstpPairBootstrap, projectID string, peerServer *model.Server) (model.StreamStateRecord, error) {
	// Role is required at create with no default (Q30).
	switch bootstrap.Role {
	case model.SstpRoleInitiator, model.SstpRoleResponder:
	default:
		return model.StreamStateRecord{}, fmt.Errorf("invalid role: must be %q or %q", model.SstpRoleInitiator, model.SstpRoleResponder)
	}

	// Structural validation of both halves before any state is mutated (Q27, Q29).
	if err := validateSstpDirection("primary", bootstrap.Primary); err != nil {
		return model.StreamStateRecord{}, err
	}
	if err := validateSstpDirection("inbound", bootstrap.Inbound); err != nil {
		return model.StreamStateRecord{}, err
	}

	// Resolve the peer Server from the alias when the caller didn't pre-resolve.
	if peerServer == nil && bootstrap.PeerServerAlias != "" && s.serverService != nil {
		resolved, err := s.serverService.GetServerByAlias(ctx, bootstrap.PeerServerAlias)
		if err != nil {
			return model.StreamStateRecord{}, errors.New("unknown peer_server_alias provided")
		}
		peerServer = resolved
	}

	// Role-asymmetric credential/endpoint handling (Q30, Q33).
	endpointUrl := bootstrap.EndpointUrl
	authHeader := bootstrap.AuthorizationHeader

	mid := bson.NewObjectID()
	pairId := mid.Hex()
	// Generate the inbound (rx-side) SID up front so the responder can mint the
	// pair bearer covering BOTH real SIDs (finding #7). buildSstpRecord is told to
	// reuse this exact SID so the token binding and the persisted record agree.
	inboundSid := bson.NewObjectID().Hex()

	if bootstrap.Role == model.SstpRoleResponder {
		// Responder rejects an operator-supplied EndpointUrl and bearer; both are
		// server-derived/minted.
		if bootstrap.EndpointUrl != "" {
			return model.StreamStateRecord{}, errors.New("endpoint_url must not be supplied on a responder; it is server-derived")
		}
		if bootstrap.AuthorizationHeader != "" {
			return model.StreamStateRecord{}, errors.New("authorization_header must not be supplied on a responder; it is server-minted")
		}
		endpointUrl = s.getFullUrl(fmt.Sprintf("/sstp/%s", pairId))

		// Mint the per-pair bearer covering both SIDs: [txSid (== PairId), rxSid
		// (== inbound SID)]. Both must be real so per-direction status/verify naming
		// the inbound SID authorizes (finding #7).
		token, err := s.keyService.GetAuthIssuer().IssueSstpPairToken(pairId, inboundSid, projectID, false, sessionFromCtx(ctx))
		if err != nil {
			return model.StreamStateRecord{}, fmt.Errorf("failed to mint sstp pair token: %v", err)
		}
		authHeader = "Bearer " + token
	} else {
		// Initiator: the operator must supply the bearer (Q30); the peer responder
		// minted it.
		if bootstrap.AuthorizationHeader == "" {
			return model.StreamStateRecord{}, errors.New("authorization_header is required on an initiator")
		}
	}

	// EndpointUrl syntactic validation, when present (Q28). The responder always
	// has one (just derived); the initiator may not have learned it yet.
	if endpointUrl != "" {
		if err := validateSstpEndpointUrl(endpointUrl); err != nil {
			return model.StreamStateRecord{}, err
		}
	}

	rec := s.buildSstpRecord(mid, pairId, inboundSid, projectID, bootstrap, endpointUrl, authHeader)

	if bootstrap.Role == model.SstpRoleResponder {
		// ReceivePush-style: write local first, then cascade; roll back on failure.
		if err := s.streamDAO.Create(ctx, rec); err != nil {
			return model.StreamStateRecord{}, err
		}
		if peerServer != nil {
			if err := s.cascadeSstpPeer(ctx, rec, bootstrap, peerServer); err != nil {
				if delErr := s.DeleteStream(ctx, rec.StreamConfiguration.Id); delErr != nil {
					ssLog.Error("failed to roll back local sstp half after peer cascade failure", "pair_id", pairId, "error", delErr)
				}
				return model.StreamStateRecord{}, fmt.Errorf("sstp peer cascade failed: %v", err)
			}
			// Persist the peer's PairId learned during the cascade; the local row
			// was written before the cascade ran (ReceivePush-style ordering).
			if err := s.streamDAO.Update(ctx, rec); err != nil {
				return model.StreamStateRecord{}, fmt.Errorf("failed to persist peer_pair_id after cascade: %v", err)
			}
		}
		ssLog.Info("SSTP pair created", "pair_id", pairId, "role", bootstrap.Role)
		return *rec, nil
	}

	// Initiator, ReceivePoll-style: cascade first (no local row yet), then write
	// local using whatever the peer returned. No rollback because nothing local
	// exists until the peer succeeds.
	if peerServer != nil {
		if err := s.cascadeSstpPeer(ctx, rec, bootstrap, peerServer); err != nil {
			return model.StreamStateRecord{}, fmt.Errorf("sstp peer cascade failed: %v", err)
		}
	}
	if err := s.streamDAO.Create(ctx, rec); err != nil {
		return model.StreamStateRecord{}, err
	}
	ssLog.Info("SSTP pair created", "pair_id", pairId, "role", bootstrap.Role)
	return *rec, nil
}

// updateSstpPair applies the SSTP patchable-fields whitelist (PRD #154 Q35) to
// a bidirectional pair record. streamID selects the direction whose Iss/Aud the
// patch targets (txSid == PairId → primary; rxSid == SstpInbound.Id → inbound).
//
// Patchable: SstpMethod.AuthorizationHeader (rotate the static bearer), the
// targeted direction's Iss and Aud, and peer connectivity fields (EndpointUrl,
// PeerPairId) ONLY while they are still unset — a staged-rollout fill-in.
//
// Immutable (rejected with a 4xx-shaped error): SstpMethod.Role, an already-set
// EndpointUrl/PeerPairId, and all IDs. UPDATE never re-triggers the peer cascade
// — delete-and-recreate is the path for that (Q35a).
func (s *StreamService) updateSstpPair(ctx context.Context, streamRec *model.StreamStateRecord, streamID string, patch model.StreamStateRecord) (*model.StreamConfiguration, error) {
	if patch.SstpMethod != nil {
		if patch.SstpMethod.Role != "" && patch.SstpMethod.Role != streamRec.SstpMethod.Role {
			return nil, errors.New("invalid patch: sstp role is immutable")
		}
		if patch.SstpMethod.AuthorizationHeader != "" {
			streamRec.SstpMethod.AuthorizationHeader = patch.SstpMethod.AuthorizationHeader
		}
		// EndpointUrl and PeerPairId are fill-in-once: a patch may set them while
		// still unset (staged rollout, Q35a) but never repoint an already-set
		// value (immutable, Q35).
		if patch.SstpMethod.EndpointUrl != "" && patch.SstpMethod.EndpointUrl != streamRec.SstpMethod.EndpointUrl {
			if streamRec.SstpMethod.EndpointUrl != "" {
				return nil, errors.New("invalid patch: sstp endpoint_url is immutable once set")
			}
			if err := validateSstpEndpointUrl(patch.SstpMethod.EndpointUrl); err != nil {
				return nil, err
			}
			streamRec.SstpMethod.EndpointUrl = patch.SstpMethod.EndpointUrl
		}
		if patch.SstpMethod.PeerPairId != "" && patch.SstpMethod.PeerPairId != streamRec.SstpMethod.PeerPairId {
			if streamRec.SstpMethod.PeerPairId != "" {
				return nil, errors.New("invalid patch: sstp peer_pair_id is immutable once set")
			}
			streamRec.SstpMethod.PeerPairId = patch.SstpMethod.PeerPairId
		}
	}

	// Per-direction Iss/Aud patch (Q35): streamID names the targeted direction.
	// rxSid (== SstpInbound.Id) patches the inbound side; anything else (txSid ==
	// PairId) patches the primary (tx) side.
	target := &streamRec.StreamConfiguration
	if streamRec.SstpInbound != nil && streamID == streamRec.SstpInbound.Id {
		target = streamRec.SstpInbound
	}
	if patch.Iss != "" {
		target.Iss = patch.Iss
	}
	if len(patch.Aud) > 0 {
		target.Aud = patch.Aud
	}

	streamRec.ModifiedAt = time.Now()
	if err := s.streamDAO.Update(ctx, streamRec); err != nil {
		return nil, err
	}
	config := streamRec.StreamConfiguration
	return &config, nil
}

// SstpDeleteOutcome reports the per-side result of an SSTP pair delete (Q37,
// ADR 0020). Local cleanup always proceeds; peer cleanup is courtesy and opt-in.
// The HTTP handler maps it to 200 (local-only, or local + peer success) or 207
// Multi-Status (local success but peer cleanup failed).
type SstpDeleteOutcome struct {
	// LocalDeleted reports that the local pair row was removed.
	LocalDeleted bool `json:"local_deleted"`
	// PeerAttempted reports whether a courtesy peer-cleanup call was made
	// (cascade_peer=true with a resolvable peer Server).
	PeerAttempted bool `json:"peer_attempted"`
	// PeerDeleted reports that the peer accepted the courtesy cleanup.
	PeerDeleted bool `json:"peer_deleted,omitempty"`
	// PeerError carries the peer-cleanup failure reason when PeerAttempted is true
	// and PeerDeleted is false.
	PeerError string `json:"peer_error,omitempty"`
}

// PartialFailure reports whether the local delete succeeded but a requested peer
// cleanup did not — the 207 Multi-Status condition (Q37).
func (o SstpDeleteOutcome) PartialFailure() bool {
	return o.LocalDeleted && o.PeerAttempted && !o.PeerDeleted
}

// DeleteSstpPair removes an SSTP pair (PRD #154 Q37, ADR 0020). Local cleanup
// ALWAYS proceeds and never blocks on peer reachability. When cascadePeer is
// true and a peer Server is resolvable, a courtesy DELETE is sent to the peer's
// SSF stream-configuration endpoint for the peer's PairId; a peer failure does
// not fail the local delete — it is surfaced in the outcome so the handler can
// answer 207 Multi-Status.
func (s *StreamService) DeleteSstpPair(ctx context.Context, sid string, cascadePeer bool, peerServer *model.Server) (SstpDeleteOutcome, error) {
	rec := s.findSstpPairBySID(ctx, sid)
	if rec == nil {
		return SstpDeleteOutcome{}, errors.New("not found")
	}

	var outcome SstpDeleteOutcome
	if err := s.DeleteStream(ctx, rec.StreamConfiguration.Id); err != nil {
		return outcome, err
	}
	outcome.LocalDeleted = true

	if !cascadePeer || peerServer == nil {
		return outcome, nil
	}

	outcome.PeerAttempted = true
	if err := s.cascadeSstpPeerDelete(ctx, rec, peerServer); err != nil {
		outcome.PeerError = err.Error()
		ssLog.Warn("sstp peer cleanup failed after local delete", "pair_id", rec.PairId, "error", err)
		return outcome, nil
	}
	outcome.PeerDeleted = true
	return outcome, nil
}

// cascadeSstpPeerDelete sends a courtesy DELETE to the peer's SSF stream-
// configuration endpoint for the peer's PairId, using the stored Server
// credentials (Q37, Q44). It returns an error only on a failed/declined peer
// call; the caller has already completed the local delete.
func (s *StreamService) cascadeSstpPeerDelete(ctx context.Context, rec *model.StreamStateRecord, peerServer *model.Server) error {
	peerPairId := ""
	if rec.SstpMethod != nil {
		peerPairId = rec.SstpMethod.PeerPairId
	}
	if peerPairId == "" {
		return errors.New("peer_pair_id unknown; cannot target peer cleanup")
	}

	client, closeClient, err := oauthClient.GetClientForServer(ctx, peerServer)
	if err != nil {
		return fmt.Errorf("failed to get client for peer: %v", err)
	}
	defer closeClient()

	endpoint, err := sstpPeerStreamEndpoint(ctx, client, peerServer)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, endpoint+"?stream_id="+url.QueryEscape(peerPairId), nil)
	if err != nil {
		return err
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to submit peer delete: %v", err)
	}
	defer httpSupport.HandleRespClose(resp)

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusAccepted {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("peer rejected delete with status %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}

// findSstpPairBySID resolves sid to its SSTP pair record, whether sid names the
// tx side (== PairId == document _id) or the rx side (== SstpInbound.Id), or
// returns nil when sid is not an SSTP pair SID. (Q39, Q41)
func (s *StreamService) findSstpPairBySID(ctx context.Context, sid string) *model.StreamStateRecord {
	if rec, err := s.streamDAO.FindByID(ctx, sid); err == nil && rec.GetType() == model.DeliverySstpPair {
		return rec
	}
	if rec, err := s.streamDAO.FindByInboundSID(ctx, sid); err == nil {
		return rec
	}
	return nil
}

// updateSstpPairStatus applies a status change to an SSTP pair with per-direction
// routing (Q39, Q41): naming the tx-side SID writes Status/ErrorMsg; naming the
// rx-side SID writes InboundStatus/InboundErrorMsg. Disabled is a pair-level
// lifecycle event and ALWAYS couples both directions regardless of which SID is
// named (Q39); Paused and Enabled honor per-direction routing.
func (s *StreamService) updateSstpPairStatus(ctx context.Context, rec *model.StreamStateRecord, sid, status, errorMsg string) {
	isInbound := rec.SstpInbound != nil && sid == rec.SstpInbound.Id

	if status == model.StreamStateDisable {
		// Pair-level: couple both directions.
		rec.Status = status
		rec.ErrorMsg = errorMsg
		rec.InboundStatus = status
		rec.InboundErrorMsg = errorMsg
	} else if isInbound {
		rec.InboundStatus = status
		rec.InboundErrorMsg = errorMsg
	} else {
		rec.Status = status
		rec.ErrorMsg = errorMsg
	}

	if err := s.streamDAO.Update(ctx, rec); err != nil {
		ssLog.Error("Error updating sstp pair status", "sid", sid, "error", err)
	}
}

// buildSstpRecord assembles the bidirectional StreamStateRecord from a validated
// bootstrap. The tx (primary) side aliases its Id to the Mongo _id hex (== the
// PairId), preserving the existing aliasing invariant; the inbound side uses the
// caller-provided inboundSid so the SID the pair bearer authorizes and the SID
// persisted on SstpInbound are the same value (finding #7).
func (s *StreamService) buildSstpRecord(mid bson.ObjectID, pairId, inboundSid, projectID string, b model.SstpPairBootstrap, endpointUrl, authHeader string) *model.StreamStateRecord {
	now := time.Now()

	primaryMode, _ := model.SstpModeToRouteMode(b.Primary.Mode)
	inboundMode, _ := model.SstpModeToRouteMode(b.Inbound.Mode)

	supported := model.GetSupportedEvents()

	primary := model.StreamConfiguration{
		Id:              pairId,
		Iss:             b.Primary.Iss,
		Aud:             b.Primary.Aud,
		IssuerJWKSUrl:   b.Primary.IssJwksUrl,
		EventsSupported: supported,
		EventsRequested: b.Primary.Events,
		EventsDelivered: s.calculateDeliveredEvents(b.Primary.Events, supported),
		Description:     b.Description,
		Format:          CSubjectFmt,
		RouteMode:       primaryMode,
		Delivery: &model.OneOfStreamConfigurationDelivery{
			SstpTransmitMarker: &model.SstpTransmitMarker{Method: model.DeliverySstp},
		},
	}

	inbound := model.StreamConfiguration{
		Id:              inboundSid,
		Iss:             b.Inbound.Iss,
		Aud:             b.Inbound.Aud,
		IssuerJWKSUrl:   b.Inbound.IssJwksUrl,
		EventsSupported: supported,
		EventsRequested: b.Inbound.Events,
		EventsDelivered: s.calculateDeliveredEvents(b.Inbound.Events, supported),
		Description:     b.Description,
		Format:          CSubjectFmt,
		RouteMode:       inboundMode,
		Delivery: &model.OneOfStreamConfigurationDelivery{
			SstpReceiveMarker: &model.SstpReceiveMarker{Method: model.ReceiveSstp},
		},
	}

	return &model.StreamStateRecord{
		Id:                  mid,
		ProjectId:           projectID,
		StreamConfiguration: primary,
		SstpInbound:         &inbound,
		PairId:              pairId,
		SstpMethod: &model.SstpMethod{
			Role:                b.Role,
			EndpointUrl:         endpointUrl,
			AuthorizationHeader: authHeader,
			PeerPairId:          b.PeerPairId,
		},
		StartDate:     now,
		CreatedAt:     now,
		ModifiedAt:    now,
		Status:        model.StreamStateEnabled,
		InboundStatus: model.StreamStateEnabled,
	}
}

// cascadeSstpPeer POSTs the mirrored bootstrap to the peer's SSF stream
// configuration endpoint using the stored Server credentials (Q31, Q44). The
// mirror flips the role and swaps the two directions so that the peer's primary
// (tx) is this node's inbound (rx) and vice-versa. On success the peer's PairId
// is recorded on the local record's SstpMethod.PeerPairId.
func (s *StreamService) cascadeSstpPeer(ctx context.Context, rec *model.StreamStateRecord, b model.SstpPairBootstrap, peerServer *model.Server) error {
	mirror := mirrorSstpBootstrap(rec, b)

	client, closeClient, err := oauthClient.GetClientForServer(ctx, peerServer)
	if err != nil {
		return fmt.Errorf("failed to get client for peer: %v", err)
	}
	defer closeClient()

	endpoint, err := sstpPeerStreamEndpoint(ctx, client, peerServer)
	if err != nil {
		return err
	}

	body, err := json.Marshal(mirror)
	if err != nil {
		return fmt.Errorf("failed to marshal mirrored bootstrap: %v", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to submit mirrored bootstrap to peer: %v", err)
	}
	defer httpSupport.HandleRespClose(resp)

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("peer rejected mirrored bootstrap with status %d: %s", resp.StatusCode, string(respBody))
	}

	var peerRec model.StreamStateRecord
	if err := json.NewDecoder(resp.Body).Decode(&peerRec); err != nil {
		return fmt.Errorf("failed to decode peer bootstrap response: %v", err)
	}

	// Learn the peer's PairId and, on an initiator, the endpoint/bearer the peer
	// responder produced.
	rec.SstpMethod.PeerPairId = peerRec.PairId
	if b.Role == model.SstpRoleInitiator && peerRec.SstpMethod != nil {
		if rec.SstpMethod.EndpointUrl == "" {
			rec.SstpMethod.EndpointUrl = peerRec.SstpMethod.EndpointUrl
		}
	}
	return nil
}

// mirrorSstpBootstrap builds the bootstrap the peer should receive: the opposite
// role and the two directions swapped, so the peer's outbound is this node's
// inbound. The peer's responder will derive its own EndpointUrl and mint its own
// bearer; an initiator-bound mirror carries this responder's endpoint+bearer.
func mirrorSstpBootstrap(rec *model.StreamStateRecord, b model.SstpPairBootstrap) model.SstpPairBootstrap {
	mirror := model.SstpPairBootstrap{
		Description: b.Description,
		PeerPairId:  rec.PairId,
		// Swap directions: peer's primary (tx) == our inbound (rx).
		Primary: b.Inbound,
		Inbound: b.Primary,
	}
	if b.Role == model.SstpRoleResponder {
		// This node is the responder/HTTP server; the peer is the initiator/client.
		// Hand the peer the endpoint and bearer it must use to reach us.
		mirror.Role = model.SstpRoleInitiator
		mirror.EndpointUrl = rec.SstpMethod.EndpointUrl
		mirror.AuthorizationHeader = rec.SstpMethod.AuthorizationHeader
	} else {
		// This node is the initiator/client; the peer is the responder/server and
		// will derive its own endpoint and mint its own bearer.
		mirror.Role = model.SstpRoleResponder
	}
	return mirror
}

// sstpPeerStreamEndpoint resolves the peer's SSF stream-configuration endpoint
// (the URL the mirrored bootstrap is POSTed to). It fetches the peer's
// well-known SSF configuration via the already-credentialed client and returns
// its configuration_endpoint.
func sstpPeerStreamEndpoint(ctx context.Context, client *http.Client, peerServer *model.Server) (string, error) {
	txConfig, err := wellKnownSupport.FetchSSFConfiguration(ctx, client, peerServer.Host)
	if err != nil {
		return "", fmt.Errorf("failed to fetch peer ssf configuration: %v", err)
	}
	if txConfig.ConfigurationEndpoint == "" {
		return "", errors.New("peer ssf configuration missing configuration_endpoint")
	}
	return txConfig.ConfigurationEndpoint, nil
}

// sessionFromCtx extracts the issuing AuthContext from the request context so a
// minted pair token records its lineage parent, mirroring CreateStream. Returns
// nil when no auth context is present (e.g. unit tests).
func sessionFromCtx(ctx context.Context) *authUtil.AuthContext {
	v := ctx.Value("authCtx")
	if v == nil {
		return nil
	}
	if authCtx, ok := v.(*authUtil.AuthContext); ok {
		return authCtx
	}
	return nil
}
