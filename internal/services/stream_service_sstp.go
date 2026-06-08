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

		// Mint the per-pair bearer covering both SIDs.
		token, err := s.keyService.GetAuthIssuer().IssueSstpPairToken(pairId, "", projectID, false, sessionFromCtx(ctx))
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

	rec := s.buildSstpRecord(mid, pairId, projectID, bootstrap, endpointUrl, authHeader)

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

// buildSstpRecord assembles the bidirectional StreamStateRecord from a validated
// bootstrap. The tx (primary) side aliases its Id to the Mongo _id hex (== the
// PairId), preserving the existing aliasing invariant; the inbound side gets its
// own fresh SID.
func (s *StreamService) buildSstpRecord(mid bson.ObjectID, pairId, projectID string, b model.SstpPairBootstrap, endpointUrl, authHeader string) *model.StreamStateRecord {
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
		Id:              bson.NewObjectID().Hex(),
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
