package server

/*
api_stream_management.go implements the SSF API requirements to register and stream and allow updates to them.
These functions require an authorization token that includes a project id and stream id value. Because of this
simplification, there is no way for a client to ask for a specific stream or all streams unless they have a token.

Because of this, administrative access is via admin.go
*/
import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/i2-open/i2goSignals/internal/authUtil"
	"github.com/i2-open/i2goSignals/internal/providers/dbProviders/mongo_provider"
	"github.com/i2-open/i2goSignals/internal/services"
	"github.com/i2-open/i2goSignals/pkg/authSupport"
	"github.com/i2-open/i2goSignals/pkg/constants"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/i2-open/i2goSignals/pkg/subjectid"

	"github.com/gorilla/mux"
)

// subjectRequest is the SSF §8.1.3.2/§8.1.3.3 Add/Remove Subject request body.
// stream_id is accepted for spec conformance but the handler always operates on
// the caller's authenticated stream. verified is meaningful for Add only.
type subjectRequest struct {
	StreamId string                   `json:"stream_id"`
	Subject  *goSet.SubjectIdentifier `json:"subject"`
	Verified bool                     `json:"verified,omitempty"`
}

// AddSubject opts a subject into delivery on the caller's stream (SSF §8.1.3.2).
//
// Inputs:
//   - Authorization (header): token with the same scope set as GetStatus.
//   - Body: { stream_id, subject, verified? }
//
// Return values:
//   - 200 OK: subject added.
//
// Errors:
//   - 400 Bad Request: missing or uncanonicalizable subject.
//   - 401/403: unauthorized, or the body names a different stream.
//   - 404 Not Found: subject filtering disabled, or stream not found.
func (sa *SignalsApplication) AddSubject(w http.ResponseWriter, r *http.Request) {
	AddSubjectHandler(sa, w, r)
}

func AddSubjectHandler(sa SsfApplicationInterface, w http.ResponseWriter, r *http.Request) {
	handleSubjectChange(sa, w, r, true)
}

// handleSubjectChange implements the shared Add/Remove Subject flow. add selects
// the SSF semantics and the success status (Add -> 200, Remove -> 204).
func handleSubjectChange(sa SsfApplicationInterface, w http.ResponseWriter, r *http.Request, add bool) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	if !services.SubjectFilteringEnabled() {
		// Subject filtering is disabled server-wide: the endpoint is not
		// advertised in discovery, so it must not be reachable either.
		w.WriteHeader(http.StatusNotFound)
		return
	}

	// Subject management is authorized with the same scope set as GetStatus.
	authCtx, status := sa.GetAuth().ValidateAuthorizationAny(r, []string{authSupport.ScopeStreamMgmt, authSupport.ScopeEventDelivery, authSupport.ScopeStreamAdmin, authSupport.ScopeRoot})
	if status != http.StatusOK {
		w.WriteHeader(status)
		return
	}

	var req subjectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Subject == nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if req.StreamId == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	// When the token is bound to a specific stream it must match the request;
	// the handler always operates on that stream (same rule as VerificationRequest).
	if authCtx.StreamId != "" && authCtx.StreamId != req.StreamId {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if _, err := subjectid.CanonicalKey(req.Subject); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	stream, err := sa.GetStreamService().GetStreamState(r.Context(), req.StreamId)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	// PRD #89 #95: in PASSTHRU mode the subject change is relayed 1:1 to the
	// upstream transmitter and no local filter is applied — downstream streams
	// share one upstream subscription. PRD #97 #103: a 404 or other error from
	// the upstream — possibly its own SSF §9.1 subject-probing mitigation — is
	// logged at WARN and tolerated; surfacing it would let an upstream's §9.1
	// posture break the downstream receiver's request.
	if stream.SubjectFilterMode == model.SubjectFilterModePassthru {
		relaySvc := sa.GetSubjectRelayService()
		if relaySvc == nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if relayErr := relaySvc.Relay(r.Context(), stream, req.Subject, req.Verified, add); relayErr != nil {
			serverLog.Warn("PASSTHRU subject relay to upstream failed", "sid", req.StreamId, "error", relayErr)
		}
		if add {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusNoContent)
		}
		return
	}

	filterSvc := sa.GetSubjectFilterService()
	if filterSvc == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	var decision services.RelayDecision
	if add {
		decision, err = filterSvc.AddSubject(r.Context(), stream, req.Subject, req.Verified)
	} else {
		decision, err = filterSvc.RemoveSubject(r.Context(), stream, req.Subject)
	}
	if err != nil {
		serverLog.Error("Subject filter change failed", "sid", req.StreamId, "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// The request may have landed on any cluster node; notify the stream's
	// PUSH lease owner to invalidate its match-result cache so the change
	// takes effect at delivery time (issue #94).
	if router := sa.GetEventRouter(); router != nil {
		router.NotifySubjectFilterChange(req.StreamId)
	}

	// PRD #89 #96 / PRD #97 #100: HYBRID also relays the change upstream, but
	// only as the *enforced* interested-set crosses the 0↔1 boundary. With
	// SSF §9.3 grace the service returns RelayDecisionDeferred for a Remove
	// that stamps a pending entry — the upstream relay is held back and the
	// push-transmitter lease owner's sweep fires it at enforceAt — and
	// RelayDecisionNone for a revive (upstream still subscribed). The local
	// filter above is the primary outcome; an upstream relay failure is
	// logged and tolerated, not surfaced to the caller.
	if stream.SubjectFilterMode == model.SubjectFilterModeHybrid && decision == services.RelayDecisionImmediate {
		if relaySvc := sa.GetSubjectRelayService(); relaySvc != nil {
			if relayErr := relaySvc.RelayHybrid(r.Context(), stream, req.Subject, req.Verified, add); relayErr != nil {
				serverLog.Warn("HYBRID subject relay to upstream failed", "sid", req.StreamId, "error", relayErr)
			}
		}
	}

	if add {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusNoContent)
	}
}

// GetStatus retrieves the status of a stream.
//
// Inputs:
//   - Authorization (header): Token with 'stream_mgmt' or 'stream_admin' scope.
//   - stream_id (query): The unique identifier of the stream.
//
// Return values:
//   - 200 OK: JSON object with the stream status.
//
// Errors:
//   - 400 Bad Request: Missing or invalid stream ID.
//   - 401/403: Unauthorized access.
//   - 404 Not Found: Stream not found.
//   - 500 Internal Server Error: Database or serialization error.
func (sa *SignalsApplication) GetStatus(w http.ResponseWriter, r *http.Request) {
	GetStatusHandler(sa, w, r)
}

func GetStatusHandler(sa SsfApplicationInterface, w http.ResponseWriter, r *http.Request) {
	authCtx, status := sa.GetAuth().ValidateAuthorizationAny(r, []string{authSupport.ScopeStreamMgmt, authSupport.ScopeEventDelivery, authSupport.ScopeStreamAdmin, authSupport.ScopeRoot})
	if status != http.StatusOK {
		serverLog.Debug("GetStatus request received: error", "authCtx", "invalid", "status", status)
		w.WriteHeader(status)
		return
	}

	sid := authCtx.StreamId
	if sid == "" {
		// The authorization token had no stream identifier in it
		serverLog.Debug("GetStatus request received: invalid sid", "status", status)
		w.WriteHeader(http.StatusForbidden)
		return
	}

	streamStatus, err := sa.GetStreamService().GetStatus(r.Context(), sid)
	if err != nil {
		serverLog.Debug("GetStatus request received: not found", "sid", authCtx.StreamId)
		w.WriteHeader(http.StatusNotFound)
		return
	}

	serverLog.Debug("GetStatus result", "sid", sid, "status", streamStatus.Status, "reason", streamStatus.Reason)
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")

	resp, err := json.Marshal(*streamStatus)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(err.Error()))
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(resp)
}

// RemoveSubject opts a subject out of delivery on the caller's stream
// (SSF §8.1.3.3).
//
// Inputs:
//   - Authorization (header): token with the same scope set as GetStatus.
//   - Body: { stream_id, subject }
//
// Return values:
//   - 204 No Content: subject removed.
//
// Errors:
//   - 400 Bad Request: missing or uncanonicalizable subject.
//   - 401/403: unauthorized, or the body names a different stream.
//   - 404 Not Found: subject filtering disabled, or stream not found.
func (sa *SignalsApplication) RemoveSubject(w http.ResponseWriter, r *http.Request) {
	RemoveSubjectHandler(sa, w, r)
}

func RemoveSubjectHandler(sa SsfApplicationInterface, w http.ResponseWriter, r *http.Request) {
	handleSubjectChange(sa, w, r, false)
}

// StreamDelete deletes an existing event stream.
//
// Inputs:
//   - Authorization (header): Token with 'stream_mgmt' or 'stream_admin' scope.
//   - stream_id (query): The unique identifier of the stream to be deleted.
//
// Return values:
//   - 204 No Content: Stream successfully deleted.
//
// Errors:
//   - 400 Bad Request: Missing or invalid stream ID.
//   - 401/403: Unauthorized access.
//   - 404 Not Found: Stream not found.
//   - 500 Internal Server Error: Error during deletion or database access.
func (sa *SignalsApplication) StreamDelete(w http.ResponseWriter, r *http.Request) {
	StreamDeleteHandler(sa, w, r)
}

func StreamDeleteHandler(sa SsfApplicationInterface, w http.ResponseWriter, r *http.Request) {
	authContext, status := sa.GetAuth().ValidateAuthorizationAny(r, []string{authSupport.ScopeStreamMgmt, authSupport.ScopeStreamAdmin})

	if status != http.StatusOK {
		w.WriteHeader(status)
		return
	}

	if authContext.StreamId == "" {
		// The authorization token had no stream identifier in it
		w.WriteHeader(http.StatusForbidden)
		return
	}
	serverLog.Warn(fmt.Sprintf("Stream %s DELETE requested.", authContext.StreamId))

	state, err := sa.GetStreamService().GetStreamState(r.Context(), authContext.StreamId)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	state.Status = model.StreamStateDisable
	sa.GetEventRouter().UpdateStreamState(state)

	// Stop all the inbound traffic if Polling
	sa.CloseReceiver(authContext.StreamId)

	// Stop any outbound activity
	sa.GetEventRouter().RemoveStream(authContext.StreamId)

	err = sa.GetStreamService().DeleteStream(r.Context(), authContext.StreamId)
	if err != nil {
		if err.Error() == "not found" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(err.Error()))
		return
	}
	// sa.EventRouter.RemoveStream(authContext)
	w.WriteHeader(http.StatusOK)
	serverLog.Info(fmt.Sprintf("Stream %s inactivated and deleted.", authContext.StreamId))
}

func replaceBase(original string, baseUrl *url.URL) string {
	originalUrl, err := url.Parse(original)
	if err != nil {
		return original // if this is not parseable, do nothing
	}

	if baseUrl == nil {
		log.Println("Warning: Detected base url is nil")
		return original
	}

	modifiedUrl := *originalUrl
	modifiedUrl.Scheme = baseUrl.Scheme
	modifiedUrl.Host = baseUrl.Host
	return modifiedUrl.String()
}

func (sa *SignalsApplication) adjustStateBaseUrl(config model.StreamStateRecord) model.StreamStateRecord {
	return adjustStateBaseUrl(sa, config)
}

func adjustStateBaseUrl(sa SsfApplicationInterface, config model.StreamStateRecord) model.StreamStateRecord {
	streamConfig := config.StreamConfiguration
	config.StreamConfiguration = adjustBaseUrl(sa, streamConfig)
	return config
}

func (sa *SignalsApplication) adjustBaseUrl(config model.StreamConfiguration) model.StreamConfiguration {
	return adjustBaseUrl(sa, config)
}

func adjustBaseUrl(sa SsfApplicationInterface, config model.StreamConfiguration) model.StreamConfiguration {
	res := config.DeepCopy()
	baseUrl := sa.GetBaseUrl()
	if res.Delivery == nil {
		return res
	}
	switch res.Delivery.GetMethod() {
	case model.DeliveryPoll:
		if res.Delivery.PollTransmitMethod != nil {
			endpoint := res.Delivery.PollTransmitMethod.EndpointUrl
			res.Delivery.PollTransmitMethod.EndpointUrl = replaceBase(endpoint, baseUrl)
		}
	case model.ReceivePush:
		if res.Delivery.PushReceiveMethod != nil {
			endpoint := res.Delivery.PushReceiveMethod.EndpointUrl
			res.Delivery.PushReceiveMethod.EndpointUrl = replaceBase(endpoint, baseUrl)
		}
	default:
		// do nothing
	}
	return res
}

// StreamGet retrieves the configuration of a stream.
//
// Inputs:
//   - Authorization (header): Token with 'stream_mgmt' or 'stream_admin' scope.
//   - stream_id (query): The unique identifier of the stream.
//
// Return values:
//   - 200 OK: JSON object of the StreamConfiguration.
//
// Errors:
//   - 400 Bad Request: Missing or invalid stream ID.
//   - 401/403: Unauthorized access.
//   - 404 Not Found: Stream not found.
//   - 500 Internal Server Error: Serialization error.
func (sa *SignalsApplication) StreamGet(w http.ResponseWriter, r *http.Request) {
	StreamGetHandler(sa, w, r)
}

func StreamGetHandler(sa SsfApplicationInterface, w http.ResponseWriter, r *http.Request) {
	authCtx, status := sa.GetAuth().ValidateAuthorizationAny(r, []string{authSupport.ScopeStreamMgmt, authSupport.ScopeStreamAdmin})

	if status != http.StatusOK {
		w.WriteHeader(status)
		return
	}
	if authCtx.StreamId == "" {
		// The authorization token had no stream identifier in it
		w.WriteHeader(http.StatusForbidden)
		return
	}

	config, err := sa.GetStreamService().GetStream(r.Context(), authCtx.StreamId)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	serverLog.Debug(fmt.Sprintf("Stream Config Get Request %s", authCtx.StreamId))
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")

	resp, err := json.Marshal(adjustBaseUrl(sa, *config))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(err.Error()))
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(resp)
}

// StreamCreate creates a new event stream configuration.
//
// Inputs:
//   - Authorization (header): Token with 'stream_mgmt' or 'stream_admin' scope.
//   - Request body (JSON): StreamConfiguration details.
//
// Return values:
//   - 201 Created: JSON object of the created StreamConfiguration.
//
// Errors:
//   - 400 Bad Request: Error decoding request body or invalid configuration.
//   - 401/403: Unauthorized access.
//   - 500 Internal Server Error: Error creating stream.
func (sa *SignalsApplication) StreamCreate(w http.ResponseWriter, r *http.Request) {
	StreamCreateHandler(sa, w, r)
}

// canProvisionTxAlias reports whether the caller may create a stream against a
// FOREIGN transmitter (tx_alias set). Foreign-server provisioning resolves a
// stored credential and drives the remote stream's whole lifecycle, so the caller
// must hold either admin (root rides free) or the full operational scope set —
// register (create) + stream (manage/status) + event (poll) together. Register
// alone is deliberately not enough. It routes through HasScope (never a bare
// authCtx.Eat check) so an OAuth/STS caller — whose Eat is nil and whose grants
// live in GrantedScopes — is evaluated correctly rather than always denied (#128).
func canProvisionTxAlias(authCtx *authUtil.AuthContext) bool {
	if authCtx.HasScope(authSupport.ScopeStreamAdmin) {
		return true
	}
	return authCtx.HasScope(authSupport.ScopeRegister) &&
		authCtx.HasScope(authSupport.ScopeStreamMgmt) &&
		authCtx.HasScope(authSupport.ScopeEventDelivery)
}

func StreamCreateHandler(sa SsfApplicationInterface, w http.ResponseWriter, r *http.Request) {
	// Creating a stream is a stream-management operation: a self-registered
	// receiver (capped at stream_mgmt by the /register privilege ceiling, never
	// stream_admin) must be able to create its own stream. This mirrors the
	// sibling stream operations (get/update/delete) which already accept
	// stream_mgmt; stream_admin remains required only for elevated key/stream
	// lifecycle actions. reg is retained for the legacy direct-IAT path.
	authCtx, status := sa.GetAuth().ValidateAuthorizationAny(r, []string{authSupport.ScopeRegister, authSupport.ScopeStreamMgmt, authSupport.ScopeStreamAdmin})
	if status != http.StatusOK {
		w.WriteHeader(status)
		return
	}
	// Decode into a StreamStateRecord (not a bare StreamConfiguration) so the
	// goSignals-specific subject-filtering operator knobs ride alongside the
	// SSF wire-format fields. The embedded StreamConfiguration is flattened by
	// encoding/json, so existing request bodies decode unchanged.
	var jsonRequest model.StreamStateRecord
	err := json.NewDecoder(r.Body).Decode(&jsonRequest)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Provisioning a stream against a FOREIGN transmitter (tx_alias set) is a
	// privileged operation: it resolves a stored foreign-server credential and
	// remotely manages a stream on another node's behalf. The caller must be able
	// to operate the whole foreign stream lifecycle, so the base stream/reg gate
	// above is not enough — it needs canProvisionTxAlias (admin, or the full
	// reg+stream+event set). A plain create (no tx_alias) — the SCIM-receiver /
	// unattended-IAT-bootstrap path — is unaffected. See ADR 0009.
	if jsonRequest.TxAlias != nil && *jsonRequest.TxAlias != "" && !canProvisionTxAlias(authCtx) {
		serverLog.Warn("StreamCreate: denied tx_alias provisioning; needs admin or reg+stream+event", "tx_alias", *jsonRequest.TxAlias, "projectId", authCtx.ProjectId)
		http.Error(w, "creating a stream with tx_alias (foreign-server provisioning) requires admin scope, or the full reg+stream+event scope set", http.StatusForbidden)
		return
	}

	jsonRequest.ResetDate = nil
	jsonRequest.ResetJti = ""

	configResp, err := sa.GetStreamService().CreateStream(context.WithValue(r.Context(), authUtil.AuthContextKey, authCtx), jsonRequest, authCtx.ProjectId, nil)
	if err != nil {
		if err.Error() == "not found" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(err.Error()))
		return
	}

	// Update the event router
	state, err := sa.GetStreamService().GetStreamState(r.Context(), configResp.Id)
	if err != nil {
		serverLog.Error("Error getting stream state after creation", "id", configResp.Id, "error", err)
	}
	sa.GetEventRouter().UpdateStreamState(state)
	sa.HandleReceiver(state)

	serverLog.Info(fmt.Sprintf("Stream %s CREATED", configResp.Id))

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	respBytes, err := json.MarshalIndent(adjustBaseUrl(sa, configResp), "", "  ")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(err.Error()))
		return
	}
	w.WriteHeader(http.StatusCreated)
	_, _ = w.Write(respBytes)

}

// StreamUpdate updates (replaces or patches) an existing stream configuration.
//
// Inputs:
//   - Authorization (header): Token with 'stream_mgmt' or 'stream_admin' scope.
//   - stream_id (query): The unique identifier of the stream.
//   - Request body (JSON): Updated StreamConfiguration details.
//
// Return values:
//   - 200 OK: JSON object of the updated StreamConfiguration.
//
// Errors:
//   - 400 Bad Request: Missing stream ID or error decoding request body.
//   - 401/403: Unauthorized access.
//   - 404 Not Found: Stream not found.
//   - 500 Internal Server Error: Database update failure.
func (sa *SignalsApplication) StreamUpdate(w http.ResponseWriter, r *http.Request) {
	StreamUpdateHandler(sa, w, r)
}

func StreamUpdateHandler(sa SsfApplicationInterface, w http.ResponseWriter, r *http.Request) {
	authCtx, status := sa.GetAuth().ValidateAuthorizationAny(r, []string{authSupport.ScopeStreamMgmt, authSupport.ScopeStreamAdmin})

	if status != http.StatusOK {
		w.WriteHeader(status)
		return
	}

	// Decode into a StreamStateRecord so subject-filtering operator knobs can
	// be patched alongside the SSF wire-format fields (see StreamCreateHandler).
	var jsonRequest model.StreamStateRecord
	err := json.NewDecoder(r.Body).Decode(&jsonRequest)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Because the PUT/PATCH request does not have a stream id parameter, we extract from payload and re-check.
	// Use IsAuthorizedForStream (not a bare Eat check) so local tokens keep their stream-id binding while
	// OAuth/STS callers — who carry no per-stream binding — are still validated against the granted scope set.
	if !authCtx.IsAuthorizedForStream(jsonRequest.StreamConfiguration.Id, authSupport.ScopeStreamMgmt, authSupport.ScopeStreamAdmin) {
		http.Error(w, "Stream identifier not authorized", http.StatusForbidden)
		return
	}
	resetJti := jsonRequest.ResetJti
	resetDate := jsonRequest.ResetDate

	jsonRequest.ResetDate = nil
	jsonRequest.ResetJti = ""

	configResp, err := sa.GetStreamService().UpdateStream(r.Context(), authCtx.StreamId, authCtx.ProjectId, jsonRequest)
	if err != nil || configResp == nil {
		if err != nil && err.Error() == mongo_provider.ErrorInvalidProject {
			http.Error(w, "Streamid invalid for authorization", http.StatusUnauthorized)
			return
		}
		if err != nil && err.Error() == "not found" || configResp == nil {
			http.Error(w, "No stream found", http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(err.Error()))
		return
	}

	streamState, err := sa.GetStreamService().GetStreamState(r.Context(), authCtx.StreamId)
	if err != nil {
		serverLog.Error("Error getting stream state after update", "id", authCtx.StreamId, "error", err)
	}
	if resetDate != nil || resetJti != "" {
		// reset the stream to a particular date
		err := sa.GetEventService().ResetEventStream(r.Context(), authCtx.StreamId, resetJti, resetDate, func(eventRecord *model.AgEventRecord) bool {
			// Operational events (verify, stream-updated) are point-to-point and excluded from replay.
			if eventRecord.Operational {
				return false
			}
			// Because reset goes through all events, this function confirms the stream should get the event
			return sa.GetEventService().MatchesStream(streamState, eventRecord)
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}

	if jsonRequest.ResetJti != "" {
		// reset the stream to a particular jti (assuming sortable)
	}

	// Update the event router
	state, err := sa.GetStreamService().GetStreamState(r.Context(), authCtx.StreamId)
	if err != nil {
		serverLog.Error("Error getting stream state for event router update", "id", authCtx.StreamId, "error", err)
	}
	if resetDate != nil || resetJti != "" {
		sa.GetEventRouter().RemoveStream(authCtx.StreamId)
	}
	sa.GetEventRouter().UpdateStreamState(state)
	sa.HandleReceiver(state)

	serverLog.Info(fmt.Sprintf("Stream %s UPDATED", authCtx.StreamId))

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	respBytes, err := json.MarshalIndent(adjustBaseUrl(sa, *configResp), "", "  ")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(err.Error()))
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(respBytes)
}

// UpdateStatus updates the status (e.g., enabled, disabled, paused) of a stream.
//
// Inputs:
//   - Authorization (header): Token with 'stream_mgmt' or 'stream_admin' scope.
//   - stream_id (query): The unique identifier of the stream.
//   - Request body (JSON): Object with the new status and optional reason.
//
// Return values:
//   - 200 OK: JSON object containing the updated status.
//
// Errors:
//   - 400 Bad Request: Missing stream ID or error decoding request body.
//   - 401/403: Unauthorized access.
//   - 404 Not Found: Stream not found.
//   - 500 Internal Server Error: Database or internal update failure.
func (sa *SignalsApplication) UpdateStatus(w http.ResponseWriter, r *http.Request) {
	UpdateStatusHandler(sa, w, r)
}

func UpdateStatusHandler(sa SsfApplicationInterface, w http.ResponseWriter, r *http.Request) {
	authCtx, status := sa.GetAuth().ValidateAuthorizationAny(r, []string{authSupport.ScopeStreamMgmt, authSupport.ScopeStreamAdmin})

	if status != http.StatusOK {
		w.WriteHeader(status)
		return
	}
	if authCtx.StreamId == "" {
		// The authorization token had no stream identifier in it
		w.WriteHeader(http.StatusForbidden)
		return
	}

	var jsonRequest model.UpdateStreamStatus
	err := json.NewDecoder(r.Body).Decode(&jsonRequest)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	modified := false
	streamState, err := sa.GetStreamService().GetStreamState(r.Context(), authCtx.StreamId)
	if err != nil {
		if err.Error() == "not found" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		serverLog.Error("Error getting stream state after update", "id", authCtx.StreamId, "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if streamState == nil {
		// should not happen!
		serverLog.Error("Error: Get Stream state returned nil after update", "id", authCtx.StreamId)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if jsonRequest.Status != "" {
		if streamState.Status != jsonRequest.Status || !strings.EqualFold(jsonRequest.Reason, streamState.ErrorMsg) {
			if jsonRequest.Status == model.StreamStatePause || jsonRequest.Status == model.StreamStateDisable || jsonRequest.Status == model.StreamStateEnabled {
				sa.GetStreamService().UpdateStreamStatus(r.Context(), authCtx.StreamId, jsonRequest.Status, jsonRequest.Reason)
				modified = true
				// Refresh streamState after update
				updatedState, err := sa.GetStreamService().GetStreamState(r.Context(), authCtx.StreamId)
				if err == nil && updatedState != nil {
					streamState = updatedState
				}
			}

		}
	}

	if modified {
		sa.GetEventRouter().UpdateStreamState(streamState)
		sa.HandleReceiver(streamState)
	}

	statusResp, err := sa.GetStreamService().GetStatus(r.Context(), authCtx.StreamId)
	if err != nil {
		serverLog.Error("Error getting status after update", "id", authCtx.StreamId, "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(err.Error()))
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	respBytes, err := json.MarshalIndent(statusResp, "", "  ")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(err.Error()))
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(respBytes)
}

func (sa *SignalsApplication) getTransmitterConfig() *model.TransmitterConfiguration {
	return getTransmitterConfig(sa)
}

func getTransmitterConfig(sa SsfApplicationInterface) *model.TransmitterConfiguration {
	baseUrl := sa.GetBaseUrl()
	jwksUri, _ := baseUrl.Parse("/jwks.json")
	configUri, _ := baseUrl.Parse("/stream")
	statusUri, _ := baseUrl.Parse("/status")
	verifyUri, _ := baseUrl.Parse("/verify")
	regUri, _ := baseUrl.Parse("/register")

	var methods []string
	var goVersion string
	switch sa.(type) {
	case *SignalsApplication:
		goVersion = constants.GoSignalsVersion
		methods = []string{
			model.DeliveryPoll,
			model.DeliveryPush,
			model.ReceivePoll,
			model.ReceivePush,
		}
	default:
		goVersion = "" // Simulate an SSF server
		methods = []string{
			model.DeliveryPoll,
			model.DeliveryPush,
		}
	}

	supportedScopes := map[string][]string{
		"configuration_endpoint":       {authSupport.ScopeStreamAdmin, authSupport.ScopeStreamMgmt},
		"status_endpoint":              {authSupport.ScopeStreamMgmt},
		"events":                       {authSupport.ScopeEventDelivery},
		"verification_endpoint":        {authSupport.ScopeEventDelivery, authSupport.ScopeStreamMgmt},
		"poll":                         {authSupport.ScopeEventDelivery},
		"client_registration_endpoint": {authSupport.ScopeRegister},
	}

	config := &model.TransmitterConfiguration{
		Issuer:                     sa.GetDefIssuer(),
		JwksUri:                    jwksUri.String(),
		DeliveryMethodsSupported:   methods,
		ConfigurationEndpoint:      configUri.String(),
		StatusEndpoint:             statusUri.String(),
		VerificationEndpoint:       verifyUri.String(),
		CriticalSubjectMembers:     nil,
		ClientRegistrationEndpoint: regUri.String(),
		SupportedScopes:            supportedScopes,
		AuthorizationSchemes: []model.AuthScheme{
			{SpecUrn: constants.BearerAuth},
			{SpecUrn: constants.RFC6749},
		},
		AuthorizationServers:   sa.GetAuth().GetOAuthServers(),
		ScopesSupported:        []string{authSupport.ScopeEventDelivery, authSupport.ScopeStreamAdmin, authSupport.ScopeStreamMgmt, authSupport.ScopeRegister},
		BearerMethodsSupported: []string{"header"},

		GoSignalsVersion: goVersion,
		SpecVersion:      constants.SSF_VERSION,
	}

	// SSF subject filtering (§8.1.3): advertise the Add/Remove Subject
	// endpoints only when the feature is enabled server-wide, so discovery
	// never advertises a capability the server will not honor.
	if services.SubjectFilteringEnabled() {
		addSubUri, _ := baseUrl.Parse("/add-subject")
		remSubUri, _ := baseUrl.Parse("/remove-subject")
		config.AddSubjectEndpoint = addSubUri.String()
		config.RemoveSubjectEndpoint = remSubUri.String()
		supportedScopes["add_subject_endpoint"] = []string{authSupport.ScopeStreamMgmt}
		supportedScopes["remove_subject_endpoint"] = []string{authSupport.ScopeStreamMgmt}
	}

	return config
}

// WellKnownSsfConfigurationGet returns the default SSF transmitter configuration.
//
// Return values:
//   - 200 OK: JSON object of the TransmitterConfiguration.
func (sa *SignalsApplication) WellKnownSsfConfigurationGet(w http.ResponseWriter, r *http.Request) {
	WellKnownSsfConfigurationGetHandler(sa, w, r)
}

func WellKnownSsfConfigurationGetHandler(sa SsfApplicationInterface, w http.ResponseWriter, _ *http.Request) {
	serverLog.Debug("GET WellKnownSsfConfiguration")
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")

	resp, _ := json.Marshal(getTransmitterConfig(sa))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(resp)

}

// WellKnownSsfConfigurationIssuerGet returns the SSF configuration for a specific issuer.
//
// Inputs:
//   - issuer (path): The name of the issuer.
//
// Return values:
//   - 200 OK: JSON object of the TransmitterConfiguration for the issuer.
//
// Errors:
//   - 404 Not Found: Configuration not found for the specified issuer.
func (sa *SignalsApplication) WellKnownSsfConfigurationIssuerGet(w http.ResponseWriter, r *http.Request) {
	WellKnownSsfConfigurationIssuerGetHandler(sa, w, r)
}

func WellKnownSsfConfigurationIssuerGetHandler(sa SsfApplicationInterface, w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	rawIssuer := vars["issuer"]
	issuer, _ := url.QueryUnescape(rawIssuer)
	serverLog.Debug(fmt.Sprintf("GET WellKnownSsfConfigurationIssuer/%s", issuer))

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")

	// TODO: Check that issuer is valid (ie. that there is a key that matches)

	baseUrl := sa.GetBaseUrl()
	jwksUri, _ := baseUrl.Parse("/jwks/" + issuer)
	config := getTransmitterConfig(sa)
	config.JwksUri = jwksUri.String()
	config.Issuer = issuer

	resp, _ := json.Marshal(config)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(resp)
}
