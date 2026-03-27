package server

/*
api_stream_management.go implements the SSF API requirements to register and stream and allow updates to them.
These functions require an authorization token that includes a project id and stream id value. Because of this
simplification, there is no way for a client to ask for a specific stream or all streams unless they have a token.

Because of this, administrative access is via admin.go
*/
import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/i2-open/i2goSignals/internal/eventRouter"
	"github.com/i2-open/i2goSignals/internal/providers/dbProviders/mongo_provider"
	"github.com/i2-open/i2goSignals/pkg/authSupport"
	"github.com/i2-open/i2goSignals/pkg/constants"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"

	"github.com/gorilla/mux"
)

// AddSubject adds a subject to a stream. (Currently not implemented)
//
// Return values:
//   - 501 Not Implemented
func (sa *SignalsApplication) AddSubject(w http.ResponseWriter, r *http.Request) {
	AddSubjectHandler(sa, w, r)
}

func AddSubjectHandler(_ SsfApplicationInterface, w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusNotImplemented)
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

	streamStatus, err := sa.GetProvider().GetStatus(sid)
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

// RemoveSubject removes a subject from a stream. (Currently not implemented)
//
// Return values:
//   - 501 Not Implemented
func (sa *SignalsApplication) RemoveSubject(w http.ResponseWriter, r *http.Request) {
	RemoveSubjectHandler(sa, w, r)
}

func RemoveSubjectHandler(_ SsfApplicationInterface, w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusNotImplemented)
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

	state, err := sa.GetProvider().GetStreamState(authContext.StreamId)
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

	err = sa.GetProvider().DeleteStream(authContext.StreamId)
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

	config, err := sa.GetProvider().GetStream(authCtx.StreamId)
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

func StreamCreateHandler(sa SsfApplicationInterface, w http.ResponseWriter, r *http.Request) {
	authCtx, status := sa.GetAuth().ValidateAuthorizationAny(r, []string{authSupport.ScopeRegister, authSupport.ScopeStreamAdmin})
	if status != http.StatusOK {
		w.WriteHeader(status)
		return
	}
	var jsonRequest model.StreamConfiguration
	err := json.NewDecoder(r.Body).Decode(&jsonRequest)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	jsonRequest.ResetDate = nil
	jsonRequest.ResetJti = ""

	configResp, err := sa.GetProvider().CreateStream(jsonRequest, authCtx)
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
	state, err := sa.GetProvider().GetStreamState(configResp.Id)
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

	var jsonRequest model.StreamConfiguration
	err := json.NewDecoder(r.Body).Decode(&jsonRequest)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Because the PUT/PATCH request does not have a stream id parameter, we extract from payload and re-check
	if authCtx.Eat != nil && !authCtx.Eat.IsAuthorized(jsonRequest.Id, []string{authSupport.ScopeStreamMgmt, authSupport.ScopeStreamAdmin}) {
		http.Error(w, "Stream identifier not authorized", http.StatusForbidden)
		return
	}
	resetJti := jsonRequest.ResetJti
	resetDate := jsonRequest.ResetDate

	jsonRequest.ResetDate = nil
	jsonRequest.ResetJti = ""

	configResp, err := sa.GetProvider().UpdateStream(authCtx.StreamId, authCtx.ProjectId, jsonRequest)
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

	streamState, err := sa.GetProvider().GetStreamState(authCtx.StreamId)
	if err != nil {
		serverLog.Error("Error getting stream state after update", "id", authCtx.StreamId, "error", err)
	}
	if resetDate != nil || resetJti != "" {
		// reset the stream to a particular date
		err := sa.GetProvider().ResetEventStream(authCtx.StreamId, resetJti, resetDate, func(eventRecord *model.EventRecord) bool {
			// Because reset goes through all events, this function confirms the stream should get the event
			return eventRouter.StreamEventMatch(streamState, eventRecord)
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
	state, err := sa.GetProvider().GetStreamState(authCtx.StreamId)
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
	streamState, err := sa.GetProvider().GetStreamState(authCtx.StreamId)
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
				sa.GetProvider().UpdateStreamStatus(authCtx.StreamId, jsonRequest.Status, jsonRequest.Reason)
				modified = true
				// Refresh streamState after update
				updatedState, err := sa.GetProvider().GetStreamState(authCtx.StreamId)
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

	statusResp, err := sa.GetProvider().GetStatus(authCtx.StreamId)
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
	addSubUri, _ := baseUrl.Parse("/add-subject")
	remSubUri, _ := baseUrl.Parse("/remove-subject")
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

	return &model.TransmitterConfiguration{
		Issuer:                     sa.GetDefIssuer(),
		JwksUri:                    jwksUri.String(),
		DeliveryMethodsSupported:   methods,
		ConfigurationEndpoint:      configUri.String(),
		StatusEndpoint:             statusUri.String(),
		AddSubjectEndpoint:         addSubUri.String(),
		RemoveSubjectEndpoint:      remSubUri.String(),
		VerificationEndpoint:       verifyUri.String(),
		CriticalSubjectMembers:     nil,
		ClientRegistrationEndpoint: regUri.String(),
		SupportedScopes: map[string][]string{
			"configuration_endpoint":       {authSupport.ScopeStreamAdmin, authSupport.ScopeStreamMgmt},
			"status_endpoint":              {authSupport.ScopeStreamMgmt},
			"add_subject_endpoint":         {authSupport.ScopeStreamMgmt},
			"remove_subject_endpoint":      {authSupport.ScopeStreamMgmt},
			"events":                       {authSupport.ScopeEventDelivery},
			"verification_endpoint":        {authSupport.ScopeEventDelivery, authSupport.ScopeStreamMgmt},
			"poll":                         {authSupport.ScopeEventDelivery},
			"client_registration_endpoint": {authSupport.ScopeRegister},
		},
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
