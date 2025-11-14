package server

import (
	"encoding/json"
	"log"
	"net/http"
	"net/url"

	"github.com/i2-open/i2goSignals/internal/authUtil"
	"github.com/i2-open/i2goSignals/internal/eventRouter"
	"github.com/i2-open/i2goSignals/internal/model"
	"github.com/i2-open/i2goSignals/internal/providers/dbProviders/mongo_provider"

	"github.com/gorilla/mux"
)

func (sa *SignalsApplication) AddSubject(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusNotImplemented)
}

func (sa *SignalsApplication) GetStatus(w http.ResponseWriter, r *http.Request) {
	authCtx, status := sa.Auth.ValidateAuthorization(r, []string{authUtil.ScopeStreamMgmt})

	if status != http.StatusOK {
		w.WriteHeader(status)
		return
	}

	sid := authCtx.StreamId
	if sid == "" {
		// The authorization token had no stream identifier in it
		w.WriteHeader(http.StatusForbidden)
		return
	}

	// vars := mux.Vars(r)
	// subject := vars["subject"]

	streamStatus, err := sa.Provider.GetStatus(sid)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	resp, _ := json.Marshal(*streamStatus)
	_, _ = w.Write(resp)
}

func (sa *SignalsApplication) RemoveSubject(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusNotImplemented)
}

func (sa *SignalsApplication) StreamDelete(w http.ResponseWriter, r *http.Request) {
	authContext, status := sa.Auth.ValidateAuthorization(r, []string{authUtil.ScopeStreamMgmt, authUtil.ScopeStreamAdmin})

	if status != http.StatusOK {
		w.WriteHeader(status)
		return
	}

	if authContext.StreamId == "" {
		// The authorization token had no stream identifier in it
		w.WriteHeader(http.StatusForbidden)
		return
	}
	serverLog.Printf("Stream %s DELETE requested.", authContext.StreamId)

	state, err := sa.Provider.GetStreamState(authContext.StreamId)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	state.Status = model.StreamStateDisable
	sa.EventRouter.UpdateStreamState(state)

	// Stop all the inbound traffic if Polling
	sa.ClosePollReceiver(authContext.StreamId)

	// Stop any outbound activity
	sa.EventRouter.RemoveStream(authContext.StreamId)

	err = sa.Provider.DeleteStream(authContext.StreamId)
	if err != nil {
		if err.Error() == "not found" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(err.Error()))
	}
	// sa.EventRouter.RemoveStream(authContext)
	w.WriteHeader(http.StatusOK)
	serverLog.Printf("Stream %s inactivated and deleted.", authContext.StreamId)
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

func (sa *SignalsApplication) adjustBaseUrl(config model.StreamConfiguration) model.StreamConfiguration {
	res := config
	switch config.Delivery.GetMethod() {
	case model.DeliveryPoll:
		endpoint := res.Delivery.PollTransmitMethod.EndpointUrl
		res.Delivery.PollTransmitMethod.EndpointUrl = replaceBase(endpoint, sa.BaseUrl)
	case model.ReceivePush:
		endpoint := res.Delivery.PushReceiveMethod.EndpointUrl
		res.Delivery.PushReceiveMethod.EndpointUrl = replaceBase(endpoint, sa.BaseUrl)
	default:
		// do nothing
	}
	return res
}

func (sa *SignalsApplication) StreamGet(w http.ResponseWriter, r *http.Request) {
	authCtx, status := sa.Auth.ValidateAuthorization(r, []string{authUtil.ScopeStreamMgmt, authUtil.ScopeStreamAdmin})

	if status != http.StatusOK {
		w.WriteHeader(status)
		return
	}
	if authCtx.StreamId == "" {
		// The authorization token had no stream identifier in it
		w.WriteHeader(http.StatusForbidden)
		return
	}

	config, err := sa.Provider.GetStream(authCtx.StreamId)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	serverLog.Printf("Stream GET %s", authCtx.StreamId)
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusOK)

	resp, _ := json.Marshal(sa.adjustBaseUrl(*config))
	_, _ = w.Write(resp)
}

func (sa *SignalsApplication) StreamCreate(w http.ResponseWriter, r *http.Request) {
	authCtx, status := sa.Auth.ValidateAuthorization(r, []string{authUtil.ScopeRegister, authUtil.ScopeStreamAdmin})
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

	configResp, err := sa.Provider.CreateStream(jsonRequest, authCtx.ProjectId)
	if err != nil {
		if err.Error() == "not found" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		_, _ = w.Write([]byte(err.Error()))
		w.WriteHeader(http.StatusInternalServerError)
	}

	if err != nil {
		if err.Error() == "not found" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		_, _ = w.Write([]byte(err.Error()))
		w.WriteHeader(http.StatusInternalServerError)
	}

	// Update the event router
	state, _ := sa.Provider.GetStreamState(configResp.Id)
	sa.EventRouter.UpdateStreamState(state)
	sa.HandleClientPollReceiver(state)

	serverLog.Printf("Stream %s CREATED", configResp.Id)

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	respBytes, _ := json.MarshalIndent(sa.adjustBaseUrl(configResp), "", "  ")
	_, _ = w.Write(respBytes)

}

func (sa *SignalsApplication) StreamUpdate(w http.ResponseWriter, r *http.Request) {
	authCtx, status := sa.Auth.ValidateAuthorization(r, []string{authUtil.ScopeStreamMgmt, authUtil.ScopeStreamAdmin})

	if status != http.StatusOK {
		w.WriteHeader(status)
		return
	}

	var jsonRequest model.StreamConfiguration
	err := json.NewDecoder(r.Body).Decode(&jsonRequest)

	// Because the PUT/PATCH request does not have a stream id parameter, we extract from payload and re-check
	if !authCtx.Eat.IsAuthorized(jsonRequest.Id, []string{authUtil.ScopeStreamMgmt, authUtil.ScopeStreamAdmin}) {
		http.Error(w, "Stream identifier not authorized", http.StatusForbidden)
		return
	}
	resetJti := jsonRequest.ResetJti
	resetDate := jsonRequest.ResetDate

	jsonRequest.ResetDate = nil
	jsonRequest.ResetJti = ""

	configResp, err := sa.Provider.UpdateStream(authCtx.StreamId, authCtx.ProjectId, jsonRequest)
	if err != nil || configResp == nil {
		if err.Error() == mongo_provider.ErrorInvalidProject {
			http.Error(w, "Streamid invalid for authorization", http.StatusUnauthorized)
			return
		}
		if err.Error() == "not found" || configResp == nil {
			http.Error(w, "No stream found", http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(err.Error()))
		w.WriteHeader(http.StatusInternalServerError)
	}

	streamState, err := sa.Provider.GetStreamState(authCtx.StreamId)
	if resetDate != nil || resetJti != "" {
		// reset the stream to a particular date
		err := sa.Provider.ResetEventStream(authCtx.StreamId, resetJti, resetDate, func(eventRecord *model.EventRecord) bool {
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
	state, _ := sa.Provider.GetStreamState(authCtx.StreamId)
	sa.EventRouter.UpdateStreamState(state)
	sa.HandleClientPollReceiver(state)

	serverLog.Printf("Stream %s UPDATED", authCtx.StreamId)

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	respBytes, _ := json.MarshalIndent(sa.adjustBaseUrl(*configResp), "", "  ")
	_, _ = w.Write(respBytes)
	// w.WriteHeader(http.StatusOK)
}

func (sa *SignalsApplication) UpdateStatus(w http.ResponseWriter, r *http.Request) {
	authCtx, status := sa.Auth.ValidateAuthorization(r, []string{authUtil.ScopeStreamMgmt, authUtil.ScopeStreamAdmin})

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
	streamState, err := sa.Provider.GetStreamState(authCtx.StreamId)
	if jsonRequest.Status != "" {
		if streamState.Status != jsonRequest.Status {
			if jsonRequest.Status == model.StreamStatePause || jsonRequest.Status == model.StreamStateDisable || jsonRequest.Status == model.StreamStateEnabled {
				sa.Provider.UpdateStreamStatus(authCtx.StreamId, jsonRequest.Status, jsonRequest.Reason)
				modified = true
			}

		}
	}

	if modified {
		sa.EventRouter.UpdateStreamState(streamState)
		sa.HandleClientPollReceiver(streamState)
	}

	statusResp, _ := sa.Provider.GetStatus(authCtx.StreamId)

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	respBytes, _ := json.MarshalIndent(statusResp, "", "  ")
	_, _ = w.Write(respBytes)

}

func (sa *SignalsApplication) VerificationRequest(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusNotImplemented)
}

func (sa *SignalsApplication) getTransmitterConfig() *model.TransmitterConfiguration {
	jwksUri, _ := sa.BaseUrl.Parse("/jwks.json")
	configUri, _ := sa.BaseUrl.Parse("/stream")
	statusUri, _ := sa.BaseUrl.Parse("/status")
	addSubUri, _ := sa.BaseUrl.Parse("/add-subject")
	remSubUri, _ := sa.BaseUrl.Parse("/remove-subject")
	verifyUri, _ := sa.BaseUrl.Parse("/verification")
	regUri, _ := sa.BaseUrl.Parse("/register")

	return &model.TransmitterConfiguration{
		Issuer:  sa.DefIssuer,
		JwksUri: jwksUri.String(),
		DeliveryMethodsSupported: []string{
			model.DeliveryPoll,
			model.DeliveryPush,
			model.ReceivePoll,
			model.ReceivePush,
		},
		ConfigurationEndpoint:      configUri.String(),
		StatusEndpoint:             statusUri.String(),
		AddSubjectEndpoint:         addSubUri.String(),
		RemoveSubjectEndpoint:      remSubUri.String(),
		VerificationEndpoint:       verifyUri.String(),
		CriticalSubjectMembers:     nil,
		ClientRegistrationEndpoint: regUri.String(),
		SupportedScopes: map[string][]string{
			"configuration_endpoint":       {authUtil.ScopeStreamAdmin, authUtil.ScopeStreamMgmt},
			"status_endpoint":              {authUtil.ScopeStreamMgmt},
			"add_subject_endpoint":         {authUtil.ScopeStreamMgmt},
			"remove_subject_endpoint":      {authUtil.ScopeStreamMgmt},
			"events":                       {authUtil.ScopeEventDelivery},
			"verification_endpoint":        {authUtil.ScopeEventDelivery, authUtil.ScopeStreamMgmt},
			"poll":                         {authUtil.ScopeEventDelivery},
			"client_registration_endpoint": {authUtil.ScopeRegister},
		},
	}
}

func (sa *SignalsApplication) WellKnownSsfConfigurationGet(w http.ResponseWriter, _ *http.Request) {
	serverLog.Println("GET WellKnownSsfConfiguration")
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")

	resp, _ := json.Marshal(sa.getTransmitterConfig())
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(resp)

}

func (sa *SignalsApplication) WellKnownSsfConfigurationIssuerGet(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	issuer := vars["issuer"]
	serverLog.Printf("GET WellKnownSsfConfigurationIssuer/%s", issuer)

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")

	// TODO: Check that issuer is valid (ie. that there is a key that matches)

	jwksUri, _ := sa.BaseUrl.Parse("/jwks/" + issuer)
	config := sa.getTransmitterConfig()
	config.JwksUri = jwksUri.String()
	config.Issuer = issuer

	resp, _ := json.Marshal(config)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(resp)
}
