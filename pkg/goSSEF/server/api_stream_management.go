/*
 * Stream Management API for OpenID Shared Security Events
 *
 * [OpenID Spec](https://openid.net/specs/openid-sse-framework-1_0.html#management)  HTTP API to be implemented by Event Transmitters. This API can be used by Event Receivers to query and update the Event Stream configuration and status, to add and remove subjects, and to trigger verification.
 *
 * API version: 1.0.0
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */
package server

import (
	"encoding/json"
	"i2goSignals/internal/model"
	"net/http"

	"github.com/gorilla/mux"
)

func (sa *SignalsApplication) AddSubject(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusNotImplemented)
}

func (sa *SignalsApplication) GetStatus(w http.ResponseWriter, r *http.Request) {
	sid, status := ValidateAuthorization(r, sa.Provider.GetAuthValidatorPubKey())

	if status != http.StatusOK {
		w.WriteHeader(status)
		return
	}
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
	w.Write(resp)
}

func (sa *SignalsApplication) RemoveSubject(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusNotImplemented)
}

func (sa *SignalsApplication) StreamDelete(w http.ResponseWriter, r *http.Request) {
	sid, status := ValidateAuthorization(r, sa.Provider.GetAuthValidatorPubKey())

	if status != http.StatusOK {
		w.WriteHeader(status)
		return
	}
	if sid == "" {
		// The authorization token had no stream identifier in it
		w.WriteHeader(http.StatusForbidden)
		return
	}

	state, err := sa.Provider.GetStreamState(sid)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	state.Status = model.StreamStateInactive
	sa.EventRouter.UpdateStreamState(state)

	// Stop all the inbound traffic if Polling
	sa.ClosePollReceiver(sid)

	// Stop any outbound activity
	sa.EventRouter.RemoveStream(sid)

	err = sa.Provider.DeleteStream(sid)
	if err != nil {
		if err.Error() == "not found" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
	}
	// sa.EventRouter.RemoveStream(sid)
	w.WriteHeader(http.StatusOK)
}

func (sa *SignalsApplication) StreamGet(w http.ResponseWriter, r *http.Request) {
	sid, status := ValidateAuthorization(r, sa.Provider.GetAuthValidatorPubKey())

	if status != http.StatusOK {
		w.WriteHeader(status)
		return
	}
	if sid == "" {
		// The authorization token had no stream identifier in it
		w.WriteHeader(http.StatusForbidden)
		return
	}

	config, err := sa.Provider.GetStream(sid)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	resp, _ := json.Marshal(config)
	w.Write(resp)
}

func (sa *SignalsApplication) StreamPost(w http.ResponseWriter, r *http.Request) {
	sid, status := ValidateAuthorization(r, sa.Provider.GetAuthValidatorPubKey())

	if status != http.StatusOK {
		w.WriteHeader(status)
		return
	}
	if sid == "" {
		// The authorization token had no stream identifier in it
		w.WriteHeader(http.StatusForbidden)
		return
	}

	var jsonRequest model.StreamConfiguration
	err := json.NewDecoder(r.Body).Decode(&jsonRequest)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	configResp, err := sa.Provider.UpdateStream(sid, jsonRequest)
	if err != nil {
		if err.Error() == "not found" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		w.Write([]byte(err.Error()))
		w.WriteHeader(http.StatusInternalServerError)
	}

	// Update the event router
	state, _ := sa.Provider.GetStreamState(sid)
	sa.EventRouter.UpdateStreamState(state)
	sa.HandleClientPollReceiver(state)

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")

	respBytes, _ := json.MarshalIndent(configResp, "", "  ")
	w.Write(respBytes)
	// w.WriteHeader(http.StatusOK)
}

func (sa *SignalsApplication) UpdateStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusNotImplemented)
}

func (sa *SignalsApplication) VerificationRequest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusNotImplemented)
}

func (sa *SignalsApplication) WellKnownSseConfigurationGet(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")

	jwksUri, _ := sa.BaseUrl.Parse("/jwks.json")
	configUri, _ := sa.BaseUrl.Parse("/stream")
	statusUri, _ := sa.BaseUrl.Parse("/status")
	addSubUri, _ := sa.BaseUrl.Parse("/add-subject")
	remSubUri, _ := sa.BaseUrl.Parse("/remove-subject")
	verifyUri, _ := sa.BaseUrl.Parse("/verification")

	config := model.TransmitterConfiguration{
		Issuer:  sa.DefIssuer,
		JwksUri: jwksUri.String(),
		DeliveryMethodsSupported: []string{
			model.DeliveryPoll,
			model.DeliveryPush,
		},
		ConfigurationEndpoint:  configUri.String(),
		StatusEndpoint:         statusUri.String(),
		AddSubjectEndpoint:     addSubUri.String(),
		RemoveSubjectEndpoint:  remSubUri.String(),
		VerificationEndpoint:   verifyUri.String(),
		CriticalSubjectMembers: nil,
	}
	resp, _ := json.Marshal(config)
	w.WriteHeader(http.StatusOK)
	w.Write(resp)

}

func (sa *SignalsApplication) WellKnownSseConfigurationIssuerGet(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	vars := mux.Vars(r)
	issuer := vars["issuer"]
	jwksUri, _ := sa.BaseUrl.Parse("/jwks.json" + issuer)
	configUri, _ := sa.BaseUrl.Parse("/stream")
	statusUri, _ := sa.BaseUrl.Parse("/status")
	addSubUri, _ := sa.BaseUrl.Parse("/add-subject")
	remSubUri, _ := sa.BaseUrl.Parse("/remove-subject")
	verifyUri, _ := sa.BaseUrl.Parse("/verification")
	config := model.TransmitterConfiguration{
		Issuer:  issuer,
		JwksUri: jwksUri.String(),
		DeliveryMethodsSupported: []string{
			model.DeliveryPoll,
			model.DeliveryPush,
		},
		ConfigurationEndpoint:  configUri.String(),
		StatusEndpoint:         statusUri.String(),
		AddSubjectEndpoint:     addSubUri.String(),
		RemoveSubjectEndpoint:  remSubUri.String(),
		VerificationEndpoint:   verifyUri.String(),
		CriticalSubjectMembers: nil,
	}
	resp, _ := json.Marshal(config)
	w.WriteHeader(http.StatusOK)
	w.Write(resp)
}
