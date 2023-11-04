// Package server - Stream Management API for OpenID Shared Security Events
// [OpenID Spec](https://openid.net/specs/openid-sse-framework-1_0.html#management)  HTTP API to be implemented by Event Transmitters. This API can be used by Event Receivers to query and update the Event Stream configuration and status, to add and remove subjects, and to trigger verification.
package server

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/i2-open/i2goSignals/internal/authUtil"
	"github.com/i2-open/i2goSignals/internal/model"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

func (sa *SignalsApplication) CreateJwksIssuer(w http.ResponseWriter, r *http.Request) {
	authCtx, stat := sa.Auth.ValidateAuthorization(r, []string{authUtil.ScopeStreamAdmin, authUtil.ScopeRoot})
	if stat != http.StatusOK || authCtx == nil {
		http.Error(w, "Invalid permission", http.StatusForbidden)
		return
	}
	vars := mux.Vars(r)
	issuer := vars["issuer"]
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")

	issuerKey := sa.Provider.CreateIssuerJwkKeyPair(issuer, authCtx.ProjectId)

	pkcs8bytes, _ := x509.MarshalPKCS8PrivateKey(issuerKey)
	keyPemBytes := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: pkcs8bytes,
		})

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(keyPemBytes)
	return
	// http.Error(w, "Unknown error generating private key", http.StatusInternalServerError)
}

// IssuerProjectIat generates an Initial Access Auth (IAT) which can be used at the registration endpoint. The
// token generated will have a unique projectId and scope of `register` that will allow individual clients
// to register and access the stream management functions of the server for a particular project. If an existing
// authorization is provided with scope authUtil.ScopeStreamAdmin, then the existing ProjectId is used. This
// allows the creation of "fresh" IATs which can be used to register new clients in the same project (e.g.
// because the current IAT is expired, or because separate IATs are desired.
func (sa *SignalsApplication) IssuerProjectIat(w http.ResponseWriter, r *http.Request) {
	authCtx, _ := sa.Auth.ValidateAuthorization(r, []string{authUtil.ScopeStreamAdmin})
	projectIat, err := sa.Auth.IssueProjectIat(authCtx)
	if err != nil {
		serverLog.Printf("Error generating IAT: %s", err.Error())
		http.Error(w, "Error generating project IAT", http.StatusInternalServerError)
	}
	response := model.RegisterResponse{Token: projectIat}
	regBytes, _ := json.Marshal(response)
	_, _ = w.Write(regBytes)
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
}

// RegisterClient handles initial SSF client registrations and issues tokens enabling stream management.
// In order to access the registration endpoint an initial access token with scope 'register' is required.
// If 'root' scope is provided, a registration token is issued which can be used to start the client registration process.
func (sa *SignalsApplication) RegisterClient(w http.ResponseWriter, r *http.Request) {
	authCtx, stat := sa.Auth.ValidateAuthorization(r, []string{authUtil.ScopeRegister})
	if stat != http.StatusOK {
		serverLog.Printf("ERROR: Issued token was not validated: HTTP Status %d", stat)

		http.Error(w, "Failed to register client. Invalid registration token", stat)
		return
	}
	var jsonRequest model.RegisterParameters
	err := json.NewDecoder(r.Body).Decode(&jsonRequest)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var scopes []string
	if len(jsonRequest.Scopes) == 0 {
		scopes = append(scopes, authUtil.ScopeStreamMgmt, authUtil.ScopeEventDelivery)
	} else {
		for _, v := range jsonRequest.Scopes {
			switch v {
			case authUtil.ScopeStreamMgmt, authUtil.ScopeStreamAdmin, authUtil.ScopeEventDelivery:
				scopes = append(scopes, v)
			default:
			}
		}
	}

	client := model.SsfClient{
		ProjectIds:    []string{authCtx.ProjectId},
		Email:         jsonRequest.Email,
		Description:   jsonRequest.Description,
		AllowedScopes: scopes,
		Id:            primitive.NewObjectID(),
	}

	response := sa.Provider.RegisterClient(client, authCtx.ProjectId)
	if response == nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	regBytes, _ := json.MarshalIndent(response, "", " ")
	_, _ = w.Write(regBytes)
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
}

func (sa *SignalsApplication) TriggerEvent(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusNotImplemented)
}
