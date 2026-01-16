// Package server - Stream Management API for OpenID Shared Security Events
// "API Out of band" is for administrative tasks not directly part of the SSF spec or specifically with stream management.
package server

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/MicahParks/keyfunc"
	"github.com/gorilla/mux"
	"github.com/i2-open/i2goSignals/internal/authUtil"
	"github.com/i2-open/i2goSignals/internal/model"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// rotateIssuer This function performs a key rotation on an existing issuer and ensures that previous public keys
// remain available when JwksJsonIssuer is requested.
func (sa *SignalsApplication) rotateIssuer(w http.ResponseWriter, r *http.Request, authCtx *authUtil.AuthContext) {
	// This function is called by CreateJwksIssuer so authentication has already been checked.

	vars := mux.Vars(r)
	issuer := vars["issuer"]

	issuerKey, kid, err := sa.Provider.RotateIssuerKey(issuer, authCtx.ProjectId)
	if err != nil {
		serverLog.Printf("Error rotating issuer keys for issuer %s: %v", issuer, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Update the router with the new key/kid
	if sa.EventRouter != nil {
		sa.EventRouter.UpdateStreamState(&model.StreamStateRecord{
			StreamConfiguration: model.StreamConfiguration{
				Iss: issuer,
			},
		})
	}

	pkcs8bytes, _ := x509.MarshalPKCS8PrivateKey(issuerKey)
	keyPemBytes := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: pkcs8bytes,
			Headers: map[string]string{
				"kid": kid,
			},
		})

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(keyPemBytes)
}

// CreateJwksIssuer handles the creation of a JWK key pair for the specified issuer and authorizes access permissions.
// Generates a PEM-encoded private key and writes it to the HTTP response with Content-Type as application/json.
// Responds with HTTP status Forbidden if permissions are invalid or Internal Server Error for unknown issues.
func (sa *SignalsApplication) CreateJwksIssuer(w http.ResponseWriter, r *http.Request) {
	authCtx, stat := sa.Auth.ValidateAuthorizationAny(r, []string{authUtil.ScopeStreamAdmin, authUtil.ScopeRoot})
	if stat != http.StatusOK || authCtx == nil {
		http.Error(w, "Invalid permission", http.StatusForbidden)
		return
	}

	vars := mux.Vars(r)
	issuer := vars["issuer"]
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")

	key := sa.Provider.GetIssuerJwksForReceiver(issuer)
	serverLog.Printf("CreateJwksIssuer: key exists: %v", key != nil)
	if key != nil {
		// Do they want to rotate?
		queryParams := r.URL.Query()
		_, rotate := queryParams["rotate"]
		if rotate {
			sa.rotateIssuer(w, r, authCtx)
			return
		}
		http.Error(w, "Already exists, specify rotate=true to rotate issuer", http.StatusForbidden)
		return
	}

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

func (sa *SignalsApplication) LoadKey(writer http.ResponseWriter, request *http.Request) {
	authCtx, stat := sa.Auth.ValidateAuthorizationAny(request, []string{authUtil.ScopeStreamAdmin, authUtil.ScopeRoot})
	if stat != http.StatusOK || authCtx == nil {
		http.Error(writer, "Invalid permission", http.StatusForbidden)
		return
	}
	vars := mux.Vars(request)
	issuer := vars["issuer"]

	contentType := strings.Split(request.Header.Get("Content-Type"), ";")[0]
	contentType = strings.TrimSpace(contentType)

	body, err := io.ReadAll(request.Body)
	if err != nil {
		http.Error(writer, "Error reading request body", http.StatusBadRequest)
		return
	}

	var priv *rsa.PrivateKey
	var pub *rsa.PublicKey

	switch contentType {
	case "application/x-pem-file":
		block, _ := pem.Decode(body)
		if block == nil {
			http.Error(writer, "Invalid PEM data", http.StatusBadRequest)
			return
		}
		if block.Type == "PRIVATE KEY" || block.Type == "RSA PRIVATE KEY" {
			if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
				priv = key
				pub = &key.PublicKey
			} else if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
				if rsaKey, ok := key.(*rsa.PrivateKey); ok {
					priv = rsaKey
					pub = &rsaKey.PublicKey
				}
			}
		} else if block.Type == "PUBLIC KEY" || block.Type == "RSA PUBLIC KEY" {
			if key, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
				pub = key
			} else if key, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
				if rsaKey, ok := key.(*rsa.PublicKey); ok {
					pub = rsaKey
				}
			}
		} else if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				http.Error(writer, "Invalid certificate", http.StatusBadRequest)
				return
			}
			if rsaKey, ok := cert.PublicKey.(*rsa.PublicKey); ok {
				pub = rsaKey
			}
		}

	case "application/pkix-cert":
		// Try parsing as certificate first
		cert, err := x509.ParseCertificate(body)
		if err == nil {
			if rsaKey, ok := cert.PublicKey.(*rsa.PublicKey); ok {
				pub = rsaKey
			}
		} else {
			// Try parsing as PKIX public key
			if key, err := x509.ParsePKIXPublicKey(body); err == nil {
				if rsaKey, ok := key.(*rsa.PublicKey); ok {
					pub = rsaKey
				}
			}
		}

	case "application/pkcs7-mime":
		// For this project, it seems pkcs7-mime means PKCS#1 DER for public keys
		if key, err := x509.ParsePKCS1PublicKey(body); err == nil {
			pub = key
		}
	}

	if priv == nil && pub == nil {
		http.Error(writer, "Could not parse key or unsupported key type", http.StatusBadRequest)
		return
	}

	err = sa.Provider.AddIssuerKey(issuer, "", priv, pub, authCtx.ProjectId)
	if err != nil {
		http.Error(writer, "Error saving key", http.StatusInternalServerError)
		return
	}

	writer.WriteHeader(http.StatusOK)
}

func (sa *SignalsApplication) DeleteJwksIssuerKey(w http.ResponseWriter, r *http.Request) {
	authCtx, stat := sa.Auth.ValidateAuthorizationAny(r, []string{authUtil.ScopeStreamAdmin, authUtil.ScopeRoot})
	if stat != http.StatusOK || authCtx == nil {
		http.Error(w, "Invalid permission", http.StatusForbidden)
		return
	}
	vars := mux.Vars(r)
	issuer := vars["issuer"]
	err := sa.Provider.DeleteIssuer(issuer)
	if err != nil {
		serverLog.Printf("Error deleting issuer keys for issuer %s: %v", issuer, err)
		if err.Error() == "issuer not found" {
			http.Error(w, "Issuer not found", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	return
}

func convertKey(jwksJson *json.RawMessage, format string) ([]byte, error) {
	jwks, err := keyfunc.NewJSON(*jwksJson)
	if err != nil {
		return nil, err
	}

	keys := jwks.ReadOnlyKeys()
	if len(keys) == 0 {
		return nil, fmt.Errorf("no keys found in JWKS")
	}

	switch format {
	case "pem":
		var pemData []byte
		for _, kid := range jwks.KIDs() {
			if pubKey, ok := keys[kid]; ok {
				der, err := x509.MarshalPKIXPublicKey(pubKey)
				if err != nil {
					return nil, err
				}
				block := &pem.Block{
					Type:  "PUBLIC KEY",
					Bytes: der,
				}
				pemData = append(pemData, pem.EncodeToMemory(block)...)
			}
		}
		return pemData, nil

	case "x509":
		// Return the first key in DER format (PKIX)
		for _, kid := range jwks.KIDs() {
			if pubKey, ok := keys[kid]; ok {
				der, err := x509.MarshalPKIXPublicKey(pubKey)
				if err != nil {
					return nil, err
				}
				return der, nil
			}
		}
		return nil, fmt.Errorf("no keys found")

	case "pkcs":
		// Return the first key in PKCS#1 format
		for _, kid := range jwks.KIDs() {
			if pubKey, ok := keys[kid]; ok {
				if rsaPubKey, ok := pubKey.(*rsa.PublicKey); ok {
					der := x509.MarshalPKCS1PublicKey(rsaPubKey)
					return der, nil
				}
				// Fallback to PKIX if not RSA
				der, err := x509.MarshalPKIXPublicKey(pubKey)
				if err != nil {
					return nil, err
				}
				return der, nil
			}
		}
		return nil, fmt.Errorf("no keys found")

	default:
		return nil, fmt.Errorf("unsupported format: %s", format)
	}
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

// RegisterClient is used in scenarios where there is no external OAuth infrastructure to manage access.
// Using RegisterClient allows a goSignals command line client or admin server to register with an IAT.
// When successful, the client is is issued an administrative token which can be used to register new streams.
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

// ProtectedResourceMetadata returns the RFC9728 based data describing OAuth access
func (sa *SignalsApplication) ProtectedResourceMetadata(w http.ResponseWriter, _ *http.Request) {
	serverLog.Println("GET ProtectedResourceMetadata")
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")

	baseURl := sa.BaseUrl.String()
	name := "GoSignals"
	prMeta := model.ProtectedResourceMetadata{
		Resource:               &baseURl,
		AuthorizationServers:   sa.Auth.GetOAuthServers(),
		ScopesSupported:        []string{authUtil.ScopeEventDelivery, authUtil.ScopeStreamMgmt, authUtil.ScopeStreamAdmin, authUtil.ScopeEventDelivery, authUtil.ScopeRegister},
		BearerMethodsSupported: []string{"header"},
		ResourceName:           &name,
	}

	resp, _ := json.MarshalIndent(prMeta, "", "  ")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(resp)
}

// ListStreamStates allows the ability to list all stream states associated with the current server project. Requires "admin" or "root" scope.
// If the authentication credential includes a project id, the result set is limited to the project.
func (sa *SignalsApplication) ListStreamStates(w http.ResponseWriter, r *http.Request) {
	authCtx, status := sa.Auth.ValidateAuthorizationAny(r, []string{authUtil.ScopeStreamAdmin, authUtil.ScopeRoot})
	if status != http.StatusOK {
		w.WriteHeader(status)
		return
	}
	projectId := authCtx.ProjectId
	mapStreams := sa.Provider.GetStateMap()
	result := make([]model.StreamStateRecord, 0)
	for _, stream := range mapStreams {
		if projectId == "" || stream.ProjectId == projectId {
			result = append(result, sa.adjustStateBaseUrl(stream))
		}
	}

	serverLog.Printf("ListStreamStates: %d returned", len(result))

	resp, err := json.Marshal(result)
	if err != nil {
		serverLog.Printf("Internal error ListStreamStates: %s\n", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(resp)
}

// GetStreamState allows the ability to retrieve a specific stream state associated with the current server project. Requires "admin" or "root" scope.
// If the authentication credential includes a project id, the result set is limited to the project.
func (sa *SignalsApplication) GetStreamState(w http.ResponseWriter, r *http.Request) {
	authCtx, status := sa.Auth.ValidateAuthorizationAny(r, []string{authUtil.ScopeStreamAdmin, authUtil.ScopeRoot})
	if status != http.StatusOK {
		w.WriteHeader(status)
		return
	}

	if authCtx.StreamId == "" {
		// The authorization and request had no streamId detected
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	config, err := sa.Provider.GetStreamState(authCtx.StreamId)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	serverLog.Printf("GetStreamState: %s returned", config.StreamConfiguration.Id)

	resp, err := json.Marshal(config)
	if err != nil {
		serverLog.Printf("Internal error GetStreamState: %s\n", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(resp)
}
