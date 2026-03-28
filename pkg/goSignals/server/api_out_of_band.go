// Package server - Stream Management API for OpenID Shared Security Events
// "API Out of band" is for administrative tasks not directly part of the SSF spec or specifically with stream management.
package server

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/MicahParks/keyfunc/v2"
	"github.com/gorilla/mux"
	"github.com/i2-open/i2goSignals/internal/authUtil"
	"github.com/i2-open/i2goSignals/internal/dao/interfaces"
	"github.com/i2-open/i2goSignals/internal/services"
	"github.com/i2-open/i2goSignals/pkg/authSupport"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"go.mongodb.org/mongo-driver/v2/bson"
)

// rotateIssuer This function performs a key rotation on an existing issuer and ensures that previous public keys
// remain available when JwksJsonIssuer is requested.
func (sa *SignalsApplication) rotateIssuer(w http.ResponseWriter, r *http.Request, authCtx *authUtil.AuthContext) {
	RotateIssuerHandler(sa, w, r, authCtx)
}

func RotateIssuerHandler(sa SsfApplicationInterface, w http.ResponseWriter, r *http.Request, authCtx *authUtil.AuthContext) {
	// This function is called by CreateJwksIssuer so authentication has already been checked.

	vars := mux.Vars(r)
	rawIssuer := vars["issuer"]
	issuer, _ := url.QueryUnescape(rawIssuer)

	issuerKey, kid, err := sa.GetProvider().RotateKey(issuer, authCtx.ProjectId)
	if err != nil {
		serverLog.Error(fmt.Sprintf("Error rotating issuer keys for issuer %s: %v", issuer, err))
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// If the rotated issuer is the token issuer, update the application's AuthIssuer
	if sa.GetAuth() != nil && sa.GetAuth().TokenIssuer == issuer {
		sa.GetAuth().UpdateTokenKey(issuer, kid, issuerKey, sa.GetProvider().GetAuthValidatorPubKey())
	}

	// Update the router with the new key/kid
	if sa.GetEventRouter() != nil {
		sa.GetEventRouter().UpdateStreamState(&model.StreamStateRecord{
			StreamConfiguration: model.StreamConfiguration{
				Iss: issuer,
			},
		})
	}

	pkcs8bytes, err := x509.MarshalPKCS8PrivateKey(issuerKey)
	if err != nil {
		serverLog.Error(fmt.Sprintf("Error marshaling private key for issuer %s: %v", issuer, err))
		http.Error(w, "Error marshaling private key", http.StatusInternalServerError)
		return
	}
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
	_, err = w.Write(keyPemBytes)
	if err != nil {
		serverLog.Error(fmt.Sprintf("Error writing response for issuer %s: %v", issuer, err))
	}
}

// CreateJwksIssuer handles the creation of a JWK key pair for the specified issuer and authorizes access permissions.
//
// Inputs:
//   - issuer (path): The name of the issuer for which to create the key pair.
//   - rotate (query): Optional. If set to "true", rotates existing keys if they already exist.
//
// Return values:
//   - 201 Created: PEM-encoded private key.
//   - 200 OK: (If rotating) PEM-encoded private key.
//
// Errors:
//   - 400 Bad Request: Malformed issuer encoding.
//   - 403 Forbidden: Invalid permissions or issuer already exists without rotate=true.
//   - 500 Internal Server Error: Error checking existing keys, generating, marshaling, or writing the private key.
func (sa *SignalsApplication) CreateJwksIssuer(w http.ResponseWriter, r *http.Request) {
	CreateJwksIssuerHandler(sa, w, r)
}

func CreateJwksIssuerHandler(sa SsfApplicationInterface, w http.ResponseWriter, r *http.Request) {
	authCtx, stat := sa.GetAuth().ValidateAuthorizationAny(r, []string{authSupport.ScopeStreamAdmin, authSupport.ScopeRoot})
	if stat != http.StatusOK || authCtx == nil {
		http.Error(w, "Invalid permission", http.StatusForbidden)
		return
	}

	vars := mux.Vars(r)
	rawIssuer := vars["issuer"]
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")

	issuer, err := url.QueryUnescape(rawIssuer)
	if err != nil {
		serverLog.Warn(fmt.Sprintf("Error unescaping issuer %s: %v", rawIssuer, err))
		http.Error(w, "Error malformed issuer encoding", http.StatusBadRequest)
		return
	}

	// Check if issuer key already exists
	existingKey, err := sa.GetProvider().GetPrivateKey(issuer)
	if err != nil && !errors.Is(err, interfaces.ErrKeyNotFound) {
		serverLog.Error(fmt.Sprintf("Error checking existing issuer key for %s: %v", issuer, err))
		http.Error(w, "Error checking existing key", http.StatusInternalServerError)
		return
	}
	if existingKey != nil {
		// Do they want to rotate?
		queryParams := r.URL.Query()
		_, rotate := queryParams["rotate"]
		if rotate {
			RotateIssuerHandler(sa, w, r, authCtx)
			return
		}
		http.Error(w, "Already exists, specify rotate=true to rotate issuer", http.StatusForbidden)
		return
	}

	issuerKey, err := sa.GetProvider().CreateKeyPair(issuer, "sig", authCtx.ProjectId)
	if err != nil {
		serverLog.Error(fmt.Sprintf("Error generating private key for issuer %s: %v", issuer, err))
		http.Error(w, "Error generating private key", http.StatusInternalServerError)
		return
	}

	// If the created issuer is the token issuer, update the application's AuthIssuer
	if sa.GetAuth() != nil && sa.GetAuth().TokenIssuer == issuer {
		sa.GetAuth().UpdateTokenKey(issuer, issuer, issuerKey, sa.GetProvider().GetAuthValidatorPubKey())
	}

	pkcs8bytes, err := x509.MarshalPKCS8PrivateKey(issuerKey)
	if err != nil {
		serverLog.Error(fmt.Sprintf("Error marshaling private key for issuer %s: %v", issuer, err))
		http.Error(w, "Error marshaling private key", http.StatusInternalServerError)
		return
	}
	keyPemBytes := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: pkcs8bytes,
		})

	w.WriteHeader(http.StatusCreated)
	_, err = w.Write(keyPemBytes)
	if err != nil {
		serverLog.Error(fmt.Sprintf("Error writing response for issuer %s: %v", issuer, err))
	}
	return
}

// LoadKey handles the uploading of a public or private key for a specified issuer.
//
// Inputs:
//   - issuer (path): The name of the issuer for which to load the key. This will become the kid in the certificates and matches certificate 'iss' values.
//   - Content-Type (header): Must be one of 'application/x-pem-file', 'application/pkix-cert', or 'application/pkcs7-mime'.
//   - Request body: The key data in PEM or DER format.
//
// Return values:
//   - 200 OK: Key successfully loaded and saved.
//
// Errors:
//   - 400 Bad Request: Error reading body, invalid PEM data, invalid certificate, or unsupported key type.
//   - 403 Forbidden: Invalid permissions.
//   - 500 Internal Server Error: Error saving the key.
func (sa *SignalsApplication) LoadKey(writer http.ResponseWriter, request *http.Request) {
	LoadKeyHandler(sa, writer, request)
}

func LoadKeyHandler(sa SsfApplicationInterface, writer http.ResponseWriter, request *http.Request) {
	authCtx, stat := sa.GetAuth().ValidateAuthorizationAny(request, []string{authSupport.ScopeStreamAdmin, authSupport.ScopeRoot})
	if stat != http.StatusOK || authCtx == nil {
		http.Error(writer, "Invalid permission", http.StatusForbidden)
		return
	}
	vars := mux.Vars(request)
	rawIssuer := vars["issuer"]
	issuer, _ := url.QueryUnescape(rawIssuer)

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

	err = sa.GetProvider().AddKey(issuer, "sig", "", priv, pub, authCtx.ProjectId)
	if err != nil {
		http.Error(writer, "Error saving key", http.StatusInternalServerError)
		return
	}

	// If the loaded issuer is the token issuer, update the application's AuthIssuer
	if sa.GetAuth() != nil && sa.GetAuth().TokenIssuer == issuer && priv != nil {
		// We don't have the kid here, it will default to issuer in UpdateTokenKey fallback or we can load it
		// But AddIssuerKey with empty kid uses issuer as kid.
		sa.GetAuth().UpdateTokenKey(issuer, issuer, priv, sa.GetProvider().GetAuthValidatorPubKey())
	}

	writer.WriteHeader(http.StatusOK)
}

// DeleteJwksIssuerKey deletes the keys associated with a specified issuer.
//
// Inputs:
//   - issuer (path): The name of the issuer whose keys are to be deleted.
//
// Return values:
//   - 200 OK: Issuer keys successfully deleted.
//
// Errors:
//   - 403 Forbidden: Invalid permissions.
//   - 404 Not Found: Issuer keys not found.
//   - 500 Internal Server Error: Error during deletion process.
func (sa *SignalsApplication) DeleteJwksIssuerKey(w http.ResponseWriter, r *http.Request) {
	DeleteJwksIssuerKeyHandler(sa, w, r)
}

func DeleteJwksIssuerKeyHandler(sa SsfApplicationInterface, w http.ResponseWriter, r *http.Request) {
	authCtx, stat := sa.GetAuth().ValidateAuthorizationAny(r, []string{authSupport.ScopeStreamAdmin, authSupport.ScopeRoot})
	if stat != http.StatusOK || authCtx == nil {
		http.Error(w, "Invalid permission", http.StatusForbidden)
		return
	}
	vars := mux.Vars(r)
	rawIssuer := vars["issuer"]
	issuer, _ := url.QueryUnescape(rawIssuer)
	err := sa.GetProvider().DeleteKeysByName(issuer)
	if err != nil {
		serverLog.Error("Error deleting issuer keys for issuer", issuer, err.Error())
		if errors.Is(err, interfaces.ErrKeyNotFound) {
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

// IssuerProjectIat generates an Initial Access Token (IAT) for a project.
// The token has a unique projectId and 'register' scope, allowing clients to register and manage streams.
//
// Inputs:
//   - Authorization (header): Existing administrative token (optional, but if provided, its ProjectId is reused).
//
// Return values:
//   - 200 OK: JSON object containing the generated IAT.
//
// Errors:
//   - 500 Internal Server Error: Error generating the Iat.
func (sa *SignalsApplication) IssuerProjectIat(w http.ResponseWriter, r *http.Request) {
	IssuerProjectIatHandler(sa, w, r)
}

func IssuerProjectIatHandler(sa SsfApplicationInterface, w http.ResponseWriter, r *http.Request) {
	authCtx, _ := sa.GetAuth().ValidateAuthorizationAny(r, []string{authSupport.ScopeStreamAdmin})
	projectIat, err := sa.GetAuth().IssueProjectIat(authCtx)
	if err != nil {
		serverLog.Error("Error generating IAT", "error", err.Error())
		http.Error(w, "Error generating project IAT", http.StatusInternalServerError)
	}
	response := model.RegisterResponse{Token: projectIat}
	regBytes, _ := json.Marshal(response)
	_, _ = w.Write(regBytes)
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
}

// RegisterClient registers a new client using an IAT.
//
// Inputs:
//   - Authorization (header): IAT with 'register' scope.
//   - Request body (JSON): RegisterParameters containing Email, Description, and Scopes.
//
// Return values:
//   - 200 OK: JSON object containing client registration details (ClientId, ClientSecret, etc.).
//
// Errors:
//   - 400 Bad Request: Error decoding request body.
//   - 401/403: Invalid or missing registration token.
//   - 500 Internal Server Error: Error during client registration.
func (sa *SignalsApplication) RegisterClient(w http.ResponseWriter, r *http.Request) {
	RegisterClientHandler(sa, w, r)
}

func RegisterClientHandler(sa SsfApplicationInterface, w http.ResponseWriter, r *http.Request) {
	authCtx, stat := sa.GetAuth().ValidateAuthorizationAny(r, []string{authSupport.ScopeRegister})
	if stat != http.StatusOK {
		serverLog.Error("ERROR: Issued token was not validated", "HTTP Status", stat)
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
		scopes = append(scopes, authSupport.ScopeStreamMgmt, authSupport.ScopeEventDelivery)
	} else {
		for _, v := range jsonRequest.Scopes {
			switch v {
			case authSupport.ScopeStreamMgmt, authSupport.ScopeStreamAdmin, authSupport.ScopeEventDelivery:
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
		Id:            bson.NewObjectID(),
	}

	response := sa.GetProvider().RegisterClient(client, authCtx.ProjectId)
	if response == nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	regBytes, _ := json.MarshalIndent(response, "", " ")
	_, _ = w.Write(regBytes)
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
}

// TriggerEvent is a placeholder handler for triggering events manually. (Not currently implemented)
//
// Return values:
//   - 501 Not Implemented
func (sa *SignalsApplication) TriggerEvent(w http.ResponseWriter, r *http.Request) {
	TriggerEventHandler(sa, w, r)
}

func TriggerEventHandler(_ SsfApplicationInterface, w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusNotImplemented)
}

// ProtectedResourceMetadata returns RFC9728 metadata describing OAuth access to the server.
//
// Return values:
//   - 200 OK: JSON object with resource name, auth servers, and supported scopes/methods.
func (sa *SignalsApplication) ProtectedResourceMetadata(w http.ResponseWriter, r *http.Request) {
	ProtectedResourceMetadataHandler(sa, w, r)
}

func ProtectedResourceMetadataHandler(sa SsfApplicationInterface, w http.ResponseWriter, _ *http.Request) {
	serverLog.Debug("GET ProtectedResourceMetadata")
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")

	baseUrl := sa.GetBaseUrl()
	var baseURl string
	if baseUrl != nil {
		baseURl = baseUrl.String()
	}
	name := "GoSignals"
	prMeta := model.ProtectedResourceMetadata{
		Resource:               &baseURl,
		AuthorizationServers:   sa.GetAuth().GetOAuthServers(),
		ScopesSupported:        []string{authSupport.ScopeEventDelivery, authSupport.ScopeStreamMgmt, authSupport.ScopeStreamAdmin, authSupport.ScopeEventDelivery, authSupport.ScopeRegister},
		BearerMethodsSupported: []string{"header"},
		ResourceName:           &name,
	}

	resp, _ := json.MarshalIndent(prMeta, "", "  ")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(resp)
}

// ListStreamStates lists all stream states associated with the current project.
//
// Inputs:
//   - Authorization (header): Token with 'admin' or 'root' scope.
//
// Return values:
//   - 200 OK: JSON array of StreamStateRecord objects.
//
// Errors:
//   - 401/403: Unauthorized access.
//   - 500 Internal Server Error: Error marshaling response.
func (sa *SignalsApplication) ListStreamStates(w http.ResponseWriter, r *http.Request) {
	ListStreamStatesHandler(sa, w, r)
}

func ListStreamStatesHandler(sa SsfApplicationInterface, w http.ResponseWriter, r *http.Request) {
	authCtx, status := sa.GetAuth().ValidateAuthorizationAny(r, []string{authSupport.ScopeStreamAdmin, authSupport.ScopeRoot})
	if status != http.StatusOK {
		w.WriteHeader(status)
		return
	}
	projectId := authCtx.ProjectId
	mapStreams := sa.GetProvider().GetStateMap()
	result := make([]model.StreamStateRecord, 0)
	for _, stream := range mapStreams {
		if projectId == "" || stream.ProjectId == projectId {
			result = append(result, adjustStateBaseUrl(sa, stream))
		}
	}

	serverLog.Debug("ListStreamStates:", "returned", len(result))

	resp, err := json.Marshal(result)
	if err != nil {
		serverLog.Error("Internal error ListStreamStates:", "error", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(resp)
}

// GetStreamState retrieves a specific stream state by stream ID.
//
// Inputs:
//   - Authorization (header): Token with 'admin' or 'root' scope, must contain the stream ID.
//
// Return values:
//   - 200 OK: JSON object of the StreamStateRecord.
//
// Errors:
//   - 400 Bad Request: Missing stream ID in authorization.
//   - 401/403: Unauthorized access.
//   - 404 Not Found: Stream not found.
//   - 500 Internal Server Error: Error marshaling response.
func (sa *SignalsApplication) GetStreamState(w http.ResponseWriter, r *http.Request) {
	GetStreamStateHandler(sa, w, r)
}

func GetStreamStateHandler(sa SsfApplicationInterface, w http.ResponseWriter, r *http.Request) {
	authCtx, status := sa.GetAuth().ValidateAuthorizationAny(r, []string{authSupport.ScopeStreamAdmin, authSupport.ScopeRoot})
	if status != http.StatusOK {
		w.WriteHeader(status)
		return
	}

	if authCtx.StreamId == "" {
		// The authorization and request had no streamId detected
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	config, err := sa.GetProvider().GetStreamState(authCtx.StreamId)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	serverLog.Debug("GetStreamState:", "returned", config.StreamConfiguration.Id)

	resp, err := json.Marshal(config)
	if err != nil {
		serverLog.Error("Internal error GetStreamState:", "error", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(resp)
}

func maskAuthorization(authHeader string) string {
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 {
		return "Invalid authorization header"
	}

	authType := parts[0]
	token := parts[1]

	if len(token) <= 8 {
		return authType + " [TOO SHORT]"
	}

	// Masking: Type + first 4 + ... + last 4
	masked := fmt.Sprintf("%s %s...%s",
		authType,
		token[:4],
		token[len(token)-4:])

	return masked
}

// CreateServer creates a new server configuration for the current project.
//
// Inputs:
//   - Authorization (header): Token with 'register' or 'admin' scope.
//   - Request body (JSON): Server object details.
//
// Return values:
//   - 201 Created: JSON object of the created Server.
//
// Errors:
//   - 400 Bad Request: Error decoding request body or creating server.
//   - 401/403: Unauthorized access.
//   - 409 Conflict: Server alias already exists.
func (sa *SignalsApplication) CreateServer(w http.ResponseWriter, r *http.Request) {
	CreateServerHandler(sa, w, r)
}

func CreateServerHandler(sa SsfApplicationInterface, w http.ResponseWriter, r *http.Request) {
	authCtx, status := sa.GetAuth().ValidateAuthorizationAny(r, []string{authSupport.ScopeRegister, authSupport.ScopeStreamAdmin})
	if status != http.StatusOK {
		w.WriteHeader(status)
		return
	}

	var server model.Server
	err := json.NewDecoder(r.Body).Decode(&server)
	if err != nil {
		http.Error(w, "Error decoding request body", http.StatusBadRequest)
		return
	}

	server.ProjectId = authCtx.ProjectId

	err = sa.GetProvider().CreateServer(r.Context(), &server)
	if err != nil {
		if errors.Is(err, services.ErrServerAlreadyExists) {
			http.Error(w, "Server alias already exists", http.StatusConflict)
			return
		}
		serverLog.Error("Error creating server", "error", err)
		http.Error(w, "Error creating server: "+err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(server)
}

// ServerGet retrieves server configuration by its alias.
//
// Inputs:
//   - alias (path): The unique alias for the server.
//   - Authorization (header): Token with 'register' or 'admin' scope.
//
// Return values:
//   - 200 OK: JSON object of the Server configuration.
//
// Errors:
//   - 401/403: Unauthorized access or project mismatch.
//   - 404 Not Found: Server not found.
//   - 500 Internal Server Error: Database error.
func (sa *SignalsApplication) ServerGet(w http.ResponseWriter, r *http.Request) {
	GetServerHandler(sa, w, r)
}

func GetServerHandler(sa SsfApplicationInterface, w http.ResponseWriter, r *http.Request) {
	authCtx, status := sa.GetAuth().ValidateAuthorizationAny(r, []string{authSupport.ScopeRegister, authSupport.ScopeStreamAdmin})
	if status != http.StatusOK {
		w.WriteHeader(status)
		return
	}

	vars := mux.Vars(r)
	rawAlias := vars["alias"]
	alias, _ := url.QueryUnescape(rawAlias)

	server, err := sa.GetProvider().GetServerByAlias(r.Context(), alias)
	if err != nil {
		if errors.Is(err, interfaces.ErrNotFound) || err.Error() == "not found" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if authCtx.ProjectId != "" && server.ProjectId != authCtx.ProjectId {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(server)
}

// ServerUpdate updates an existing server configuration by its alias.
//
// Inputs:
//   - alias (path): The unique alias for the server.
//   - Authorization (header): Token with 'register' or 'admin' scope.
//   - Request body (JSON): Updated Server object details.
//
// Return values:
//   - 200 OK: JSON object of the updated Server configuration.
//
// Errors:
//   - 400 Bad Request: Error decoding request body.
//   - 401/403: Unauthorized access or project mismatch.
//   - 404 Not Found: Server not found.
//   - 409 Conflict: New server alias already exists.
//   - 500 Internal Server Error: Database error or update failure.
func (sa *SignalsApplication) ServerUpdate(w http.ResponseWriter, r *http.Request) {
	UpdateServerHandler(sa, w, r)
}

func UpdateServerHandler(sa SsfApplicationInterface, w http.ResponseWriter, r *http.Request) {
	authCtx, status := sa.GetAuth().ValidateAuthorizationAny(r, []string{authSupport.ScopeRegister, authSupport.ScopeStreamAdmin})
	if status != http.StatusOK {
		w.WriteHeader(status)
		return
	}

	vars := mux.Vars(r)
	rawAlias := vars["alias"]
	alias, _ := url.QueryUnescape(rawAlias)

	// Find the existing server
	existing, err := sa.GetProvider().GetServerByAlias(r.Context(), alias)
	if err != nil {
		if errors.Is(err, interfaces.ErrNotFound) || err.Error() == "not found" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if authCtx.ProjectId != "" && existing.ProjectId != authCtx.ProjectId {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	var server model.Server
	err = json.NewDecoder(r.Body).Decode(&server)
	if err != nil {
		http.Error(w, "Error decoding request body", http.StatusBadRequest)
		return
	}

	// Ensure we are updating the right one
	server.Id = existing.Id
	server.ProjectId = existing.ProjectId // Don't allow changing project id via update

	err = sa.GetProvider().UpdateServer(r.Context(), &server)
	if err != nil {
		if errors.Is(err, services.ErrServerAlreadyExists) {
			http.Error(w, "Server alias already exists", http.StatusConflict)
			return
		}
		serverLog.Error("Error updating server", "error", err)
		http.Error(w, "Error updating server: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(server)
}

// ServerDelete deletes a server configuration by its alias.
//
// Inputs:
//   - alias (path): The unique alias for the server.
//   - Authorization (header): Token with 'register' or 'admin' scope.
//
// Return values:
//   - 204 No Content: Server successfully deleted.
//
// Errors:
//   - 401/403: Unauthorized access or project mismatch.
//   - 404 Not Found: Server not found.
//   - 500 Internal Server Error: Database error or deletion failure.
func (sa *SignalsApplication) ServerDelete(w http.ResponseWriter, r *http.Request) {
	DeleteServerHandler(sa, w, r)
}

func DeleteServerHandler(sa SsfApplicationInterface, w http.ResponseWriter, r *http.Request) {
	authCtx, status := sa.GetAuth().ValidateAuthorizationAny(r, []string{authSupport.ScopeRegister, authSupport.ScopeStreamAdmin})
	if status != http.StatusOK {
		w.WriteHeader(status)
		return
	}

	vars := mux.Vars(r)
	rawAlias := vars["alias"]
	alias, _ := url.QueryUnescape(rawAlias)

	existing, err := sa.GetProvider().GetServerByAlias(r.Context(), alias)
	if err != nil {
		if errors.Is(err, interfaces.ErrNotFound) || err.Error() == "not found" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if authCtx.ProjectId != "" && existing.ProjectId != authCtx.ProjectId {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	err = sa.GetProvider().DeleteServer(r.Context(), existing.Id.Hex())
	if err != nil {
		serverLog.Error("Error deleting server", "error", err)
		http.Error(w, "Error deleting server: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ServerList lists all server configurations associated with the current project.
//
// Inputs:
//   - Authorization (header): Token with 'register' or 'admin' scope.
//
// Return values:
//   - 200 OK: JSON array of Server objects.
//
// Errors:
//   - 401/403: Unauthorized access.
//   - 500 Internal Server Error: Database error.
func (sa *SignalsApplication) ServerList(w http.ResponseWriter, r *http.Request) {
	ListServerHandler(sa, w, r)
}

func ListServerHandler(sa SsfApplicationInterface, w http.ResponseWriter, r *http.Request) {
	authCtx, status := sa.GetAuth().ValidateAuthorizationAny(r, []string{authSupport.ScopeRegister, authSupport.ScopeStreamAdmin})
	if status != http.StatusOK {
		w.WriteHeader(status)
		return
	}

	servers, err := sa.GetProvider().ListServers(r.Context())
	if err != nil {
		serverLog.Error("Error listing servers", "error", err)
		http.Error(w, "Error listing servers: "+err.Error(), http.StatusInternalServerError)
		return
	}

	result := make([]model.Server, 0)
	for _, s := range servers {
		if authCtx.ProjectId == "" || s.ProjectId == authCtx.ProjectId {
			result = append(result, s)
		}
	}

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(result)
}
