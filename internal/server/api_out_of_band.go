// Package server - Stream Management API for OpenID Shared Security Events
// "API Out of band" is for administrative tasks not directly part of the SSF spec or specifically with stream management.
package server

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/MicahParks/keyfunc/v2"
	"github.com/gorilla/mux"
	"github.com/i2-open/i2goSignals/internal/authUtil"
	"github.com/i2-open/i2goSignals/internal/dao/interfaces"
	"github.com/i2-open/i2goSignals/internal/services"
	"github.com/i2-open/i2goSignals/pkg/authSupport"
	"github.com/i2-open/i2goSignals/pkg/goSet"
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
	rawIssuer := vars["keyName"]
	if rawIssuer == "" {
		rawIssuer = vars["issuer"]
	}
	issuer, _ := url.QueryUnescape(rawIssuer)

	issuerKey, kid, err := sa.GetKeyService().RotateKey(r.Context(), issuer, authCtx.ProjectId)
	if err != nil {
		serverLog.Error(fmt.Sprintf("Error rotating issuer keys for issuer %s: %v", issuer, err))
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// If the rotated issuer is the token issuer, update the application's AuthIssuer
	if sa.GetAuth() != nil && sa.GetAuth().TokenIssuer == issuer {
		sa.GetAuth().UpdateTokenKey(issuer, kid, issuerKey, sa.GetKeyService().GetAuthValidatorPubKey())
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

// CreateKey handles the creation or uploading of a JWK key pair for the specified keyName.
// If a payload is present in the request body, the key is loaded from the payload.
// If no payload is present, a new key pair is generated for the specified keyName.
//
// Inputs:
//   - keyName (path): The name of the key to create or load.
//
// Return values:
//   - 201 Created: (If generating) PEM-encoded private key.
//   - 200 OK: (If loading or rotating) PEM-encoded private key or success message.
func (sa *SignalsApplication) CreateKey(w http.ResponseWriter, r *http.Request) {
	CreateKeyHandler(sa, w, r)
}

func CreateKeyHandler(sa SsfApplicationInterface, w http.ResponseWriter, r *http.Request) {
	// Key creation accepts the narrow "key" scope in addition to stream_admin/root.
	// The "key" scope is CREATE-ONLY: a key-scoped caller may mint a NEW issuer
	// signing key but is denied takeover operations (force=replace/rotate). That
	// guard is enforced below once the requested operation is known.
	authCtx, stat := sa.GetAuth().ValidateAuthorizationAny(r, []string{authSupport.ScopeKey, authSupport.ScopeStreamAdmin, authSupport.ScopeRoot})
	if stat != http.StatusOK || authCtx == nil {
		http.Error(w, "Invalid permission", http.StatusForbidden)
		return
	}

	// A key-scope-only caller (no admin/root) may not perform a takeover.
	if keyScopeOnly(authCtx) && requestIsKeyTakeover(r) {
		http.Error(w, "key scope is create-only; force=replace/rotate is not permitted", http.StatusForbidden)
		return
	}

	// Read body to check for payload
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Error reading request body", http.StatusBadRequest)
		return
	}

	if len(body) > 0 {
		// The "key" scope is create-only and server-generated. A key-scope-only
		// (bootstrap) caller may NOT upload caller-supplied key material: a
		// non-empty body routes to loadKeyHandler, which would install an issuer
		// signing key of the caller's choosing (private PEM or external jwks_uri)
		// for a brand-new issuer with no force/rotate required — enabling SET
		// forgery under that issuer. Uploading requires stream_admin/root, the
		// same scope LoadKeyHandler enforces.
		if keyScopeOnly(authCtx) {
			http.Error(w, "key scope is create-only; uploading key material requires stream_admin/root", http.StatusForbidden)
			return
		}
		loadKeyHandler(sa, w, r, authCtx, body)
	} else {
		createKeyByNameHandler(sa, w, r, authCtx)
	}
}

// keyScopeOnly reports whether the AuthContext carries the narrow "key" scope
// but NOT a broader stream_admin/root capability. Such a caller is a bootstrap
// identity and is restricted to create-only key operations.
func keyScopeOnly(authCtx *authUtil.AuthContext) bool {
	if authCtx == nil || authCtx.Eat == nil {
		return false
	}
	if authCtx.Eat.IsScopeMatch([]string{authSupport.ScopeStreamAdmin}) ||
		authCtx.Eat.IsScopeMatch([]string{authSupport.ScopeRoot}) {
		return false
	}
	return authCtx.Eat.IsScopeMatch([]string{authSupport.ScopeKey})
}

// requestIsKeyTakeover reports whether the key request asks to replace or rotate
// an existing key (force=replace / force=rotate / ?rotate). These are denied for
// key-scope-only callers to prevent key takeover and event forgery.
func requestIsKeyTakeover(r *http.Request) bool {
	q := r.URL.Query()
	force := q.Get("force")
	if force == "replace" || force == "rotate" {
		return true
	}
	if _, rotate := q["rotate"]; rotate {
		return true
	}
	return false
}

func createKeyByNameHandler(sa SsfApplicationInterface, w http.ResponseWriter, r *http.Request, authCtx *authUtil.AuthContext) {
	vars := mux.Vars(r)
	rawKeyName := vars["keyName"]
	if rawKeyName == "" {
		rawKeyName = vars["issuer"]
	}
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")

	keyName, err := url.QueryUnescape(rawKeyName)
	if err != nil {
		serverLog.Warn(fmt.Sprintf("Error unescaping keyName %s: %v", rawKeyName, err))
		http.Error(w, "Error malformed keyName encoding", http.StatusBadRequest)
		return
	}

	queryParams := r.URL.Query()
	force := queryParams.Get("force")
	_, rotate := queryParams["rotate"]

	// Check if key already exists
	if checkKeyNameExists(sa, keyName) {
		if force == "" && !rotate {
			http.Error(w, "Key already exists. Use query parameter force=replace or force=rotate", http.StatusConflict)
			return
		}

		if force == "rotate" || rotate {
			RotateIssuerHandler(sa, w, r, authCtx)
			return
		}

		if force == "replace" {
			err := sa.GetKeyService().DeleteKeysByName(r.Context(), keyName)
			if err != nil && !errors.Is(err, interfaces.ErrKeyNotFound) {
				serverLog.Error(fmt.Sprintf("Error deleting existing keys for %s: %v", keyName, err))
				http.Error(w, "Error replacing existing keys", http.StatusInternalServerError)
				return
			}
		}
	}

	issuerKey, err := sa.GetKeyService().CreateKeyPair(r.Context(), keyName, "sig", authCtx.ProjectId)
	if err != nil {
		serverLog.Error(fmt.Sprintf("Error generating private key for issuer %s: %v", keyName, err))
		http.Error(w, "Error generating private key", http.StatusInternalServerError)
		return
	}

	// If the created issuer is the token issuer, update the application's AuthIssuer
	if sa.GetAuth() != nil && sa.GetAuth().TokenIssuer == keyName {
		sa.GetAuth().UpdateTokenKey(keyName, keyName, issuerKey, sa.GetKeyService().GetAuthValidatorPubKey())
	}

	pkcs8bytes, err := x509.MarshalPKCS8PrivateKey(issuerKey)
	if err != nil {
		serverLog.Error(fmt.Sprintf("Error marshaling private key for issuer %s: %v", keyName, err))
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
		serverLog.Error(fmt.Sprintf("Error writing response for issuer %s: %v", keyName, err))
	}
	return
}

// LoadKey handles the uploading of a public or private key for a specified issuer.
//
// Inputs:
//   - issuer (path): The name of the issuer for which to load the key. This will become the kid in the certificates and matches certificate 'iss' values.
//   - force (query): Optional. If 'replace', all existing keys for the issuer are deleted before adding the new key.
//     If 'rotate', a new unique kid is generated and added to the set of keys for the issuer.
//   - use (query): Optional. Specifies the intended use of the key. Acceptable values are 'sig' (signing) or 'enc' (encryption). Defaults to 'sig'.
//   - Content-Type (header): Must be one of 'application/x-pem-file', 'application/pkix-cert', or 'application/pkcs7-mime'.
//   - Request body: The key data in PEM or DER format.
//
// Return values:
//   - 200 OK: Key successfully loaded and saved.
//
// Errors:
//   - 400 Bad Request: Error reading body, invalid PEM data, invalid certificate, or unsupported key type.
//   - 403 Forbidden: Invalid permissions.
//   - 409 Conflict: Key already exists without force parameter.
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
	body, err := io.ReadAll(request.Body)
	if err != nil {
		http.Error(writer, "Error reading request body", http.StatusBadRequest)
		return
	}
	loadKeyHandler(sa, writer, request, authCtx, body)
}

func CreateKeyNameHandler(sa SsfApplicationInterface, w http.ResponseWriter, r *http.Request) {
	authCtx, stat := sa.GetAuth().ValidateAuthorizationAny(r, []string{authSupport.ScopeStreamAdmin, authSupport.ScopeRoot})
	if stat != http.StatusOK || authCtx == nil {
		http.Error(w, "Invalid permission", http.StatusForbidden)
		return
	}
	createKeyByNameHandler(sa, w, r, authCtx)
}

func loadKeyHandler(sa SsfApplicationInterface, writer http.ResponseWriter, request *http.Request, authCtx *authUtil.AuthContext, body []byte) {
	ctx := request.Context()
	vars := mux.Vars(request)
	rawKeyName := vars["keyName"]
	if rawKeyName == "" {
		rawKeyName = vars["issuer"]
	}
	keyName, _ := url.QueryUnescape(rawKeyName)
	queryParams := request.URL.Query()
	force := queryParams.Get("force")

	if checkKeyNameExists(sa, keyName) && force == "" {
		http.Error(writer, "Key already exists. Use query parameter force=replace or force=rotate", http.StatusConflict)
		return
	}

	contentType := strings.Split(request.Header.Get("Content-Type"), ";")[0]
	contentType = strings.TrimSpace(contentType)

	var priv *rsa.PrivateKey
	var pub *rsa.PublicKey

	switch contentType {
	case "application/json":
		// in this case we are expecting a JSON struct with
		type requestType struct {
			JwksUri  string `json:"jwks_uri"`
			Use      string `json:"use"`
			StreamId string `json:"stream_id"`
		}
		var request requestType
		err := json.Unmarshal(body, &request)
		if err != nil {
			http.Error(writer, "Error parsing JSON request body", http.StatusBadRequest)
			return
		}

		if request.JwksUri == "" {
			http.Error(writer, "Missing required parameter jwksUri", http.StatusBadRequest)
			return
		}
		jwksExtern, err := goSet.GetJwks(request.JwksUri)
		if err != nil {
			msg := fmt.Sprintf("Error getting jwks for keyName %s: %v", keyName, err)
			http.Error(writer, msg, http.StatusBadRequest)
		}

		use := "sig"
		if request.Use != "" {
			use = request.Use
		}

		err = sa.GetKeyService().StoreExternalKey(ctx, keyName, jwksExtern.KIDs(), request.StreamId, use, request.JwksUri)
		if err != nil {
			msg := fmt.Sprintf("Error storing keyName %s: %v", keyName, err)
			http.Error(writer, msg, http.StatusInternalServerError)
			return
		}
		writer.WriteHeader(http.StatusOK)
		return

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

	kid := ""
	if force == "replace" {
		err := sa.GetKeyService().DeleteKeysByName(ctx, keyName)
		if err != nil && !errors.Is(err, interfaces.ErrKeyNotFound) {
			serverLog.Error(fmt.Sprintf("Error deleting existing keys for %s: %v", keyName, err))
			http.Error(writer, "Error replacing existing keys", http.StatusInternalServerError)
			return
		}
	} else if force == "rotate" {
		kid = fmt.Sprintf("%s-%s", keyName, bson.NewObjectID().Hex())
	}

	use := queryParams.Get("use")
	if use == "" {
		use = "sig"
	} else if use != "sig" && use != "enc" {
		http.Error(writer, "Invalid use parameter", http.StatusBadRequest)
		return
	}

	err := sa.GetKeyService().AddKey(ctx, keyName, use, kid, priv, pub, authCtx.ProjectId)
	if err != nil {
		http.Error(writer, "Error saving key", http.StatusInternalServerError)
		return
	}

	// If the loaded issuer is the token issuer, update the application's AuthIssuer
	if sa.GetAuth() != nil && sa.GetAuth().TokenIssuer == keyName && priv != nil {
		// Update the kid for the token issuer if not set
		if kid == "" {
			kid = keyName
		}
		sa.GetAuth().UpdateTokenKey(keyName, kid, priv, sa.GetKeyService().GetAuthValidatorPubKey())
	}

	writer.WriteHeader(http.StatusOK)
}

// DeleteKey deletes the keys associated with a specified issuer.
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
func (sa *SignalsApplication) DeleteKey(w http.ResponseWriter, r *http.Request) {
	DeleteJwksIssuerKeyHandler(sa, w, r)
}

func DeleteJwksIssuerKeyHandler(sa SsfApplicationInterface, w http.ResponseWriter, r *http.Request) {
	authCtx, stat := sa.GetAuth().ValidateAuthorizationAny(r, []string{authSupport.ScopeStreamAdmin, authSupport.ScopeRoot})
	if stat != http.StatusOK || authCtx == nil {
		http.Error(w, "Invalid permission", http.StatusForbidden)
		return
	}
	vars := mux.Vars(r)
	rawKeyName := vars["keyName"]
	if rawKeyName == "" {
		rawKeyName = vars["issuer"]
	}
	keyName, _ := url.QueryUnescape(rawKeyName)
	err := sa.GetKeyService().DeleteKeysByName(r.Context(), keyName)
	if err != nil {
		serverLog.Error("Error deleting keys for keyName", keyName, err.Error())
		if errors.Is(err, interfaces.ErrKeyNotFound) {
			http.Error(w, "Key not found", http.StatusNotFound)
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
	serverLog.Debug("IssuerProjectIatHandler called", "remoteAddr", r.RemoteAddr)
	// Honor the validation status. /iat accepts {key, stream_admin, root}. A
	// missing/invalid bearer (including the now-removed anonymous path) is
	// rejected, so an unset bootstrap secret fails closed. The minted IAT is
	// always reg-only — the key/admin capability does not propagate.
	authCtx, stat := sa.GetAuth().ValidateAuthorizationAny(r, []string{authSupport.ScopeKey, authSupport.ScopeStreamAdmin, authSupport.ScopeRoot})
	if stat != http.StatusOK || authCtx == nil {
		http.Error(w, "Invalid bootstrap or administrative token", stat)
		return
	}
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
//   - Request body (JSON): RegisterParameters containing Email, Description, and Roles.
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
	authHeader := r.Header.Get("Authorization")
	serverLog.Debug("RegisterClientHandler", "authHeader", authHeader)
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

	// Privilege ceiling: a reg (IAT) caller may not self-grant stream_admin at
	// /register. A self-registration caps at stream_mgmt + event_delivery; an
	// admin client is provisioned out of band, not via the registration door.
	var scopes []string
	if len(jsonRequest.Scopes) == 0 {
		scopes = append(scopes, authSupport.ScopeStreamMgmt, authSupport.ScopeEventDelivery)
	} else {
		for _, v := range jsonRequest.Scopes {
			switch v {
			case authSupport.ScopeStreamMgmt, authSupport.ScopeEventDelivery:
				scopes = append(scopes, v)
			default:
				// stream_admin and any unknown scope are silently dropped — a reg
				// token cannot escalate its own privilege.
			}
		}
		// An explicit, non-empty scope list that filters entirely to empty (every
		// entry above the ceiling or unknown) is refused rather than silently
		// falling back to the default — a caller asking only for above-ceiling
		// scopes may be attempting privilege escalation (WARN-worthy).
		if len(scopes) == 0 {
			serverLog.Warn("RegisterClient: refusing registration; all requested scopes were dropped", "requestedScopes", jsonRequest.Scopes)
			http.Error(w, "None of the requested scopes can be granted", http.StatusBadRequest)
			return
		}
	}

	client := model.SsfClient{
		ProjectIds:    []string{authCtx.ProjectId},
		Email:         jsonRequest.Email,
		Description:   jsonRequest.Description,
		AllowedScopes: scopes,
		Id:            bson.NewObjectID(),
	}

	// The redeemed IAT's JTI is this client token's lineage parent (ADR 0007).
	parentJTI := ""
	if authCtx.Eat != nil {
		parentJTI = authCtx.Eat.ID
	}

	response := sa.GetClientService().RegisterClient(r.Context(), client, authCtx.ProjectId, parentJTI)
	if response == nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Best-effort IAT redemption capture: a /register call is a redemption of
	// the IAT (ADR 0007). A write failure logs at WARN and never blocks
	// registration, matching the TrackToken posture.
	if parentJTI != "" {
		remoteIP := model.BuildRemoteIPFromRequest(r).String()
		if err := sa.GetTokenService().RecordRedemption(r.Context(), parentJTI, remoteIP, time.Now().UTC()); err != nil {
			serverLog.Warn("RegisterClient: failed to record IAT redemption", "jti", parentJTI, "error", err)
		}
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

func TriggerEventHandler(sa SsfApplicationInterface, w http.ResponseWriter, r *http.Request) {
	authCtx, status := sa.GetAuth().ValidateAuthorizationAny(r, []string{authSupport.ScopeStreamAdmin, authSupport.ScopeRoot})
	if status != http.StatusOK {
		w.WriteHeader(status)
		return
	}

	var req struct {
		StreamID  string         `json:"stream_id"`
		EventType string         `json:"event_type"`
		Subject   map[string]any `json:"subject"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	state, err := sa.GetStreamService().GetStreamState(r.Context(), req.StreamID)
	if err != nil {
		http.Error(w, "Stream not found", http.StatusNotFound)
		return
	}

	if authCtx.ProjectId != "" && state.ProjectId != authCtx.ProjectId {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	subject := &goSet.EventSubject{}
	if sub, ok := req.Subject["sub"].(string); ok {
		subject.Sub = sub
	} else {
		// Try to marshal back to SubjectIdentifier
		subBytes, _ := json.Marshal(req.Subject)
		_ = json.Unmarshal(subBytes, &subject.SubjectIdentifier)
	}

	set := goSet.CreateSet(subject, state.Iss, state.Aud)
	set.AddEventPayload(req.EventType, nil)

	// HandleEvent(eventToken *goSet.SecurityEventToken, rawEvent string, sid string) error
	if err := sa.GetEventRouter().HandleEvent(&set, "", state.Id.Hex()); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusOK)
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
	prMeta := buildProtectedResourceMetadata(baseURl, sa.GetAuth().GetOAuthServers(), cliClientId())

	resp, _ := json.MarshalIndent(prMeta, "", "  ")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(resp)
}

// cliClientId resolves the recommended public OAuth client_id advertised to
// interactive clients (the goSignals CLI). Sourced from I2SIG_CLI_CLIENT_ID,
// defaulting to "gosignals-cli".
func cliClientId() string {
	if v := os.Getenv("I2SIG_CLI_CLIENT_ID"); v != "" {
		return v
	}
	return "gosignals-cli"
}

// buildProtectedResourceMetadata assembles RFC9728 metadata. It advertises the
// configured authorization_servers, the recommended public CLI client_id, and
// the scopes supported by the server (including the narrow "key" scope).
func buildProtectedResourceMetadata(baseUrl string, authServers []string, cliClient string) model.ProtectedResourceMetadata {
	name := "GoSignals"
	res := baseUrl
	meta := model.ProtectedResourceMetadata{
		Resource:               &res,
		AuthorizationServers:   authServers,
		ScopesSupported:        []string{authSupport.ScopeEventDelivery, authSupport.ScopeStreamMgmt, authSupport.ScopeStreamAdmin, authSupport.ScopeRegister, authSupport.ScopeKey},
		BearerMethodsSupported: []string{"header"},
		ResourceName:           &name,
	}
	if cliClient != "" {
		meta.ClientID = &cliClient
	}
	return meta
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
	mapStreams := sa.GetStreamService().GetStateMap(r.Context())
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

	config, err := sa.GetStreamService().GetStreamState(r.Context(), authCtx.StreamId)
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

	err = sa.GetServerService().CreateServer(r.Context(), &server)
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

	server, err := sa.GetServerService().GetServerByAlias(r.Context(), alias)
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
	existing, err := sa.GetServerService().GetServerByAlias(r.Context(), alias)
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

	err = sa.GetServerService().UpdateServer(r.Context(), &server)
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

	existing, err := sa.GetServerService().GetServerByAlias(r.Context(), alias)
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

	err = sa.GetServerService().DeleteServer(r.Context(), existing.Id.Hex())
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

	servers, err := sa.GetServerService().ListServers(r.Context())
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

// JwksJson returns the JSON Web Key Set (JWKS) for the default issuer.
//
// Return values:
//   - 200 OK: JWKS as a JSON object.
//
// Errors:
//   - 404 Not Found: Default issuer keys not found.
//   - 500 Internal Server Error: Database or serialization error.
func (sa *SignalsApplication) JwksJson(w http.ResponseWriter, r *http.Request) {
	JwksJsonHandler(sa, w, r)
}

func JwksJsonHandler(sa SsfApplicationInterface, w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")

	jsonKey := sa.GetKeyService().GetPublicJWKS(r.Context(), sa.GetDefIssuer())
	if jsonKey == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	keyBytes, err := jsonKey.MarshalJSON()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(keyBytes)
}

type IssuerResponse struct {
	Issuers []string `json:"issuers"`
}

func (sa *SignalsApplication) GetSummaries(w http.ResponseWriter, r *http.Request) {
	authCtx, stat := sa.GetAuth().ValidateAuthorizationAny(r, []string{authSupport.ScopeStreamAdmin, authSupport.ScopeRoot})
	if stat != http.StatusOK || authCtx == nil {
		if stat != http.StatusUnauthorized {
			w.WriteHeader(stat)
			return
		}
		w.WriteHeader(stat)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	summaries, err := sa.GetKeyService().ListSummaries(r.Context())
	if err != nil {
		serverLog.Warn("Error listing summaries", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	adjusted := make([]interfaces.KeySummary, len(summaries))
	for i, s := range summaries {
		adjusted[i] = s.AdjustBase(sa.BaseUrl)
	}

	resp, err := json.Marshal(adjusted)
	if err != nil {
		serverLog.Warn("Error marshalling summaries", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(resp)
}

// callerMayActOnProject implements the shared single-token project guard
// (ADR 0008). It reuses the ProjectScope derivation from the token service: an
// admin/root caller is unrestricted; every other caller may act only on tokens
// whose project matches its own AuthContext.ProjectId. A target with no tracked
// project (unknown JTI) is treated as out-of-scope for a confined caller, which
// the callers turn into a no-op (revoke) or active:false (introspect) without
// leaking existence.
func callerMayActOnProject(authCtx *authUtil.AuthContext, targetProjectID string) bool {
	var eat *authSupport.EventAuthToken
	if authCtx != nil {
		eat = authCtx.Eat
	}
	unrestricted, projectID := services.ProjectScope(eat)
	if unrestricted {
		return true
	}
	// Fail closed: a confined caller with no resolved project (OAuth client or
	// token with no ProjectId) may act on nothing; never match the empty-project
	// bucket. A confined caller may act only on a target in its own project.
	if projectID == "" {
		return false
	}
	return targetProjectID == projectID
}

// IntrospectHandler implements RFC7662 token introspection.
func (sa *SignalsApplication) IntrospectHandler(w http.ResponseWriter, r *http.Request) {
	// 1. Validate authorization (Relatively open) - should this be anyone?
	authCtx, status := sa.GetAuth().ValidateAuthorizationAny(r, []string{authSupport.ScopeRoot, authSupport.ScopeStreamAdmin, authSupport.ScopeStreamMgmt, authSupport.ScopeEventDelivery})
	if status != http.StatusOK || authCtx == nil {
		http.Error(w, "Unauthorized", status)
		return
	}

	// 2. Parse token from form
	token := r.FormValue("token")
	if token == "" {
		http.Error(w, "Missing token", http.StatusBadRequest)
		return
	}

	// 3. Extract JTI if it's a JWT, or use as is if it's an opaque JTI
	jti := token
	if claims, err := sa.GetAuth().ParseAuthTokenVerbose(token, false); err == nil && claims != nil {
		jti = claims.ID
	} else if peeked := authUtil.PeekJti(token); peeked != "" {
		jti = peeked
	}

	// 4. Project guard (ADR 0008): a non-admin caller may only introspect tokens
	// in its own project. A cross-project (or unknown) target is reported as
	// active:false rather than 403, so existence is not leaked.
	record, err := sa.GetTokenService().FindByJTI(r.Context(), jti)
	if err != nil {
		serverLog.Error("Introspection lookup error", "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	targetProject := ""
	if record != nil {
		targetProject = record.ProjectID
	}
	if !callerMayActOnProject(authCtx, targetProject) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(&model.IntrospectionResponse{Active: false})
		return
	}

	// 5. Introspect — build the response from the record already fetched for the
	// project guard (a nil record yields active:false), avoiding a second read.
	resp := services.IntrospectionFromRecord(record)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// RevokeHandler implements RFC 7009 token revocation for a token holder. The
// holder presents the token string in a `token` form field (with an
// accepted-but-ignored `token_type_hint`); the JTI is parsed from the JWT and
// revoked. Per RFC 7009 §2.2 the response is ALWAYS HTTP 200 — for an unknown,
// already-revoked, expired, unparseable, or cross-project-denied token — so the
// existence of a token is never leaked. Only a malformed request (no `token`
// parameter) is a 400.
func (sa *SignalsApplication) RevokeHandler(w http.ResponseWriter, r *http.Request) {
	authCtx, status := sa.GetAuth().ValidateAuthorizationAny(r, []string{authSupport.ScopeRoot, authSupport.ScopeStreamAdmin, authSupport.ScopeStreamMgmt, authSupport.ScopeEventDelivery})
	if status != http.StatusOK || authCtx == nil {
		http.Error(w, "Unauthorized", status)
		return
	}

	token := r.FormValue("token")
	if token == "" {
		http.Error(w, "Missing token", http.StatusBadRequest)
		return
	}
	// token_type_hint is accepted but ignored (RFC 7009 §2.1).

	// Parse the JTI from the JWT. An unverified peek is used so that an expired
	// or already-revoked token still yields its JTI; an unparseable token leaves
	// jti empty and the handler simply returns 200 without revoking.
	jti := ""
	if claims, err := sa.GetAuth().ParseAuthTokenVerbose(token, false); err == nil && claims != nil {
		jti = claims.ID
	} else if peeked := authUtil.PeekJti(token); peeked != "" {
		jti = peeked
	}

	if jti != "" {
		sa.revokeIfPermitted(r, authCtx, jti)
	}

	// RFC 7009 §2.2: always 200, regardless of outcome.
	w.WriteHeader(http.StatusOK)
}

// revokeIfPermitted applies the project guard then revokes by JTI. A
// cross-project (or unknown) target is a silent no-op so /revoke never leaks
// existence. Revocation failures are logged but never change the HTTP outcome.
func (sa *SignalsApplication) revokeIfPermitted(r *http.Request, authCtx *authUtil.AuthContext, jti string) {
	record, err := sa.GetTokenService().FindByJTI(r.Context(), jti)
	if err != nil {
		serverLog.Warn("Revoke lookup error", "jti", jti, "error", err)
		return
	}
	targetProject := ""
	if record != nil {
		targetProject = record.ProjectID
	}
	if !callerMayActOnProject(authCtx, targetProject) {
		// Cross-project or unknown: no-op, but still 200 (no leak).
		return
	}
	if err := sa.GetTokenService().RevokeToken(r.Context(), jti); err != nil {
		serverLog.Warn("Revocation error", "jti", jti, "error", err)
	}
}

// TokenRevokeHandler revokes a token by its JTI (admin path, DELETE /token/{jti}).
func (sa *SignalsApplication) TokenRevokeHandler(w http.ResponseWriter, r *http.Request) {
	authCtx, status := sa.GetAuth().ValidateAuthorizationAny(r, []string{authSupport.ScopeRoot, authSupport.ScopeStreamAdmin, authSupport.ScopeStreamMgmt})
	if status != http.StatusOK || authCtx == nil {
		http.Error(w, "Unauthorized", status)
		return
	}

	vars := mux.Vars(r)
	jti := vars["jti"]
	if jti == "" {
		http.Error(w, "Missing jti", http.StatusBadRequest)
		return
	}

	// Project guard (ADR 0008): a non-admin caller may only revoke tokens in its
	// own project. Unlike RFC 7009 /revoke, the admin-by-identifier path returns
	// 403 on a cross-project target (the admin acts from a table row and is
	// entitled to a clear authorization error).
	record, err := sa.GetTokenService().FindByJTI(r.Context(), jti)
	if err != nil {
		serverLog.Error("Revoke lookup error", "jti", jti, "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	targetProject := ""
	if record != nil {
		targetProject = record.ProjectID
	}
	if !callerMayActOnProject(authCtx, targetProject) {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	if err := sa.GetTokenService().RevokeToken(r.Context(), jti); err != nil {
		serverLog.Error("Revocation error", "jti", jti, "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// TokenListHandler returns a caller-scoped, enriched token inventory.
//
// Project scope is derived from the AuthContext, never from a query parameter:
// admin/root callers see all projects; every other authorized caller sees only
// its own project. Optional filters: type=IAT|STREAM and active=true|false
// (composable). STREAM-typed rows include the stream's last-seen IP, joined
// live from the stream's RemoteAddress.
func (sa *SignalsApplication) TokenListHandler(w http.ResponseWriter, r *http.Request) {
	authCtx, status := sa.GetAuth().ValidateAuthorizationAny(r, []string{authSupport.ScopeRoot, authSupport.ScopeStreamAdmin, authSupport.ScopeStreamMgmt})
	if status != http.StatusOK || authCtx == nil {
		http.Error(w, "Unauthorized", status)
		return
	}

	queryParams := r.URL.Query()

	filters := services.TokenListFilters{}
	switch typeParam := queryParams.Get("type"); typeParam {
	case "":
		// no type filter
	case model.TokenTypeIAT, model.TokenTypeStream:
		filters.Type = typeParam
	default:
		http.Error(w, "invalid type filter (expected IAT or STREAM)", http.StatusBadRequest)
		return
	}

	if activeParam := queryParams.Get("active"); activeParam != "" {
		active, err := strconv.ParseBool(activeParam)
		if err != nil {
			http.Error(w, "invalid active filter (expected true or false)", http.StatusBadRequest)
			return
		}
		filters.Active = &active
	}

	tokens, err := sa.GetTokenService().ListForAuthority(r.Context(), authCtx.Eat, filters)
	if err != nil {
		serverLog.Error("Token list error", "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(tokens)
}

// JwksIssuers lists all issuers that have JWKS available.
//
// Return values:
//   - 200 OK: JSON array of issuer names.
//
// Errors:
//   - 500 Internal Server Error: Database error.
func (sa *SignalsApplication) JwksIssuers(w http.ResponseWriter, r *http.Request) {
	JwksIssuersHandler(sa, w, r)
}

func JwksIssuersHandler(sa SsfApplicationInterface, w http.ResponseWriter, r *http.Request) {
	authCtx, stat := sa.GetAuth().ValidateAuthorizationAny(r, []string{authSupport.ScopeStreamAdmin, authSupport.ScopeRoot})
	if stat != http.StatusOK || authCtx == nil {
		if stat != http.StatusUnauthorized {
			w.WriteHeader(stat)
			return
		}
		w.WriteHeader(stat)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	names, _ := sa.GetKeyService().ListKeyNames(r.Context())
	issuerResponse := IssuerResponse{
		Issuers: names,
	}
	jsonIssuers, err := json.Marshal(issuerResponse)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(jsonIssuers)
}

// JwksJsonIssuer returns the JSON Web Key Set (JWKS) for a specific keyName.
//
// Inputs:
//   - issuer (path): The name of the issuer.
//   - format (query): Optional. If set to "pem", "x509", or "pkcs", returns the keys in that format instead of JWKS.
//
// Return values:
//   - 200 OK: JWKS as a JSON object, or keys in requested format.
//
// Errors:
//   - 400 Bad Request: Unsupported format requested.
//   - 404 Not Found: Issuer keys not found.
//   - 500 Internal Server Error: Database or conversion error.
func (sa *SignalsApplication) JwksJsonIssuer(w http.ResponseWriter, r *http.Request) {
	JwksJsonIssuerHandler(sa, w, r)
}

func JwksJsonIssuerHandler(sa SsfApplicationInterface, w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	rawKeyName := vars["keyName"]
	if rawKeyName == "" {
		rawKeyName = vars["issuer"]
	}
	keyName, _ := url.QueryUnescape(rawKeyName)
	jsonKey := sa.GetKeyService().GetPublicJWKS(r.Context(), keyName)
	if jsonKey == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	queryParams := r.URL.Query()
	respType, isFormat := queryParams["format"]
	if isFormat {
		resp, err := convertKey(jsonKey, respType[0])
		if err != nil {
			serverLog.Warn("Error converting key", "error", err.Error())
			http.Error(w, fmt.Sprintf("Error converting key: %v", err), http.StatusBadRequest)
			return
		}
		switch respType[0] {
		case "pem":
			w.Header().Set("Content-Type", "application/x-pem-file")
		case "x509":
			w.Header().Set("Content-Type", "application/pkix-cert")
		case "pkcs":
			w.Header().Set("Content-Type", "application/pkcs7-mime")
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(resp)
		return
	}

	// This is the normal JWKS response
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")

	keyBytes, err := jsonKey.MarshalJSON()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(keyBytes)
	return
}

func checkKeyNameExists(sa SsfApplicationInterface, keyName string) bool {
	// Check for existing key
	keyNames, _ := sa.GetKeyService().ListKeyNames(context.Background())
	return slices.Contains(keyNames, keyName)
}
