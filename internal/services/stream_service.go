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
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/MicahParks/keyfunc/v2"
	"github.com/i2-open/i2goSignals/internal/authUtil"
	"github.com/i2-open/i2goSignals/internal/dao/interfaces"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/httpSupport"
	"github.com/i2-open/i2goSignals/pkg/logger"
	"github.com/i2-open/i2goSignals/pkg/oauthClient"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/i2-open/i2goSignals/pkg/wellKnownSupport"
	"go.mongodb.org/mongo-driver/v2/bson"
)

var ssLog = logger.Sub("STREAM_SERVICE")

const CSubjectFmt = "opaque"
const ErrorInvalidProject = "invalid project_id - invalid token"
const ErrorInvalidDeliveryMethod = "cannot change delivery method"

type StreamService struct {
	streamDAO               interfaces.StreamDAO
	keyService              *KeyService
	defaultIssuer           string
	receiverStreams         map[string]*model.StreamStateRecord
	BaseUrl                 *url.URL
	mu                      sync.RWMutex
	minVerificationInterval int
	maxInactivityTimeout    int
}

func NewStreamService(streamDAO interfaces.StreamDAO, keyService *KeyService, defaultIssuer string) *StreamService {
	minVerificationInterval := 300
	maxInactivityTimeout := 3600
	var err error
	var baseUrl *url.URL
	base, exist := os.LookupEnv("BASE_URL")
	if exist {
		baseUrl, err = url.Parse(base)
		if err != nil {
			ssLog.Error("Invalid BASE_URL value", "error", err.Error())
		}
	}
	minVer, exist := os.LookupEnv("MIN_VERIFICATION_INTERVAL")
	if exist {
		minVerificationInterval, err = strconv.Atoi(minVer)
		if err != nil {
			minVerificationInterval = 300
			ssLog.Error("Invalid MIN_VERIFICATION_INTERVAL value", "error", err.Error())
		}
	}
	maxInactivityStr, exist := os.LookupEnv("MAX_INACTIVITY_TIMEOUT")
	if exist {
		maxInactivityTimeout, err = strconv.Atoi(maxInactivityStr)
		if err != nil {
			maxInactivityTimeout = 3600
			ssLog.Error("Invalid MAX_INACTIVITY_TIMEOUT value", "error", err.Error())
		}
	}
	return &StreamService{
		streamDAO:               streamDAO,
		keyService:              keyService,
		defaultIssuer:           defaultIssuer,
		receiverStreams:         make(map[string]*model.StreamStateRecord),
		BaseUrl:                 baseUrl,
		minVerificationInterval: minVerificationInterval,
		maxInactivityTimeout:    maxInactivityTimeout,
	}
}

func (s *StreamService) SetBaseUrl(u *url.URL) {
	s.BaseUrl = u
}

func (s *StreamService) getFullUrl(relativePath string) string {
	if s.BaseUrl == nil {
		return relativePath
	}
	u, err := s.BaseUrl.Parse(relativePath)
	if err != nil {
		ssLog.Error("failed to parse relative URL", "error", err, "relative", relativePath)
		return relativePath
	}
	return u.String()
}

func (s *StreamService) CreateStream(ctx context.Context, request model.StreamConfiguration, projectID string, txServer *model.Server) (model.StreamConfiguration, error) {
	mid := bson.NewObjectID()

	// var authCtx authUtil.AuthContext
	// authCtx = ctx.Value(authUtil.AuthContextKey).(authUtil.AuthContext)

	if logger.IsDebugEnabled() {
		ssLog.Debug("CreateStream dump:")
		fmt.Println("CreateStream", mid, "projectID", projectID)
		rbytes, err := json.MarshalIndent(request, "", "  ")
		if rbytes != nil {
			fmt.Println(string(rbytes))
		} else {
			fmt.Println("error", err)
		}
		if txServer != nil {
			fmt.Println("Tx Server:", txServer.Alias)
			rbytes, err = json.MarshalIndent(txServer, "", "  ")
			if rbytes != nil {
				fmt.Println(string(rbytes))
			} else {
				fmt.Println("error", err)
			}
		}
	}

	transmitAlias := ""
	if request.TxAlias != nil {
		transmitAlias = *request.TxAlias // take a copy so it is preserved.
	}
	transmitToken := ""
	if request.TxToken != nil {
		transmitToken = *request.TxToken
	}
	var config model.StreamConfiguration
	var pushAutoReg bool
	var defaultTxJwksUrl string
	var txConfig *model.TransmitterConfiguration
	var err error
	if request.Iss == "" {
		config.Iss = s.defaultIssuer
	} else {
		config.Iss = request.Iss
	}

	isOAuth := false
	if ctx.Value("authCtx") != nil {
		authCtx := ctx.Value("authCtx").(*authUtil.AuthContext)
		isOAuth = authCtx.IsOAuthClient
	}

	config.Id = mid.Hex()
	config.Aud = request.Aud

	config.EventsSupported = model.GetSupportedEvents()

	if len(request.EventsRequested) > 0 {
		config.EventsRequested = request.EventsRequested
		config.EventsDelivered = s.calculateDeliveredEvents(request.EventsRequested, config.EventsSupported)
	}

	delivery := request.Delivery
	config.RouteMode = request.RouteMode
	config.TxWellKnownUrl = request.TxWellKnownUrl
	if transmitAlias != "" {
		config.TxAlias = &transmitAlias
	}

	if transmitToken != "" {
		config.TxToken = &transmitToken
	}

	authIssuer := s.keyService.GetAuthIssuer()
	selectedTxServerParam := false
	if txServer != nil || (request.TxWellKnownUrl != nil && request.TxToken != nil && *request.TxToken != "" && *request.TxWellKnownUrl != "") {
		selectedTxServerParam = true
		if txServer == nil {
			selectedTxServerParam = false
			// In static token mode, we don't necessarily have a pre-defined server. Create one so we can use the new http client / credential handler
			txServer = &model.Server{
				Host:        *request.TxWellKnownUrl,
				ClientToken: request.TxToken,
			}
		}
		client := oauthClient.GetBaseHTTPClientForServer(txServer)
		// Retrieve the transmitter configuration from the WellKnownUrl
		txConfig, err = wellKnownSupport.FetchSSFConfiguration(ctx, client, txServer.Host)
		if err != nil {
			return model.StreamConfiguration{}, fmt.Errorf("failed to fetch transmitter configuration: %v", err)
		}
		if txConfig.ConfigurationEndpoint == "" {
			return model.StreamConfiguration{}, errors.New("transmitter configuration missing configuration_endpoint")
		}
		defaultTxJwksUrl = txConfig.JwksUri
	}

	switch delivery.GetMethod() {
	case model.DeliveryPush:
		config.Delivery = request.Delivery
		if request.RouteMode == "" {
			config.RouteMode = model.RouteModePublish // default is publish
		}

	case model.DeliveryPoll, "DEFAULT":
		authToken := ""
		if !isOAuth {
			authToken, err = authIssuer.IssueStreamToken(mid.Hex(), projectID, nil)
		}
		if err != nil {
			return model.StreamConfiguration{}, fmt.Errorf("failed to issue stream token: %v", err)
		}

		delivery := &model.OneOfStreamConfigurationDelivery{
			PollTransmitMethod: &model.PollTransmitMethod{
				Method:              model.DeliveryPoll,
				EndpointUrl:         s.getFullUrl(fmt.Sprintf("/poll/%s", mid.Hex())),
				AuthorizationHeader: "Bearer " + authToken,
			},
		}
		if request.RouteMode == "" {
			config.RouteMode = model.RouteModePublish // default is publish
		}
		config.Delivery = delivery

	case model.ReceivePush:
		// ReceivePush indicates this goSignals instance will receive events via a PUSH endpoint.
		// If a TxWellKnownUrl and TxToken are provided, create the receiver endpoints and then register with the SSF Transmitter.
		config.Delivery = request.Delivery
		if request.RouteMode == "" {
			config.RouteMode = model.RouteModeImport
		}
		method := config.Delivery.PushReceiveMethod
		method.EndpointUrl = s.getFullUrl(fmt.Sprintf("/events/%s", mid.Hex()))
		if !isOAuth {
			authToken, err := authIssuer.IssueStreamToken(mid.Hex(), projectID, nil)
			if err != nil {
				return model.StreamConfiguration{}, fmt.Errorf("failed to issue stream token: %v", err)
			}
			method.AuthorizationHeader = "Bearer " + authToken

		}
		if transmitAlias != "" {
			config.TxAlias = &transmitAlias // save TxAlias to support client credential flows
		}
		config.TxWellKnownUrl = request.TxWellKnownUrl
		if transmitToken != "" {
			config.TxToken = &transmitToken
		}

		// If a transmitter server (txServer) or well-known URL and token are provided, enable automatic registration.
		// TxAlias is used to link the created stream to a defined Transmitter Server for later credential recovery.
		if selectedTxServerParam || (request.TxWellKnownUrl != nil && *request.TxWellKnownUrl != "" && request.TxToken != nil && *request.TxToken != "") {
			pushAutoReg = true
		}

	case model.ReceivePoll:
		// ReceivePoll indicates this goSignals instance will poll an external SSF Transmitter for events.
		// If a TxWellKnownUrl and TxToken are provided, attempt to do an SSF registration to create the Polling Transmit Stream and then create the local receiver stream
		config.Delivery = request.Delivery
		if transmitAlias != "" {
			config.TxAlias = &transmitAlias // save TxAlias to support client credential flows
		}
		config.TxWellKnownUrl = request.TxWellKnownUrl
		if transmitToken != "" {
			config.TxToken = &transmitToken
		}

		config.TxWellKnownUrl = request.TxWellKnownUrl

		if selectedTxServerParam || (request.TxWellKnownUrl != nil && request.TxToken != nil && *request.TxToken != "" && *request.TxWellKnownUrl != "") {
			// Attempt to do an SSF registration to create the Polling Transmit Stream
			ssLog.Debug("Retrieving SSF transmitter configuration for automatic registration...")

			var client *http.Client
			var closeClient func()
			var err error
			var req *http.Request
			var resp *http.Response

			transmitStreamReq := model.StreamConfiguration{
				Iss:             request.Iss,
				Aud:             request.Aud,
				EventsRequested: request.EventsRequested,
				Description:     request.Description,
				Delivery: &model.OneOfStreamConfigurationDelivery{
					PollTransmitMethod: &model.PollTransmitMethod{
						Method: model.DeliveryPoll,
					},
				},
			}

			// Use GetClientForServer to handle OAuth Client Credentials or Static Token based on server configuration
			client, closeClient, err = oauthClient.GetClientForServer(ctx, txServer)
			if err != nil {
				return model.StreamConfiguration{}, fmt.Errorf("failed to get client for transmitter: %v", err)
			}
			defer closeClient()

			ssLog.Debug("Submitting POLL stream registration request to transmitter...")
			reqBody, err := json.Marshal(transmitStreamReq)
			if err != nil {
				return model.StreamConfiguration{}, fmt.Errorf("failed to marshal registration request: %v", err)
			}
			if txConfig == nil {
				ssLog.Warn("unexpected nil for transmitter configuration")
				return model.StreamConfiguration{}, errors.New("unexpected nil for transmitter configuration")
			}
			req, err = http.NewRequestWithContext(ctx, http.MethodPost, txConfig.ConfigurationEndpoint, bytes.NewReader(reqBody))
			if err != nil {
				return model.StreamConfiguration{}, err
			}
			req.Header.Set("Content-Type", "application/json")

			resp, err = client.Do(req)
			if err != nil {
				ssLog.Warn("failed to submit registration request to transmitter", "error", err)
				return model.StreamConfiguration{}, fmt.Errorf("failed to submit registration request to transmitter: %v", err)
			}
			defer httpSupport.HandleRespClose(resp)

			// parse the response and handle any errors. If they occur return a detailed error
			if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
				ssLog.Warn("transmitter registration failed", "host", txConfig.ConfigurationEndpoint, "status", resp.StatusCode)
				if resp.Body != nil {
					respBody, _ := io.ReadAll(resp.Body)
					if respBody != nil && len(respBody) > 4 { // if there is more than just empty json payload - log it
						ssLog.Info("transmitter registration failed response", "body", string(respBody))
					}
				}
				return model.StreamConfiguration{}, fmt.Errorf("transmitter registration failed with status %d", resp.StatusCode)
			}

			var txStreamResp model.StreamConfiguration
			if err := json.NewDecoder(resp.Body).Decode(&txStreamResp); err != nil {
				return model.StreamConfiguration{}, fmt.Errorf("failed to decode transmitter registration response: %v", err)
			}

			// from the response, update config.EventsDelivered with the transmitters response EventsDelivered
			config.EventsDelivered = txStreamResp.EventsDelivered
			config.TxWellKnownUrl = request.TxWellKnownUrl
			txId := txStreamResp.Id

			txIdPtr := txId
			config.RemoteStreamId = &txIdPtr

			if txStreamResp.Delivery != nil && txStreamResp.Delivery.PollTransmitMethod != nil {

				// Copy the authorization header for use at the Status and management endpoints
				txToken := txStreamResp.Delivery.PollTransmitMethod.AuthorizationHeader
				config.TxToken = &txToken // Use for status and verification endpoints
				config.Delivery.PollReceiveMethod.AuthorizationHeader = txStreamResp.Delivery.PollTransmitMethod.AuthorizationHeader
				config.Delivery.PollReceiveMethod.EndpointUrl = txStreamResp.Delivery.PollTransmitMethod.EndpointUrl
				config.Delivery.PollReceiveMethod.PollConfig = txStreamResp.Delivery.PollTransmitMethod.PollConfig // follow the Transmitters poll config if asserted
				if transmitAlias != "" {
					config.TxAlias = &transmitAlias // This is needed for client crecdential flow
				}
				config.RemoteStreamId = &txId

			} else {
				ssLog.Warn("transmitter configuration delivery is missing PollTransmitMethod information, receive creation aborted", "stream_id", config.Id, "transmitter_url", request.TxWellKnownUrl)
				return model.StreamConfiguration{}, errors.New("unexpected response did not include delivery information")
			}

			// Allow the request to override the Transmitters poll config if asserted
			if request.Delivery.PollReceiveMethod.PollConfig != nil {
				config.Delivery.PollReceiveMethod.PollConfig = request.Delivery.PollReceiveMethod.PollConfig
			}
			ssLog.Debug("Poll stream transmitter created.", "stream_id", config.Id)
		}

		method := config.Delivery.PollReceiveMethod

		if request.RouteMode == "" {
			config.RouteMode = model.RouteModeImport
		}

		if method.PollConfig == nil {
			// Set the default polling if missing
			config.Delivery.PollReceiveMethod.PollConfig = &model.PollParameters{
				MaxEvents:         1000,
				ReturnImmediately: false,
				TimeoutSecs:       10,
			}
		}
	}

	// Set the default values based on environment values
	config.InactivityTimeout = int32(s.maxInactivityTimeout)
	config.MinVerificationInterval = int32(s.minVerificationInterval)

	// It is not SSF compliant, but goSignals will accept these settings on stream creation
	if request.InactivityTimeout > 0 {
		config.InactivityTimeout = request.InactivityTimeout
	}
	if request.MinVerificationInterval > 0 {
		config.MinVerificationInterval = request.MinVerificationInterval
	}

	config.Description = request.Description

	config.Format = CSubjectFmt

	if request.IssuerJWKSUrl != "" {
		config.IssuerJWKSUrl = request.IssuerJWKSUrl
	} else if defaultTxJwksUrl != "" {
		ssLog.Debug("Configuring for JWKS Url based on transmitter discovery", "url", defaultTxJwksUrl)
		config.IssuerJWKSUrl = defaultTxJwksUrl
	} else {
		method := config.Delivery.GetMethod()
		if (method == model.ReceivePoll || method == model.ReceivePush) && config.Iss != "" {
			config.IssuerJWKSUrl = ""
			host := "unknown"
			if txServer != nil {
				host = txServer.Host
			} else if txConfig != nil {
				host = txConfig.JwksUri
			}
			ssLog.Warn("No issuer jwks_url value defined. SETs cannot be validated", "iss", config.Iss, "tx-host", host)
		}
	}

	now := time.Now()

	streamRec := &model.StreamStateRecord{
		Id:                  mid,
		ProjectId:           projectID,
		StreamConfiguration: config,
		StartDate:           now,
		Status:              model.StreamStateEnabled,
		CreatedAt:           now,
		ModifiedAt:          now,
	}

	err = s.streamDAO.Create(ctx, streamRec)
	if err != nil {
		return model.StreamConfiguration{}, err
	}
	ssLog.Info("Stream created", "id", streamRec.Id, "type", config.Delivery.GetMethod())

	// If this is a receiver stream, load its JWKS
	if streamRec.IsReceiver() {
		s.mu.Lock()
		s.receiverStreams[config.Id] = streamRec
		s.mu.Unlock()
		s.loadJwksForReceiver(ctx, streamRec)
		ssLog.Debug("Receiver started", "id", streamRec.Id)
	}

	// If automatic transmitter registration is requested for ReceivePush, do it now.
	// The stream is now active and in the DB.
	if pushAutoReg {
		ssLog.Debug("Retrieving SSF transmitter configuration for automatic registration...")

		var client *http.Client
		var closeClient func()
		var err error
		var req *http.Request
		var resp *http.Response

		// Use GetClientForServer to handle OAuth Client Credentials or Static Token based on server configuration
		client, closeClient, err = oauthClient.GetClientForServer(ctx, txServer)
		if err != nil {
			return model.StreamConfiguration{}, fmt.Errorf("failed to get client for transmitter: %v", err)
		}
		defer closeClient()

		method := streamRec.StreamConfiguration.Delivery.PushReceiveMethod
		endpoint := s.getFullUrl(method.EndpointUrl)

		remoteId := mid.Hex()
		// Using the returned configuration endpoint, form a stream create-request with model.DeliveryPush.
		transmitStreamReq := model.StreamConfiguration{
			Iss:             request.Iss,
			Aud:             request.Aud,
			EventsRequested: request.EventsRequested,
			Description:     request.Description,
			Delivery: &model.OneOfStreamConfigurationDelivery{
				PushTransmitMethod: &model.PushTransmitMethod{
					Method:              model.DeliveryPush,
					EndpointUrl:         endpoint,
					AuthorizationHeader: method.AuthorizationHeader,
				},
			},
			RemoteStreamId: &remoteId, // note: ssf servers will ignore
		}

		ssLog.Debug("Submitting PUSH stream registration request to transmitter...")

		// Submit the creation request to the transmitter's ConfigurationEndpoint.
		var reqBody []byte
		reqBody, err = json.Marshal(transmitStreamReq)
		if err != nil {
			if cleanupErr := s.DeleteStream(ctx, config.Id); cleanupErr != nil {
				ssLog.Error("failed to delete stream during cleanup", "id", config.Id, "error", cleanupErr)
			}
			return model.StreamConfiguration{}, fmt.Errorf("failed to marshal registration request: %v", err)
		}
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, txConfig.ConfigurationEndpoint, bytes.NewReader(reqBody))
		if err != nil {
			if cleanupErr := s.DeleteStream(ctx, config.Id); cleanupErr != nil {
				ssLog.Error("failed to delete stream during cleanup", "id", config.Id, "error", cleanupErr)
			}
			return model.StreamConfiguration{}, err
		}
		req.Header.Set("Content-Type", "application/json")

		// Note: authorization and TLS config is handled by the client previously defined
		resp, err = client.Do(req)
		if err != nil {
			ssLog.Error("failed to submit registration request to transmitter", "error", err)
			if cleanupErr := s.DeleteStream(ctx, config.Id); cleanupErr != nil {
				ssLog.Error("failed to delete stream during cleanup", "id", config.Id, "error", cleanupErr)
			}
			return model.StreamConfiguration{}, fmt.Errorf("failed to submit registration request to transmitter: %v", err)
		}
		defer httpSupport.HandleRespClose(resp)

		// parse the response and handle any errors. If they occur return a detailed error
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
			ssLog.Warn("transmitter registration failed", "host", txConfig.ConfigurationEndpoint, "status", resp.StatusCode)
			if cleanupErr := s.DeleteStream(ctx, config.Id); cleanupErr != nil {
				ssLog.Error("failed to delete stream during cleanup", "id", config.Id, "error", cleanupErr)
			}
			return model.StreamConfiguration{}, fmt.Errorf("transmitter registration failed with status %d", resp.StatusCode)
		}

		var txStreamResp model.StreamConfiguration
		if err := json.NewDecoder(resp.Body).Decode(&txStreamResp); err != nil {
			if cleanupErr := s.DeleteStream(ctx, config.Id); cleanupErr != nil {
				ssLog.Error("failed to delete stream during cleanup", "id", config.Id, "error", cleanupErr)
			}
			return model.StreamConfiguration{}, fmt.Errorf("failed to decode transmitter registration response: %v", err)
		}

		// from the response, update config with the transmitters response values
		config.EventsDelivered = txStreamResp.EventsDelivered
		config.EventsRequested = request.EventsRequested
		config.Description = request.Description
		config.TxWellKnownUrl = request.TxWellKnownUrl

		config.RemoteStreamId = &txStreamResp.Id

		if txStreamResp.Delivery != nil && txStreamResp.Delivery.PushTransmitMethod != nil {
			// If no authorization_header value is returned, keep using the request token
			config.TxToken = request.TxToken
			if txStreamResp.Delivery.PushTransmitMethod.AuthorizationHeader != "" {
				txTokStr := txStreamResp.Delivery.PushTransmitMethod.AuthorizationHeader
				config.TxToken = &txTokStr
			}

		} else {
			ssLog.Warn("transmitter configuration delivery is missing PushTransmitMethod information, registration aborted", "stream_id", config.Id, "transmitter_url", request.TxWellKnownUrl)
			if cleanupErr := s.DeleteStream(ctx, config.Id); cleanupErr != nil {
				ssLog.Error("failed to delete stream during cleanup", "id", config.Id, "error", cleanupErr)
			}
			return model.StreamConfiguration{}, errors.New("unexpected response did not include delivery information")
		}

		// Update the persisted record
		streamRec.StreamConfiguration = config
		err = s.streamDAO.Update(ctx, streamRec)
		if err != nil {
			if cleanupErr := s.DeleteStream(ctx, config.Id); cleanupErr != nil {
				ssLog.Error("failed to delete stream during cleanup", "id", config.Id, "error", cleanupErr)
			}
			return model.StreamConfiguration{}, fmt.Errorf("failed to update stream after registration: %v", err)
		}

		ssLog.Debug("Push transmitter stream configured to send to this receiver")
	}

	return config, nil
}

func (s *StreamService) calculateDeliveredEvents(requested []string, supported []string) []string {
	var delivered []string
	if len(requested) == 0 {
		return []string{}
	}
	if requested[0] == "*" {
		return supported
	}

	for _, reqUri := range requested {
		compUri := "(?i)" + reqUri
		if strings.Contains(reqUri, "*") {
			compUri = strings.Replace(compUri, "*", ".*", -1)
		}

		for _, eventUri := range supported {
			match, err := regexp.MatchString(compUri, eventUri)
			if err != nil {
				continue
			}
			if match {
				delivered = append(delivered, eventUri)
			}
		}
	}
	return delivered
}

func (s *StreamService) UpdateStream(ctx context.Context, streamID string, projectID string, configReq model.StreamConfiguration) (*model.StreamConfiguration, error) {
	streamRec, err := s.streamDAO.FindByID(ctx, streamID)
	if err != nil {
		return nil, err
	}
	if streamRec.ProjectId != projectID {
		return nil, errors.New(ErrorInvalidProject)
	}

	config := &streamRec.StreamConfiguration

	if len(configReq.EventsRequested) > 0 {
		config.EventsRequested = configReq.EventsRequested
		config.EventsDelivered = s.calculateDeliveredEvents(configReq.EventsRequested, configReq.EventsSupported)
	}

	if configReq.Format != "" {
		config.Format = configReq.Format
	}

	if configReq.Delivery != nil && configReq.Delivery.GetMethod() != config.Delivery.GetMethod() {
		return nil, errors.New(ErrorInvalidDeliveryMethod)
	}

	if configReq.Description != "" {
		config.Description = configReq.Description
	}

	switch config.Delivery.GetMethod() {
	case model.DeliveryPoll:
		if configReq.Delivery != nil {
			config.Delivery.PollTransmitMethod = configReq.Delivery.PollTransmitMethod
		} // otherwise ignore it
		// MinVerificationInterval and InactivityTimeout are transmitter asserted and cannot be changed
	case model.DeliveryPush:
		if configReq.Delivery != nil {
			config.Delivery.PushTransmitMethod = configReq.Delivery.PushTransmitMethod
		}
		// MinVerificationInterval and InactivityTimeout are transmitter asserted and cannot be changed
	case model.ReceivePoll:
		if configReq.Delivery != nil {
			config.Delivery.PollReceiveMethod = configReq.Delivery.PollReceiveMethod
		}
		if configReq.TxWellKnownUrl != nil {
			config.TxWellKnownUrl = configReq.TxWellKnownUrl
		}
		if configReq.TxToken != nil {
			config.TxToken = configReq.TxToken
		}
		if configReq.TxAlias != nil {
			config.TxAlias = configReq.TxAlias
		}
		if configReq.RemoteStreamId != nil {
			config.RemoteStreamId = configReq.RemoteStreamId
		}
		if configReq.MinVerificationInterval != 0 {
			config.MinVerificationInterval = configReq.MinVerificationInterval
		}
		if configReq.InactivityTimeout > 0 {
			config.InactivityTimeout = configReq.InactivityTimeout
		}
	case model.ReceivePush:
		if configReq.Delivery != nil {
			config.Delivery.PushReceiveMethod = configReq.Delivery.PushReceiveMethod
		}
		if configReq.TxWellKnownUrl != nil {
			config.TxWellKnownUrl = configReq.TxWellKnownUrl
		}
		if configReq.TxToken != nil {
			config.TxToken = configReq.TxToken
		}
		if configReq.TxAlias != nil {
			config.TxAlias = configReq.TxAlias
		}
		if configReq.RemoteStreamId != nil {
			config.RemoteStreamId = configReq.RemoteStreamId
		}
		if configReq.MinVerificationInterval != 0 {
			config.MinVerificationInterval = configReq.MinVerificationInterval
		}
		if configReq.InactivityTimeout > 0 {
			config.InactivityTimeout = configReq.InactivityTimeout
		}
	}

	streamRec.StreamConfiguration = *config
	streamRec.ModifiedAt = time.Now()

	err = s.streamDAO.Update(ctx, streamRec)
	if err != nil {
		return nil, err
	}

	return config, nil
}

func (s *StreamService) DeleteStream(ctx context.Context, streamID string) error {
	// Remove from receiver streams cache if present
	s.mu.Lock()
	delete(s.receiverStreams, streamID)
	s.mu.Unlock()
	return s.streamDAO.Delete(ctx, streamID)
}

func (s *StreamService) GetStream(ctx context.Context, id string) (*model.StreamConfiguration, error) {
	rec, err := s.streamDAO.FindByID(ctx, id)
	if err != nil {
		return nil, err
	}
	config := rec.StreamConfiguration
	return &config, nil
}

func (s *StreamService) ListStreams(ctx context.Context) []model.StreamConfiguration {
	recs, err := s.streamDAO.List(ctx)
	if err != nil {
		ssLog.Error("Error listing streams", "error", err)
		return nil
	}

	res := make([]model.StreamConfiguration, len(recs))
	for i, v := range recs {
		res[i] = v.StreamConfiguration
	}
	return res
}

func (s *StreamService) GetStreamState(ctx context.Context, id string) (*model.StreamStateRecord, error) {
	return s.streamDAO.FindByID(ctx, id)
}

func (s *StreamService) UpdateStreamStatus(ctx context.Context, streamID string, status string, errorMsg string) {
	err := s.streamDAO.UpdateStatus(ctx, streamID, status, errorMsg)
	if err != nil {
		ssLog.Error("Error updating stream status", "streamID", streamID, "error", err)
	}

	// Update cache if receiver stream
	s.mu.RLock()
	state, ok := s.receiverStreams[streamID]
	s.mu.RUnlock()
	if ok {
		state.Status = status
		state.ErrorMsg = errorMsg
	}
}

func (s *StreamService) GetStatus(ctx context.Context, streamID string) (*model.StreamStatus, error) {
	state, err := s.streamDAO.FindByID(ctx, streamID)
	if err != nil {
		return nil, err
	}

	status := model.StreamStatus{
		Status: state.Status,
	}
	if state.ErrorMsg != "" {
		status.Reason = state.ErrorMsg
	}
	return &status, nil
}

func (s *StreamService) GetStateMap(ctx context.Context) map[string]model.StreamStateRecord {
	states, err := s.streamDAO.List(ctx)
	if err != nil {
		ssLog.Error("Error getting state map", "error", err)
		return nil
	}

	stateMap := make(map[string]model.StreamStateRecord, len(states))
	for _, state := range states {
		stateMap[state.StreamConfiguration.Id] = state
	}
	return stateMap
}

func (s *StreamService) LoadReceiverStreams(ctx context.Context) map[string]*model.StreamStateRecord {
	recs, err := s.streamDAO.List(ctx)
	if err != nil {
		ssLog.Error("Error loading receiver streams", "error", err)
		return nil
	}

	res := map[string]*model.StreamStateRecord{}
	for _, streamState := range recs {
		if streamState.IsReceiver() {
			state := streamState
			res[streamState.StreamConfiguration.Id] = &state
			s.loadJwksForReceiver(ctx, &state)
		}
	}
	s.mu.Lock()
	s.receiverStreams = res
	s.mu.Unlock()
	return res
}

// isPermanentJwksError determines if a JWKS loading error is permanent (should disable stream)
// or temporary (should allow retries). Permanent errors include:
// - Invalid URL format/syntax
// - Unsupported protocol scheme
// - Invalid response format (not valid JWKS)
func isPermanentJwksError(err error) bool {
	if err == nil {
		return false
	}

	errStr := err.Error()

	// Check for URL parsing/format errors
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		// Unsupported protocol scheme is permanent
		if strings.Contains(urlErr.Err.Error(), "unsupported protocol scheme") {
			return true
		}
		// Check if the underlying error is permanent
		return isPermanentJwksError(urlErr.Err)
	}

	// Invalid URL format errors
	if strings.Contains(errStr, "invalid URL") ||
		strings.Contains(errStr, "unsupported protocol scheme") ||
		strings.Contains(errStr, "parse") && strings.Contains(errStr, "URL") {
		return true
	}

	// Invalid JWKS response format
	if strings.Contains(errStr, "failed to decode") ||
		strings.Contains(errStr, "invalid character") ||
		strings.Contains(errStr, "unexpected end of JSON") ||
		strings.Contains(errStr, "cannot unmarshal") {
		return true
	}

	// HTTP 4xx errors (except 429 Too Many Requests) are permanent
	if strings.Contains(errStr, "400 Bad Request") ||
		strings.Contains(errStr, "401 Unauthorized") ||
		strings.Contains(errStr, "403 Forbidden") ||
		strings.Contains(errStr, "404 Not Found") ||
		strings.Contains(errStr, "410 Gone") {
		return true
	}

	// Everything else (connection errors, timeouts, 5xx errors) is temporary
	return false
}

func (s *StreamService) loadJwksForReceiver(ctx context.Context, streamState *model.StreamStateRecord) {
	if streamState.Status == model.StreamStateEnabled {
		if streamState.IssuerJWKSUrl == "" {
			return
		}
		ssLog.Debug("Loading JWKS key", "url", streamState.IssuerJWKSUrl)
		jwks, err := goSet.GetJwks(streamState.IssuerJWKSUrl)
		if err != nil {
			msg := fmt.Sprintf("Error retrieving issuer JWKS public key: %s", err.Error())

			// Determine if this is a permanent error that should disable the stream
			if isPermanentJwksError(err) {
				// Permanent error - disable the stream immediately
				ssLog.Error("Permanent error loading JWKS, disabling stream", "sid", streamState.StreamConfiguration.Id, "error", err.Error())
				streamState.Status = model.StreamStateDisable
				streamState.ErrorMsg = msg
				// Update the stream in the database
				err = s.streamDAO.Update(ctx, streamState)
				if err != nil {
					ssLog.Error("Error updating stream status in database", "sid", streamState.StreamConfiguration.Id, "error", err)
				}
			} else {
				// Temporary error - log but don't change stream state
				// Let the polling client handle retries with backoff
				ssLog.Error("Temporary error loading JWKS, will retry", "sid", streamState.StreamConfiguration.Id, "error", err.Error())
			}
			return
		}
		streamState.ValidateJwks = jwks
	}
}

func (s *StreamService) GetIssuerJwksForReceiver(ctx context.Context, sid string) *keyfunc.JWKS {
	// Check cache first
	s.mu.RLock()
	streamState, ok := s.receiverStreams[sid]
	s.mu.RUnlock()
	if ok {
		return streamState.ValidateJwks
	}

	// Try to load the stream
	streamState, err := s.streamDAO.FindByID(ctx, sid)
	if err != nil {
		ssLog.Error("Error loading receiver stream during JWKS initialization", "sid", sid, "error", err)
		return nil
	}

	if streamState.IsReceiver() {
		s.loadJwksForReceiver(ctx, streamState)
		s.receiverStreams[sid] = streamState
		return streamState.ValidateJwks
	}

	return nil
}
