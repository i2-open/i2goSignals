package services

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/MicahParks/keyfunc"
	"github.com/i2-open/i2goSignals/internal/dao/interfaces"
	"github.com/i2-open/i2goSignals/internal/logger"
	"github.com/i2-open/i2goSignals/internal/model"
	"github.com/i2-open/i2goSignals/pkg/goSet"
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
		minVerificationInterval: minVerificationInterval,
		maxInactivityTimeout:    maxInactivityTimeout,
	}
}

func (s *StreamService) SetBaseUrl(u *url.URL) {
	s.BaseUrl = u
}

func (s *StreamService) CreateStream(ctx context.Context, request model.StreamConfiguration, projectID string) (model.StreamConfiguration, error) {
	mid := bson.NewObjectID()

	var config model.StreamConfiguration

	if request.Iss == "" {
		config.Iss = s.defaultIssuer
	} else {
		config.Iss = request.Iss
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

	authIssuer := s.keyService.GetAuthIssuer()

	switch delivery.GetMethod() {
	case model.DeliveryPush:
		config.Delivery = request.Delivery
		if request.RouteMode == "" {
			config.RouteMode = model.RouteModePublish // default is publish
		}

	case model.DeliveryPoll, "DEFAULT":
		authToken, err := authIssuer.IssueStreamToken(mid.Hex(), projectID)
		if err != nil {
			return model.StreamConfiguration{}, fmt.Errorf("failed to issue stream token: %v", err)
		}
		delivery := &model.OneOfStreamConfigurationDelivery{
			PollTransmitMethod: &model.PollTransmitMethod{
				Method:              model.DeliveryPoll,
				EndpointUrl:         fmt.Sprintf("/poll/%s", mid.Hex()),
				AuthorizationHeader: "Bearer " + authToken,
			},
		}
		if request.RouteMode == "" {
			config.RouteMode = model.RouteModePublish // default is publish
		}
		config.Delivery = delivery

	case model.ReceivePush:
		config.Delivery = request.Delivery
		method := config.Delivery.PushReceiveMethod
		if request.RouteMode == "" {
			config.RouteMode = model.RouteModeImport
		}
		method.EndpointUrl = fmt.Sprintf("/events/%s", mid.Hex())
		authToken, err := authIssuer.IssueStreamToken(mid.Hex(), projectID)
		if err != nil {
			return model.StreamConfiguration{}, fmt.Errorf("failed to issue stream token: %v", err)
		}
		method.AuthorizationHeader = "Bearer " + authToken

	case model.ReceivePoll:
		config.Delivery = request.Delivery
		if request.TxWellKnownUrl != nil && request.TxToken != nil && *request.TxToken != "" && *request.TxWellKnownUrl != "" {
			// Attempt to do an SSF registration to create the Polling Transmit Stream
			ssLog.Debug("Retrieving SSF transmitter configuration for automatic registration...")
			// Retrieve the transmitter configuration from the WellKnownUrl
			resp, err := http.Get(*request.TxWellKnownUrl)
			if err != nil {
				return model.StreamConfiguration{}, fmt.Errorf("failed to fetch transmitter configuration: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				return model.StreamConfiguration{}, fmt.Errorf("transmitter configuration returned status %d", resp.StatusCode)
			}
			var txConfig model.TransmitterConfiguration
			if err := json.NewDecoder(resp.Body).Decode(&txConfig); err != nil {
				return model.StreamConfiguration{}, fmt.Errorf("failed to decode transmitter configuration: %v", err)
			}

			if txConfig.ConfigurationEndpoint == "" {
				return model.StreamConfiguration{}, errors.New("transmitter configuration missing configuration_endpoint")
			}

			transmitStreamReq := model.StreamConfiguration{
				Iss: request.Iss,
				Aud: request.Aud,
				Delivery: &model.OneOfStreamConfigurationDelivery{
					PollTransmitMethod: &model.PollTransmitMethod{
						Method: model.DeliveryPoll,
					},
				},
			}
			ssLog.Debug("Submitting POLL stream registration request to transmitter...")
			reqBody, err := json.Marshal(transmitStreamReq)
			if err != nil {
				return model.StreamConfiguration{}, fmt.Errorf("failed to marshal registration request: %v", err)
			}
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, txConfig.ConfigurationEndpoint, bytes.NewReader(reqBody))
			if err != nil {
				return model.StreamConfiguration{}, err
			}
			req.Header.Set("Content-Type", "application/json")
			parts := strings.Split(*request.TxToken, " ")
			if len(parts) == 1 {
				req.Header.Set("Authorization", "Bearer "+*request.TxToken)
			} else {
				req.Header.Set("Authorization", *request.TxToken)
			}

			resp, err = http.DefaultClient.Do(req)
			if err != nil {
				ssLog.Error("failed to submit registration request to transmitter", "error", err)
				return model.StreamConfiguration{}, fmt.Errorf("failed to submit registration request to transmitter: %v", err)
			}
			defer resp.Body.Close()

			// parse the response and handle any errors. If they occur return a detailed error
			if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
				ssLog.Warn("transmitter registration failed", "host", txConfig.ConfigurationEndpoint, "status", resp.StatusCode)
				return model.StreamConfiguration{}, fmt.Errorf("transmitter registration failed with status %d", resp.StatusCode)
			}

			var txStreamResp model.StreamConfiguration
			if err := json.NewDecoder(resp.Body).Decode(&txStreamResp); err != nil {
				return model.StreamConfiguration{}, fmt.Errorf("failed to decode transmitter registration response: %v", err)
			}

			// from the response, update config.EventsDelivered with the transmitters response EventsDelivered
			config.EventsDelivered = txStreamResp.EventsDelivered
			config.TxWellKnownUrl = request.TxWellKnownUrl

			if txStreamResp.Delivery != nil && txStreamResp.Delivery.PollTransmitMethod != nil {

				config.TxToken = &txStreamResp.Delivery.PollTransmitMethod.AuthorizationHeader // Use for status and verification endpoints
				config.Delivery.PollReceiveMethod.AuthorizationHeader = txStreamResp.Delivery.PollTransmitMethod.AuthorizationHeader
				config.Delivery.PollReceiveMethod.EndpointUrl = txStreamResp.Delivery.PollTransmitMethod.EndpointUrl
				config.Delivery.PollReceiveMethod.PollConfig = txStreamResp.Delivery.PollTransmitMethod.PollConfig // follow the Transmitters poll config if asserted

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
	} else {
		config.IssuerJWKSUrl = "/jwks/" + config.Iss
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

	err := s.streamDAO.Create(ctx, streamRec)
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
	if request.Delivery.GetMethod() == model.ReceivePush && request.TxWellKnownUrl != nil && request.TxToken != nil {
		ssLog.Debug("Retrieving SSF transmitter configuration for automatic registration...")
		// Retrieve the transmitter configuration from the WellKnownUrl
		resp, err := http.Get(*request.TxWellKnownUrl)
		if err != nil {
			if cleanupErr := s.DeleteStream(ctx, config.Id); cleanupErr != nil {
				ssLog.Error("failed to delete stream during cleanup", "id", config.Id, "error", cleanupErr)
			}
			return model.StreamConfiguration{}, fmt.Errorf("failed to fetch transmitter configuration: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			if cleanupErr := s.DeleteStream(ctx, config.Id); cleanupErr != nil {
				ssLog.Error("failed to delete stream during cleanup", "id", config.Id, "error", cleanupErr)
			}
			return model.StreamConfiguration{}, fmt.Errorf("transmitter configuration returned status %d", resp.StatusCode)
		}
		var txConfig model.TransmitterConfiguration
		if err := json.NewDecoder(resp.Body).Decode(&txConfig); err != nil {
			if cleanupErr := s.DeleteStream(ctx, config.Id); cleanupErr != nil {
				ssLog.Error("failed to delete stream during cleanup", "id", config.Id, "error", cleanupErr)
			}
			return model.StreamConfiguration{}, fmt.Errorf("failed to decode transmitter configuration: %v", err)
		}

		if txConfig.ConfigurationEndpoint == "" {
			if cleanupErr := s.DeleteStream(ctx, config.Id); cleanupErr != nil {
				ssLog.Error("failed to delete stream during cleanup", "id", config.Id, "error", cleanupErr)
			}
			return model.StreamConfiguration{}, errors.New("transmitter configuration missing configuration_endpoint")
		}

		method := streamRec.StreamConfiguration.Delivery.PushReceiveMethod
		endpoint := method.EndpointUrl
		if s.BaseUrl != nil {
			u, _ := s.BaseUrl.Parse(endpoint)
			endpoint = u.String()
		}

		// Using the returned configuration endpoint, form a stream create-request with model.DeliveryPush.
		transmitStreamReq := model.StreamConfiguration{
			Iss:             request.Iss,
			Aud:             request.Aud,
			EventsRequested: request.EventsRequested,
			Delivery: &model.OneOfStreamConfigurationDelivery{
				PushTransmitMethod: &model.PushTransmitMethod{
					Method:              model.DeliveryPush,
					EndpointUrl:         endpoint,
					AuthorizationHeader: method.AuthorizationHeader,
				},
			},
		}

		ssLog.Debug("Submitting PUSH stream registration request to transmitter...")

		// Submit the creation request to the transmitter's ConfigurationEndpoint.
		reqBody, err := json.Marshal(transmitStreamReq)
		if err != nil {
			if cleanupErr := s.DeleteStream(ctx, config.Id); cleanupErr != nil {
				ssLog.Error("failed to delete stream during cleanup", "id", config.Id, "error", cleanupErr)
			}
			return model.StreamConfiguration{}, fmt.Errorf("failed to marshal registration request: %v", err)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, txConfig.ConfigurationEndpoint, bytes.NewReader(reqBody))
		if err != nil {
			if cleanupErr := s.DeleteStream(ctx, config.Id); cleanupErr != nil {
				ssLog.Error("failed to delete stream during cleanup", "id", config.Id, "error", cleanupErr)
			}
			return model.StreamConfiguration{}, err
		}
		req.Header.Set("Content-Type", "application/json")
		parts := strings.Split(*request.TxToken, " ")
		if len(parts) == 1 {
			req.Header.Set("Authorization", "Bearer "+*request.TxToken)
		} else {
			req.Header.Set("Authorization", *request.TxToken)
		}

		resp, err = http.DefaultClient.Do(req)
		if err != nil {
			ssLog.Error("failed to submit registration request to transmitter", "error", err)
			if cleanupErr := s.DeleteStream(ctx, config.Id); cleanupErr != nil {
				ssLog.Error("failed to delete stream during cleanup", "id", config.Id, "error", cleanupErr)
			}
			return model.StreamConfiguration{}, fmt.Errorf("failed to submit registration request to transmitter: %v", err)
		}
		defer resp.Body.Close()

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

		// from the response, update config.EventsDelivered with the transmitters response EventsDelivered
		config.EventsDelivered = txStreamResp.EventsDelivered
		config.TxWellKnownUrl = request.TxWellKnownUrl
		config.TxToken = &txStreamResp.Delivery.PushTransmitMethod.AuthorizationHeader

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
		ssLog.Info("Loading JWKS key", "url", streamState.IssuerJWKSUrl)
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
