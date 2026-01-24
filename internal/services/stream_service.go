package services

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/MicahParks/keyfunc"
	"github.com/i2-open/i2goSignals/internal/dao/interfaces"
	"github.com/i2-open/i2goSignals/internal/logger"
	"github.com/i2-open/i2goSignals/internal/model"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

var ssLog = logger.Sub("STREAM_SERVICE")

const CSubjectFmt = "opaque"
const ErrorInvalidProject = "invalid project_id - invalid token"

type StreamService struct {
	streamDAO       interfaces.StreamDAO
	keyService      *KeyService
	defaultIssuer   string
	receiverStreams map[string]*model.StreamStateRecord
}

func NewStreamService(streamDAO interfaces.StreamDAO, keyService *KeyService, defaultIssuer string) *StreamService {
	return &StreamService{
		streamDAO:       streamDAO,
		keyService:      keyService,
		defaultIssuer:   defaultIssuer,
		receiverStreams: make(map[string]*model.StreamStateRecord),
	}
}

func (s *StreamService) CreateStream(ctx context.Context, request model.StreamConfiguration, projectID string) (model.StreamConfiguration, error) {
	mid := primitive.NewObjectID()

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

	authIssuer := s.keyService.GetAuthIssuer()

	switch delivery.GetMethod() {
	case model.DeliveryPush:
		config.Delivery = request.Delivery
		if request.RouteMode == "" {
			config.RouteMode = model.RouteModePublish // default is publish
		}

	case model.DeliveryPoll, "DEFAULT":
		authToken, _ := authIssuer.IssueStreamToken(mid.Hex(), projectID)
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
		authToken, _ := authIssuer.IssueStreamToken(mid.Hex(), projectID)
		method.AuthorizationHeader = "Bearer " + authToken

	case model.ReceivePoll:
		config.Delivery = request.Delivery
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

	config.MinVerificationInterval = 15
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

	// If this is a receiver stream, load its JWKS
	if streamRec.IsReceiver() {
		s.receiverStreams[config.Id] = streamRec
		s.loadJwksForReceiver(ctx, streamRec)
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
	delete(s.receiverStreams, streamID)
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
	if state, ok := s.receiverStreams[streamID]; ok {
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
	s.receiverStreams = res
	return res
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
			ssLog.Error(msg)
			streamState.Status = model.StreamStatePause
			streamState.ErrorMsg = msg
			return
		}
		streamState.ValidateJwks = jwks
	}
}

func (s *StreamService) GetIssuerJwksForReceiver(ctx context.Context, sid string) *keyfunc.JWKS {
	// Check cache first
	if streamState, ok := s.receiverStreams[sid]; ok {
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
