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
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/MicahParks/keyfunc/v2"
	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/authSupport"
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
	serverService           *ServerService
	subjectFilterService    *SubjectFilterService
	subjectRelayService     *SubjectRelayService
	defaultIssuer           string
	receiverStreams         map[string]*model.StreamStateRecord
	BaseUrl                 *url.URL
	mu                      sync.RWMutex
	minVerificationInterval int
	maxInactivityTimeout    int
}

// SetSubjectFilterService wires in the SubjectFilterService so that a
// defaultSubjects baseline change on a live stream clears that stream's
// subject filter. Optional: when unset, UpdateStream skips the filter clear.
func (s *StreamService) SetSubjectFilterService(svc *SubjectFilterService) {
	s.subjectFilterService = svc
}

// SetServerService wires in the ServerService that owns Server records. Once
// set, CreateStream resolves a tx_alias request field to the corresponding
// Server before delegating to the rest of the pipeline. Lifted out of the
// provider façade as part of PRD #39 PR 4.
func (s *StreamService) SetServerService(svc *ServerService) {
    s.serverService = svc
}

// SetSubjectRelayService wires in the SubjectRelayService so that
// CreateStream/UpdateStream validate a transmitter stream's subject-filter
// mode against its upstream (PRD #89 #95). Optional: when unset, validation is
// skipped.
func (s *StreamService) SetSubjectRelayService(svc *SubjectRelayService) {
    s.subjectRelayService = svc
}

// validateSubjectFilterMode rejects or warns on a transmitter stream's
// subject-filter mode against its resolved upstream (PRD #89 #95). It is a
// no-op when subject filtering is disabled server-wide, no mode is set, or the
// relay service is unwired.
func (s *StreamService) validateSubjectFilterMode(ctx context.Context, rec *model.StreamStateRecord) error {
    if !SubjectFilteringEnabled() || rec.SubjectFilterMode == "" || s.subjectRelayService == nil {
        return nil
    }
    verdict := s.subjectRelayService.ValidateConfig(ctx, rec)
    if verdict.Err != nil {
        return fmt.Errorf("invalid subject-filter configuration: %w", verdict.Err)
    }
    if verdict.Warn != "" {
        ssLog.Warn(verdict.Warn, "stream_id", rec.StreamConfiguration.Id, "mode", rec.SubjectFilterMode)
    }
    return nil
}

// validateSubjectRemovalGrace rejects a malformed SSF §9.3 grace override on
// the request before any state is mutated (PRD #97 issue #98). Sits alongside
// validateSubjectFilterMode in the create/update pipeline. Only the request
// value is checked here — the WARN-and-drop for a receiver stream is the
// caller's responsibility, since the rejection must be field-shape only.
func validateSubjectRemovalGrace(grace int) error {
    if grace < 0 {
        return fmt.Errorf("invalid subject_removal_grace_seconds: must be >= 0, got %d", grace)
    }
    return nil
}

// applyRemovalGraceOverride copies a non-zero SSF §9.3 grace override from the
// request onto streamRec. On a receiver stream the value has no meaning and is
// dropped with a WARN (PRD #97 issue #98). The request value has already been
// shape-checked by validateSubjectRemovalGrace.
func applyRemovalGraceOverride(streamRec *model.StreamStateRecord, requested int) {
    if requested == 0 {
        return
    }
    if streamRec.IsReceiver() {
        ssLog.Warn("subject_removal_grace_seconds ignored on a receiver stream",
            "stream_id", streamRec.StreamConfiguration.Id,
            "value", requested)
        return
    }
    streamRec.SubjectRemovalGraceSeconds = requested
}

// validateEventSource enforces the ADR 0004 event_source.type rules against a
// transmitter stream's resolved configuration (issue #117). It is a pure shape
// check that mutates no state, and is a no-op for a nil descriptor or for the
// silent-AUDIENCE default (empty type with no source_stream_ids), so pre-
// existing streams keep working with no error and no warning. R4's WARN-and-
// drop for receiver streams is handled by applyEventSource before this runs, so
// a receiver stream never reaches this validation with a non-nil EventSource.
func validateEventSource(es *model.EventSource, mode string) error {
    if es == nil {
        return nil
    }
    if es.Type == model.EventSourceExplicit {
        // R2: EXPLICIT must name at least one upstream stream.
        if len(es.SourceStreamIds) == 0 {
            return fmt.Errorf("invalid event_source: type EXPLICIT requires a non-empty source_stream_ids")
        }
        return nil
    }
    // R3: source_stream_ids is only meaningful for EXPLICIT. Every non-EXPLICIT
    // type — DIRECT, AUDIENCE, and the unset/empty silent-AUDIENCE default —
    // must leave it empty.
    if len(es.SourceStreamIds) > 0 {
        return fmt.Errorf("invalid event_source: source_stream_ids is only valid when type is EXPLICIT")
    }
    // R1: a DIRECT stream has no SSF upstream to relay Add/Remove to.
    if es.Type == model.EventSourceDirect &&
        (mode == model.SubjectFilterModePassthru || mode == model.SubjectFilterModeHybrid) {
        return fmt.Errorf("invalid event_source: type DIRECT is incompatible with subject_filter_mode %s (no upstream to relay to)", mode)
    }
    return nil
}

// applyEventSource copies the requested event_source descriptor onto streamRec.
// On a receiver stream the descriptor has no meaning — there is no routing to
// govern — so it is dropped with a WARN and the request still succeeds (R4,
// ADR 0004 issue #117). Mirrors applyRemovalGraceOverride. A nil request is a
// no-op so an UpdateStream that does not touch event_source leaves it intact.
func applyEventSource(streamRec *model.StreamStateRecord, requested *model.EventSource) {
    if requested == nil {
        return
    }
    if streamRec.IsReceiver() {
        ssLog.Warn("event_source ignored on a receiver stream",
            "stream_id", streamRec.StreamConfiguration.Id)
        streamRec.EventSource = nil
        return
    }
    streamRec.EventSource = requested
}

// StreamServiceConfig carries the operator-tunable stream knobs that were
// previously read from environment variables inside the constructor. The wiring
// tree (the provider) now resolves these — via internal/envcompat or otherwise —
// and passes concrete values in, so this package no longer reads the
// environment. A non-positive MinVerificationInterval/MaxInactivityTimeout
// falls back to the historical defaults (300 / 3600), preserving prior
// behaviour when the caller leaves them unset.
type StreamServiceConfig struct {
	BaseUrl                 *url.URL
	MinVerificationInterval int
	MaxInactivityTimeout    int
}

func NewStreamService(streamDAO interfaces.StreamDAO, keyService *KeyService, defaultIssuer string, cfg StreamServiceConfig) *StreamService {
	minVerificationInterval := cfg.MinVerificationInterval
	if minVerificationInterval <= 0 {
		minVerificationInterval = 300
	}
	maxInactivityTimeout := cfg.MaxInactivityTimeout
	if maxInactivityTimeout <= 0 {
		maxInactivityTimeout = 3600
	}
	return &StreamService{
		streamDAO:               streamDAO,
		keyService:              keyService,
		defaultIssuer:           defaultIssuer,
		receiverStreams:         make(map[string]*model.StreamStateRecord),
		BaseUrl:                 cfg.BaseUrl,
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

// CreateStream creates a stream from request. request is a StreamStateRecord
// rather than a bare StreamConfiguration so that goSignals-specific operator
// knobs (subject-filtering fields) can be supplied alongside the SSF
// wire-format configuration without leaking into it.
func (s *StreamService) CreateStream(ctx context.Context, request model.StreamStateRecord, projectID string, txServer *model.Server) (model.StreamConfiguration, error) {
    // Resolve tx_alias → Server when the caller didn't pre-resolve it. This
    // logic was previously in BaseProvider.CreateStream; it lives here now
    // so the provider façade can be a pass-through.
    if txServer == nil && request.TxAlias != nil && *request.TxAlias != "" && s.serverService != nil {
        resolved, err := s.serverService.GetServerByAlias(ctx, *request.TxAlias)
        if err != nil {
            return model.StreamConfiguration{}, errors.New("unknown tx_alias provided")
        }
        txServer = resolved
    }

    // Normalise IssuerJWKSUrl == "NONE" (any case) to the empty string. SCIM
    // servers signal "key is internal to this server" via "NONE"; downstream
    // code expects an empty value.
    if strings.EqualFold(request.IssuerJWKSUrl, "NONE") {
        request.IssuerJWKSUrl = ""
    }

    // Validate goSignals-specific knobs before any state is mutated. The SSF
    // §9.3 grace override (PRD #97 #98) is validated alongside #89's mode and
    // event-source pipeline a few lines below.
    if err := validateSubjectRemovalGrace(request.SubjectRemovalGraceSeconds); err != nil {
        return model.StreamConfiguration{}, err
    }

    mid := bson.NewObjectID()

	// var authCtx authSupport.AuthContext
	// authCtx = ctx.Value(authSupport.AuthContextKey).(authSupport.AuthContext)

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
	// deliveryParent carries the lineage parent for any delivery (stream) token
	// minted below: the stream-client token that authorized this CreateStream
	// (ADR 0007). Passing it as the issuing session sets Parent without altering
	// the delivery token's other claims (an empty-ID session leaves Parent empty).
	var deliveryParent *authSupport.AuthContext
	if ctx.Value("authCtx") != nil {
		authCtx := ctx.Value("authCtx").(*authSupport.AuthContext)
		isOAuth = authCtx.IsOAuthClient
		if authCtx.Eat != nil {
			deliveryParent = &authSupport.AuthContext{Eat: &authSupport.EventAuthToken{}}
			deliveryParent.Eat.ID = authCtx.Eat.ID
		}
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
			authToken, err = authIssuer.IssueStreamToken(mid.Hex(), projectID, deliveryParent)
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
			authToken, err := authIssuer.IssueStreamToken(mid.Hex(), projectID, deliveryParent)
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

	// defaultSubjects is an operator knob that is inert until subject filtering
	// is enabled server-wide; silently ignore it otherwise so an upgrade does
	// not change delivery behavior for streams that set it.
	defaultSubjects := request.DefaultSubjects
	if !SubjectFilteringEnabled() {
		defaultSubjects = ""
	}

	streamRec := &model.StreamStateRecord{
		Id:                  mid,
		ProjectId:           projectID,
		StreamConfiguration: config,
		StartDate:           now,
		Status:              model.StreamStateEnabled,
		CreatedAt:           now,
		ModifiedAt:          now,
		DefaultSubjects:     defaultSubjects,
		SubjectFilterMode:   request.SubjectFilterMode,
	}

	// ADR 0004 (issue #117): apply event_source, dropping it with a WARN on
	// receiver streams, then validate the type rules for transmitter streams.
	// The drop happens first so a receiver never fails event_source validation.
	applyEventSource(streamRec, request.EventSource)
	if err = validateEventSource(streamRec.EventSource, streamRec.SubjectFilterMode); err != nil {
		return model.StreamConfiguration{}, err
	}

	// SSF §9.3 grace override (PRD #97 #98). Dropped on receiver streams with
	// a WARN; honored on transmitter streams. Request value is already shape-
	// checked above by validateSubjectRemovalGrace.
	applyRemovalGraceOverride(streamRec, request.SubjectRemovalGraceSeconds)

	// PRD #89 #95: reject (or WARN on) a subject-filter mode that is
	// incompatible with the stream's upstream before the stream is persisted.
	if err = s.validateSubjectFilterMode(ctx, streamRec); err != nil {
		return model.StreamConfiguration{}, err
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

// UpdateStream patches an existing stream. configReq is a StreamStateRecord so
// the goSignals-specific subject-filtering operator knobs can be updated
// alongside the SSF wire-format configuration. Like the rest of this method,
// only non-empty request fields are applied.
//
// projectID confines a project-scoped token to streams it owns. An empty
// projectID means the caller is not project-bound (e.g. an external OAuth/STS
// admin token authorized purely by scope, as goSignalsAdmin uses); such a
// caller addresses the stream by stream_id and is not project-confined.
func (s *StreamService) UpdateStream(ctx context.Context, streamID string, projectID string, configReq model.StreamStateRecord) (*model.StreamConfiguration, error) {
	streamRec, err := s.streamDAO.FindByID(ctx, streamID)
	if err != nil {
		// An SSTP pair's receive-side SID is not its document _id; fall back to the
		// inbound-SID index so an rxSid resolves to its pair record. (Q35, Q39)
		inboundRec, inboundErr := s.streamDAO.FindByInboundSID(ctx, streamID)
		if inboundErr != nil {
			return nil, err
		}
		streamRec = inboundRec
	}
	if projectID != "" && streamRec.ProjectId != projectID {
		return nil, errors.New(ErrorInvalidProject)
	}

	// SSTP pairs use a distinct patchable-fields whitelist (Q35): the generic
	// delivery-method switch below does not apply. streamID names a direction
	// (txSid == PairId, or rxSid == SstpInbound.Id) so per-direction Iss/Aud can
	// be targeted.
	if streamRec.GetType() == model.DeliverySstpPair {
		return s.updateSstpPair(ctx, streamRec, streamID, configReq)
	}

	// Validate goSignals-specific knobs against the request before mutating
	// the persisted record. PRD #97 #98 — alongside the mode/event-source
	// validation performed below by validateSubjectFilterMode.
	if err := validateSubjectRemovalGrace(configReq.SubjectRemovalGraceSeconds); err != nil {
		return nil, err
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

	// Subject-filtering operator knobs. defaultSubjects is gated on the
	// server-wide feature being enabled; when disabled the request value is
	// silently ignored, consistent with CreateStream. A baseline change clears
	// the stream's subject filter so stale entries never carry the opposite
	// meaning under the new baseline.
	defaultSubjectsFlipped := false
	if SubjectFilteringEnabled() && configReq.DefaultSubjects != "" {
		defaultSubjectsFlipped = configReq.DefaultSubjects != streamRec.DefaultSubjects
		streamRec.DefaultSubjects = configReq.DefaultSubjects
	}
	if configReq.SubjectFilterMode != "" {
		streamRec.SubjectFilterMode = configReq.SubjectFilterMode
	}
	// ADR 0004 (issue #117): apply event_source, dropping it with a WARN on
	// receiver streams, then validate the type rules for transmitter streams.
	applyEventSource(streamRec, configReq.EventSource)
	if err = validateEventSource(streamRec.EventSource, streamRec.SubjectFilterMode); err != nil {
		return nil, err
	}

	// SSF §9.3 grace override (PRD #97 #98). Request value is already shape-
	// checked above by validateSubjectRemovalGrace.
	applyRemovalGraceOverride(streamRec, configReq.SubjectRemovalGraceSeconds)

	// PRD #89 #95: re-validate the subject-filter mode against the upstream
	// whenever the mode or event source could have changed.
	if err = s.validateSubjectFilterMode(ctx, streamRec); err != nil {
		return nil, err
	}

	err = s.streamDAO.Update(ctx, streamRec)
	if err != nil {
		return nil, err
	}

	if defaultSubjectsFlipped && s.subjectFilterService != nil {
		if clearErr := s.subjectFilterService.ClearFilter(ctx, streamID); clearErr != nil {
			ssLog.Warn("Error clearing subject filter after defaultSubjects change", "sid", streamID, "error", clearErr)
		}
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

// GetStreamConfigBySID resolves a SID to its StreamConfiguration, routing per
// direction for SSTP pairs (Q40). Naming the tx-side SID returns the primary
// (outbound) StreamConfiguration; naming the rx-side SID returns the inbound
// StreamConfiguration. Verification (POST /verify) targets the outbound side of
// whichever direction the SID names, so it scopes the generated verify SET to
// the resolved direction's iss/aud. Non-SSTP streams resolve via FindByID.
func (s *StreamService) GetStreamConfigBySID(ctx context.Context, sid string) (*model.StreamConfiguration, error) {
	if rec := s.findSstpPairBySID(ctx, sid); rec != nil {
		if rec.SstpInbound != nil && sid == rec.SstpInbound.Id {
			inbound := *rec.SstpInbound
			return &inbound, nil
		}
		config := rec.StreamConfiguration
		return &config, nil
	}
	return s.GetStream(ctx, sid)
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

// GetStreamStateBySID resolves a SID to its StreamStateRecord, routing SSTP
// pairs by either direction (Q40/Q41). A non-SSTP SID, or the tx-side SID of a
// pair, resolves via FindByID; the rx-side (inbound) SID of a pair resolves to
// the same single pair record. This lets operational paths keyed on a SID (e.g.
// verify) find the pair when the named SID is the inbound side, whose value is
// not the document _id.
func (s *StreamService) GetStreamStateBySID(ctx context.Context, sid string) (*model.StreamStateRecord, error) {
	if rec := s.findSstpPairBySID(ctx, sid); rec != nil {
		return rec, nil
	}
	return s.streamDAO.FindByID(ctx, sid)
}

// GetStreamStateByInboundSID returns the SSTP pair record whose receive-side
// SID (SstpInbound.Id) equals sid, or interfaces.ErrNotFound. (PRD #154 Q24)
func (s *StreamService) GetStreamStateByInboundSID(ctx context.Context, sid string) (*model.StreamStateRecord, error) {
	return s.streamDAO.FindByInboundSID(ctx, sid)
}

// GetStreamStateByPairId returns the record whose PairId equals pairId, or
// interfaces.ErrNotFound. PairId is the on-wire SSF stream_id for an SSTP pair.
func (s *StreamService) GetStreamStateByPairId(ctx context.Context, pairId string) (*model.StreamStateRecord, error) {
	return s.streamDAO.FindByPairId(ctx, pairId)
}

// PersistStreamStateRecord writes a fully-formed StreamStateRecord directly via
// the DAO, bypassing CreateStream's request-shaped validation. It is the
// storage-layer seam SSTP pair creation (slice #161) will build on; this slice
// uses it only to exercise the bidirectional record round-trip across both
// providers. (PRD #154 Q24)
func (s *StreamService) PersistStreamStateRecord(ctx context.Context, rec *model.StreamStateRecord) error {
	return s.streamDAO.Create(ctx, rec)
}

func (s *StreamService) UpdateStreamStatus(ctx context.Context, streamID string, status string, errorMsg string) {
	// SSTP pairs route status per direction (Q39, Q41) and Disabled couples both
	// directions. When the SID belongs to a pair, the SSTP path owns the update.
	if rec := s.findSstpPairBySID(ctx, streamID); rec != nil {
		s.updateSstpPairStatus(ctx, rec, streamID, status, errorMsg)
		return
	}

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

func (s *StreamService) UpdateRemoteAddress(ctx context.Context, streamID string, addr *model.RemoteIP) {
	err := s.streamDAO.UpdateRemoteAddress(ctx, streamID, addr)
	if err != nil {
		ssLog.Error("Error updating remote address", "streamID", streamID, "error", err)
	}

	// Update cache if receiver stream
	s.mu.RLock()
	state, ok := s.receiverStreams[streamID]
	s.mu.RUnlock()
	if ok {
		state.RemoteAddress = addr
	}
}

func (s *StreamService) GetStatus(ctx context.Context, streamID string) (*model.StreamStatus, error) {
	// SSTP pairs report status per direction (Q41). When streamID names the rx
	// (inbound) side, report InboundStatus/InboundErrorMsg; when it names the tx
	// side, report Status/ErrorMsg. findSstpPairBySID resolves either direction;
	// non-SSTP streams fall through to the plain FindByID path below.
	if rec := s.findSstpPairBySID(ctx, streamID); rec != nil {
		if rec.SstpInbound != nil && streamID == rec.SstpInbound.Id {
			status := model.StreamStatus{Status: rec.InboundStatus}
			if rec.InboundErrorMsg != "" {
				status.Reason = rec.InboundErrorMsg
			}
			return &status, nil
		}
		status := model.StreamStatus{Status: rec.Status}
		if rec.ErrorMsg != "" {
			status.Reason = rec.ErrorMsg
		}
		return &status, nil
	}

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

// ListReceiverStreams returns the streams that receive events on this server
// (ReceivePush, ReceivePoll, or either direction of an SSTP pair). It uses
// HasInbound() rather than IsReceiver() so an SSTP pair — whose primary Delivery
// is the transmit marker but which still ingests inbound SETs — is enumerated for
// the startup inbound-JWKS preload (finding #10). For plain RFC8935/8936 streams
// HasInbound() == IsReceiver(), so they are unaffected. It is a pure query — no
// cache mutation, no JWKS loading — and is the canonical home for the
// receiver-stream predicate.
func (s *StreamService) ListReceiverStreams(ctx context.Context) ([]model.StreamStateRecord, error) {
	recs, err := s.streamDAO.List(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]model.StreamStateRecord, 0, len(recs))
	for _, rec := range recs {
		if rec.HasInbound() {
			out = append(out, rec)
		}
	}
	return out, nil
}

// ListTransmitterStreams returns the streams that transmit events from this server
// (DeliveryPush, DeliveryPoll, or either direction of an SSTP pair) — the
// downstream-stream set the HYBRID interested-set is computed over (issue #96). It
// uses HasOutbound() rather than !IsReceiver() so an SSTP pair is enumerated for
// its transmit side without being mis-classified as transmit-only (finding #10).
// For plain RFC8935/8936 streams HasOutbound() == !IsReceiver(), so they are
// unaffected. Like ListReceiverStreams it is a pure query: no cache mutation, no
// JWKS loading.
func (s *StreamService) ListTransmitterStreams(ctx context.Context) ([]model.StreamStateRecord, error) {
	recs, err := s.streamDAO.List(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]model.StreamStateRecord, 0, len(recs))
	for _, rec := range recs {
		if rec.HasOutbound() {
			out = append(out, rec)
		}
	}
	return out, nil
}

func (s *StreamService) LoadReceiverStreams(ctx context.Context) map[string]*model.StreamStateRecord {
	recs, err := s.ListReceiverStreams(ctx)
	if err != nil {
		ssLog.Error("Error loading receiver streams", "error", err)
		return nil
	}

	res := map[string]*model.StreamStateRecord{}
	for _, streamState := range recs {
		state := streamState
		// An SSTP pair receives on its inbound direction: preload the inbound JWKS
		// keyed under the rx-side SID (== SstpInbound.Id), the key the receive path
		// looks up (finding #1/#2/#10). The tx-side primary config holds no inbound
		// issuer, so loadJwksForReceiver would resolve nothing useful for it.
		if state.GetType() == model.DeliverySstpPair {
			if state.SstpInbound != nil {
				inboundView := state
				inboundView.ValidateJwks = s.loadInboundJwksForPair(ctx, &state)
				res[state.SstpInbound.Id] = &inboundView
			}
			continue
		}
		res[streamState.StreamConfiguration.Id] = &state
		s.loadJwksForReceiver(ctx, &state)
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
		jwks := s.fetchReceiverJwks(ctx, streamState.StreamConfiguration.Id, streamState.Iss, streamState.IssuerJWKSUrl, streamState)
		if jwks != nil {
			streamState.ValidateJwks = jwks
		}
	}
}

// fetchReceiverJwks resolves the verification JWKS for a receiver direction. It
// loads from the explicit iss_jwks_url when set, otherwise from the internally
// registered key for the issuer. On a permanent fetch error it disables the
// owning record (disableRec) and persists it; transient errors are logged and
// left for retry. Returning nil means "no JWKS available" — callers must NOT
// treat that as "verification disabled" (finding #2). Used for both plain
// receiver streams and the inbound direction of an SSTP pair.
func (s *StreamService) fetchReceiverJwks(ctx context.Context, sid, iss, jwksUrl string, disableRec *model.StreamStateRecord) *keyfunc.JWKS {
	var jwks *keyfunc.JWKS
	var err error
	if jwksUrl == "" {
		ssLog.Debug("Attempting to load JWKS internally", "iss", iss)
		jwksJson := s.keyService.GetPublicJWKS(ctx, iss)
		if jwksJson == nil {
			ssLog.Debug("No JWKS key found for issuer", "iss", iss)
			return nil
		}
		jwks, err = keyfunc.NewJSON(*jwksJson)
		if jwks == nil && err != nil {
			ssLog.Error("Unable to parse internal key", "iss", iss, "err", err.Error())
			return nil
		}
		return jwks
	}

	ssLog.Debug("Loading JWKS key", "url", jwksUrl)
	jwks, err = goSet.GetJwks(jwksUrl)
	if err != nil {
		msg := fmt.Sprintf("Error retrieving issuer JWKS public key: %s", err.Error())
		if isPermanentJwksError(err) {
			ssLog.Error("Permanent error loading JWKS, disabling stream", "sid", sid, "error", err.Error())
			if disableRec != nil {
				disableRec.Status = model.StreamStateDisable
				disableRec.ErrorMsg = msg
				if uErr := s.streamDAO.Update(ctx, disableRec); uErr != nil {
					ssLog.Error("Error updating stream status in database", "sid", sid, "error", uErr)
				}
			}
		} else {
			ssLog.Error("Temporary error loading JWKS, will retry", "sid", sid, "error", err.Error())
		}
		return nil
	}
	return jwks
}

// loadInboundJwksForPair resolves the inbound-direction verification JWKS for an
// SSTP pair from its SstpInbound config (inbound iss / iss_jwks_url), honoring the
// pair's InboundStatus (finding #1/#2). It returns nil when the inbound side is
// not enabled or no key is resolvable; a non-nil result is the JWKS that
// goSetPush.ParseReceivedSET must use so a forged inbound SET is rejected.
func (s *StreamService) loadInboundJwksForPair(ctx context.Context, rec *model.StreamStateRecord) *keyfunc.JWKS {
	if rec.SstpInbound == nil || rec.InboundStatus != model.StreamStateEnabled {
		return nil
	}
	return s.fetchReceiverJwks(ctx, rec.SstpInbound.Id, rec.SstpInbound.Iss, rec.SstpInbound.IssuerJWKSUrl, rec)
}

func (s *StreamService) GetIssuerJwksForReceiver(ctx context.Context, sid string) *keyfunc.JWKS {
	// Check cache first
	s.mu.RLock()
	streamState, ok := s.receiverStreams[sid]
	s.mu.RUnlock()
	if ok {
		return streamState.ValidateJwks
	}

	// An SSTP pair receives on its inbound direction whose SID (== SstpInbound.Id)
	// is NOT the document _id, so FindByID(sid) misses. Resolve the pair by its
	// inbound SID and load the JWKS from the inbound config so a forged inbound SET
	// is verified and rejected (finding #1/#2).
	if pair, pErr := s.streamDAO.FindByInboundSID(ctx, sid); pErr == nil && pair != nil {
		inboundView := *pair
		inboundView.ValidateJwks = s.loadInboundJwksForPair(ctx, pair)
		s.mu.Lock()
		s.receiverStreams[sid] = &inboundView
		s.mu.Unlock()
		return inboundView.ValidateJwks
	}

	// Try to load the stream
	streamState, err := s.streamDAO.FindByID(ctx, sid)
	if err != nil {
		ssLog.Error("Error loading receiver stream during JWKS initialization", "sid", sid, "error", err)
		return nil
	}

	if streamState.IsReceiver() {
		s.loadJwksForReceiver(ctx, streamState)
		s.mu.Lock()
		s.receiverStreams[sid] = streamState
		s.mu.Unlock()
		return streamState.ValidateJwks
	}

	return nil
}
