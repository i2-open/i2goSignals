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
	"strings"
	"sync"
	"time"

	"github.com/MicahParks/keyfunc/v2"
	"github.com/i2-open/i2goSignals/pkg/authSupport"
	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
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

// CMintedAudPrefix is the URN namespace for a transmitter-assigned audience
// (ADR 0024). When a strict SSF receiver registers a transmitter stream without
// asserting aud, goSignals mints a fixed, immutable, opaque, URI-shaped audience
// under this prefix, stable for the stream's lifetime.
const CMintedAudPrefix = "urn:i2-open:ssf:aud:"

// isTransmitterMethod reports whether a delivery method denotes a transmit-side
// (RFC8935/RFC8936) stream for which goSignals is the SSF transmitter. The empty
// "DEFAULT" method (a bare/poll create) is treated as transmit-side, matching the
// DeliveryPoll/DEFAULT handling below.
func isTransmitterMethod(method string) bool {
	switch method {
	case model.DeliveryPush, model.DeliveryPoll, "DEFAULT":
		return true
	default:
		return false
	}
}

// mintStreamAud generates a fixed, immutable, opaque, URI-shaped audience for a
// transmitter-assigned stream (ADR 0024). It is JTI-like (a ksuid) so it is
// globally unique and carries no caller-identifying information; the value is
// persisted on the stream and is stable for the stream's lifetime.
func mintStreamAud() string {
	return CMintedAudPrefix + goSet.GenerateJti()
}

type StreamService struct {
	streamDAO               interfaces.StreamDAO
	keyService              *KeyService
	serverService           *ServerService
	subjectFilterService    *SubjectFilterService
	subjectRelayService     *SubjectRelayService
	defaultIssuer           string
	receiverStreams         map[string]*receiverCacheEntry
	BaseUrl                 *url.URL
	mu                      sync.RWMutex
	minVerificationInterval int
	maxInactivityTimeout    int
	eventValidationDefault  model.EventValidationMode

	// now is the clock the JWKS retry backoff is measured against (ADR 0033).
	// It is a field rather than a direct time.Now call so the lazy, per-entry
	// backoff deadline can be driven deterministically from tests without
	// sleeping. Always non-nil: NewStreamService defaults it to time.Now.
	now func() time.Time
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

// normalizeStreamTrustFields applies the "NONE" → empty normalization to the
// stream's IssuerJWKSUrl. Some SCIM peers signal "the key is internal to this
// server" by literally writing "NONE" for IssuerJWKSUrl; downstream code and
// the validateBusinessStreamSecurity invariant expect an empty value in that
// case. Case-insensitive per the historical CreateStream normalization.
func normalizeStreamTrustFields(cfg *model.StreamConfiguration) {
	if cfg == nil {
		return
	}
	if strings.EqualFold(cfg.IssuerJWKSUrl, "NONE") {
		cfg.IssuerJWKSUrl = ""
	}
}

// validateBusinessStreamSecurity enforces the ADR-0066 §D2 invariant: every
// business stream MUST have at least one active authentication layer — L2
// channel auth (bearer / mTLS), OR L3 SET-signature verification against a
// configured trust root (IssuerJWKSUrl + Iss).
//
// In this codebase, the receive-side L2 posture is represented by SigningOnly:
// when SigningOnly is TRUE the transport bearer requirement is dropped
// (see internal/server/api_sstp.go and internal/server/api_receiver.go under
// #184), so the ONLY remaining trust layer is the SET signature — and that
// requires a real trust anchor (Iss + IssuerJWKSUrl). When SigningOnly is
// FALSE the bearer requirement is in force and the L2 layer is active; a
// trust anchor is still allowed (belt-and-suspenders) but is not required.
//
// This function is invariant-only: it does NOT validate SSF-shape fields or
// operator knobs. Call this from every create/update entry point, and from
// startup receiver-stream loading, so a persisted-but-invalid configuration
// cannot go live.
//
// The invariant guard is expressed positively so a diff or a reviewer can
// see it at a glance:
//   - if L2 = None (SigningOnly): trust root MUST be configured.
//   - otherwise: no additional guard.
//
// The "None + unverified" state is not representable through this validator.
func validateBusinessStreamSecurity(cfg model.StreamConfiguration) error {
	if !cfg.SigningOnly {
		// L2 (bearer) is the active authentication layer — invariant satisfied.
		return nil
	}
	// L2 = None; a trust anchor (Iss + IssuerJWKSUrl) is mandatory (ADR-0066 §D2).
	if strings.EqualFold(cfg.IssuerJWKSUrl, "NONE") {
		// Defensive: callers should have normalized this to "" before validating.
		return errors.New(
			"signingOnly (L2=None) requires a configured trust root — " +
				"IssuerJWKSUrl 'NONE' is not a trust root (ADR-0066 §D2)")
	}
	if cfg.Iss == "" || cfg.IssuerJWKSUrl == "" {
		return errors.New(
			"signingOnly (L2=None) requires both iss and issuerJWKSUrl to be " +
				"configured — 'None + unverified' is not a configurable state (ADR-0066 §D2)")
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
// environment.
//
// MinVerificationInterval / MaxInactivityTimeout: any non-positive value
// (absent / zero-valued cfg, an explicit 0, or a negative) means "unset" and
// falls back to the historical defaults (300 / 3600). 0 is deliberately NOT a
// supported operator value for these two knobs: the rest of the stream-config
// layer already treats 0 as "no value set" (a receiver-requested override is
// applied only when > 0, and config-update paths only when != 0), so storing a
// literal 0 as the server default would be read back everywhere as "unset".
// This contract is pinned by TestNewStreamServiceConfigDefaults and was decided
// in issue #182.
// EventValidationDefault: the server-wide fallback for a stream that carries no
// per-stream event_validation value (spec #247 issue #250). An unset, empty, or
// unrecognized value resolves to model.EventValidationNone with a WARN log,
// following the defaulting pattern above.
type StreamServiceConfig struct {
	BaseUrl                 *url.URL
	MinVerificationInterval int
	MaxInactivityTimeout    int
	EventValidationDefault  model.EventValidationMode
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
	eventValidationDefault := cfg.EventValidationDefault
	if eventValidationDefault == model.EventValidationUnset || !eventValidationDefault.Valid() {
		// UNSET is the documented default for every deployment that has not opted
		// in, so it is not a misconfiguration and must not WARN: an operator who
		// sees a new "unrecognized value" warning on every node start and every
		// failover learns to ignore the WARN channel. A genuinely bad value still
		// WARNs — both here and, for the env path, in streamServiceConfigFromEnv.
		if eventValidationDefault != model.EventValidationUnset {
			ssLog.Warn("event validation server default unrecognized — falling back to NONE",
				"requested", string(cfg.EventValidationDefault),
				"effective", string(model.EventValidationNone))
		}
		eventValidationDefault = model.EventValidationNone
	}
	return &StreamService{
		streamDAO:               streamDAO,
		keyService:              keyService,
		defaultIssuer:           defaultIssuer,
		receiverStreams:         make(map[string]*receiverCacheEntry),
		BaseUrl:                 cfg.BaseUrl,
		minVerificationInterval: minVerificationInterval,
		maxInactivityTimeout:    maxInactivityTimeout,
		eventValidationDefault:  eventValidationDefault,
		now:                     time.Now,
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
	// code and the ADR-0066 §D2 invariant expect an empty value.
	normalizeStreamTrustFields(&request.StreamConfiguration)

	// Validate goSignals-specific knobs before any state is mutated. The SSF
	// §9.3 grace override (PRD #97 #98) is validated alongside #89's mode and
	// event-source pipeline a few lines below.
	if err := validateSubjectRemovalGrace(request.SubjectRemovalGraceSeconds); err != nil {
		return model.StreamConfiguration{}, err
	}

	// Per-receiver event-validation mode (spec #247 #250) — shape-checked here,
	// direction-checked by applyEventValidation once the record exists.
	if err := validateEventValidationMode(request.EventValidation); err != nil {
		return model.StreamConfiguration{}, err
	}

	// events_requested patterns must compile, or the stream registers with a
	// silently narrower events_delivered than the receiver asked for.
	if err := validateEventPatterns(request.EventsRequested); err != nil {
		return model.StreamConfiguration{}, err
	}

	// ADR-0066 §D2 invariant — "None + unverified" is not a configurable state
	// (i2goSignals#235). We validate the request as supplied (before Iss is
	// defaulted to the local issuer), so signingOnly can never be silently
	// enabled without a real trust anchor.
	if err := validateBusinessStreamSecurity(request.StreamConfiguration); err != nil {
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
	authCtx, _ := ctx.Value(authSupport.AuthContextKey).(*authSupport.AuthContext)
	if authCtx != nil {
		isOAuth = authCtx.IsOAuthClient
		if authCtx.Eat != nil {
			deliveryParent = &authSupport.AuthContext{Eat: &authSupport.EventAuthToken{}}
			deliveryParent.Eat.ID = authCtx.Eat.ID
		}
	}

	config.Id = mid.Hex()
	config.Aud = request.Aud
	// aud identifies the Event Receiver(s); it is Read-Only / transmitter-asserted
	// (SSF 1.0 §7.1.1) and is echoed into every SET's aud claim, so the transmitter
	// must populate it even when the receiver asserts none. Acceptance is
	// presence-based (ADR 0024): honor a caller-asserted aud verbatim; mint one
	// only when absent.
	if len(config.Aud) == 0 {
		if isTransmitterMethod(request.Delivery.GetMethod()) {
			// Transmitter-assigned aud (ADR 0024): a strict SSF receiver (e.g. the
			// conformance suite) registers without asserting aud and expects the
			// transmitter to supply one (SSF §8.1.1.1). Mint a fixed, immutable,
			// opaque, URI-shaped identifier once at creation; it is persisted on the
			// stream and stable for its lifetime, doubling as the AUDIENCE routing
			// handle (slice 2). It is deliberately opaque — it does NOT leak the
			// caller's client_id or project_id.
			config.Aud = []string{mintStreamAud()}
		} else if authCtx != nil && authCtx.Eat != nil && authCtx.Eat.ClientId != "" {
			// Receiver streams connect to a foreign transmitter; the most specific
			// stable local identity is the registered client_id of a locally issued
			// token, falling back to the project id (the only identity an OAuth/STS
			// caller carries, having no local EAT).
			config.Aud = []string{authCtx.Eat.ClientId}
		} else if projectID != "" {
			config.Aud = []string{projectID}
		}
	}

	config.EventsSupported = model.GetSupportedEvents()

	// An omitted events_requested defaults to the full supported catalog, and any
	// "*" shorthand is enumerated here so the stored/returned configuration is
	// always a concrete URI set (see resolveStreamEvents).
	config.EventsRequested, config.EventsDelivered = resolveStreamEvents(request.EventsRequested, config.EventsSupported)

	delivery := request.Delivery
	config.RouteMode = request.RouteMode
	config.SigningOnly = request.SigningOnly
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
			// Carry the receiver's transmitter-TLS settings onto the synthesized
			// server so discovery and stream registration honor a self-signed or
			// hostname-mismatched transmitter cert (tx_tls_certificate /
			// tx_tls_skip_verify). Without this the inline static path always
			// verified against the system roots regardless of the request fields.
			txServer = &model.Server{
				Host:           *request.TxWellKnownUrl,
				ClientToken:    request.TxToken,
				TLSCertificate: request.TxTLSCertificate,
				TLSSkipVerify:  request.TxTLSSkipVerify || TxTLSSkipVerifyDefault(),
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
		// SSF §7.2.4 issuer binding: the transmitter's advertised issuer must
		// equal the location its discovery document was retrieved from
		// (txServer.Host). jwks_uri stays free-form and is not part of this
		// check. A strict peer (txServer.StrictSsf — the per-peer posture, NOT
		// the goSsfServer-only I2SIG_STRICT_SSF env flag) aborts on a mismatch;
		// a flexible peer only warns. The inline static TxWellKnownUrl path
		// synthesizes txServer without StrictSsf, so it defaults to the flexible
		// warn-and-continue branch.
		if warn, berr := wellKnownSupport.EvaluateIssuerBinding(txConfig.Issuer, txServer.Host, txServer.StrictSsf); berr != nil {
			return model.StreamConfiguration{}, berr
		} else if warn != "" {
			ssLog.Warn(warn, "tx-host", txServer.Host, "advertised-issuer", txConfig.Issuer)
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

		// Skip auto-registration when the caller already supplied a RemoteStreamId:
		// this is the paired/connection flow (e.g. `create stream poll connection`)
		// where the publisher half was just created on the foreign transmitter and
		// we only need to record TxWellKnownUrl + TxToken so the receiver-side can
		// later resolve configuration_endpoint for cascade DELETE (SSF §8.1.1.5)
		// and verify-on-establish. Auto-registering here would POST a duplicate
		// stream-config request to the foreign tx and fail with 409 Conflict.
		alreadyRegistered := request.RemoteStreamId != nil && *request.RemoteStreamId != ""
		if alreadyRegistered {
			config.RemoteStreamId = request.RemoteStreamId
			if request.TxToken != nil && *request.TxToken != "" {
				tok := *request.TxToken
				config.TxToken = &tok
			}
		}

		if !alreadyRegistered && (selectedTxServerParam || (request.TxWellKnownUrl != nil && request.TxToken != nil && *request.TxToken != "" && *request.TxWellKnownUrl != "")) {
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
			// When the resolved transmitter is marked strict (SSF §8.1.1.1) strip
			// the transmitter-owned iss/aud/issuerJWKSUrl from this publisher-leg
			// POST. The shared helper also clears Read-Only fields on every body.
			wireReq := model.StripTransmitterSupplied(transmitStreamReq, txServer != nil && txServer.StrictSsf)
			reqBody, err := json.Marshal(wireReq)
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
			respBody, readErr := io.ReadAll(resp.Body)
			if readErr != nil {
				return model.StreamConfiguration{}, fmt.Errorf("failed to read transmitter registration response: %v", readErr)
			}
			// Tolerate a string-valued aud (RFC 7519 §4.1.3) from the transmitter.
			if err := model.UnmarshalStreamConfigurationJSON(respBody, &txStreamResp); err != nil {
				return model.StreamConfiguration{}, fmt.Errorf("failed to decode transmitter registration response: %v", err)
			}

			// from the response, update config.EventsDelivered with the transmitters response EventsDelivered
			config.EventsDelivered = txStreamResp.EventsDelivered
			// aud/iss are transmitter-asserted, Read-Only (SSF 1.0 §7.1.1): accept the
			// values the transmitter returns, overriding what we requested.
			if len(txStreamResp.Aud) > 0 {
				config.Aud = txStreamResp.Aud
			}
			if txStreamResp.Iss != "" {
				config.Iss = txStreamResp.Iss
			}
			config.TxWellKnownUrl = request.TxWellKnownUrl
			txId := txStreamResp.Id

			txIdPtr := txId
			config.RemoteStreamId = &txIdPtr

			if txStreamResp.Delivery != nil && txStreamResp.Delivery.PollTransmitMethod != nil {

				// Copy the transmitter-issued poll authorization header for the status,
				// management, poll and delete calls. RFC 8936 permits the transmitter to
				// omit it, in which case the receiver keeps using the credential it
				// registered with — otherwise we'd blank out the token and lose access to
				// every subsequent call (the push path guards this the same way).
				if hdr := txStreamResp.Delivery.PollTransmitMethod.AuthorizationHeader; hdr != "" {
					config.TxToken = &hdr // Use for status and verification endpoints
					config.Delivery.PollReceiveMethod.AuthorizationHeader = hdr
				} else {
					config.TxToken = request.TxToken
				}
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

	// Honor an explicit request.RemoteStreamId on receiver-side creates when the
	// auto-registration path above didn't populate it. The CLI's
	// `create stream poll connection` flow registers the publisher half on the
	// foreign transmitter via its own call, then POSTs the receiver half with
	// the transmitter's stream_id in this field — without preserving it,
	// CascadeReceiverStreamDelete (SSF §8.1.1.5) and verify-on-establish have
	// no way to address the transmitter stream by its remote id.
	if config.RemoteStreamId == nil && request.RemoteStreamId != nil && *request.RemoteStreamId != "" {
		deliveryMethod := config.Delivery.GetMethod()
		if deliveryMethod == model.ReceivePoll || deliveryMethod == model.ReceivePush {
			rid := *request.RemoteStreamId
			config.RemoteStreamId = &rid
		}
	}

	// Set the default values based on environment values
	config.InactivityTimeout = int32(s.maxInactivityTimeout)
	config.MinVerificationInterval = int32(s.minVerificationInterval)

	// TxTLSSkipVerify (goSignals extension): the transmitter skips receiver TLS
	// certificate verification when delivering pushes. Honor an explicit per-stream
	// request value (e.g. set by goSignalsAdmin) and allow a deployment-wide default
	// via I2SIG_TX_TLS_SKIP_VERIFY for receivers that present a self-signed / SAN-less
	// cert (dev, conformance). The field is built field-by-field here, so without
	// this copy the request value would be silently dropped.
	config.TxTLSSkipVerify = request.TxTLSSkipVerify || TxTLSSkipVerifyDefault()

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
	} else if isTransmitterMethod(config.Delivery.GetMethod()) && config.Iss == s.defaultIssuer {
		// Transmitter-assigned identity (ADR 0024 / ADR 0023 local-issuer
		// addressing): when goSignals is the SSF transmitter and iss is the
		// advertised issuer, jwks_uri derives from that issuer — the same
		// /jwks.json the .well-known transmitter metadata advertises — so a strict
		// receiver can fetch keys and verify delivered SETs. A caller-asserted
		// foreign iss is left untouched (it is not our key location).
		config.IssuerJWKSUrl = s.getFullUrl("/jwks.json")
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
	} else if defaultSubjects == "" && request.SubjectFilterMode != model.SubjectFilterModePassthru {
		// SSF §8.1.3 Add/Remove-Subject is an optional narrowing of an existing
		// event subscription: a stream that filters locally but subscribes to event
		// types without an explicit baseline must deliver every matching event. The
		// local baseline must be ALL or NONE (never ""), but a create request rarely
		// carries default_subjects, so default the empty case to ALL. Without this,
		// entryDelivers only delivers under an ALL baseline when no per-subject entry
		// exists, so enabling the feature server-wide would silently blackhole every
		// stream's events. PASSTHRU streams are excluded: they filter nothing locally
		// (subject management is relayed upstream), so they carry no local baseline.
		defaultSubjects = model.DefaultSubjectsAll
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

	// Per-receiver event-validation mode (spec #247 #250). Receive-side only:
	// dropped with a WARN on a transmit-only stream. Request value is already
	// shape-checked above by validateEventValidationMode.
	applyEventValidation(streamRec, request.EventValidation)

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

	// If this is a receiver stream, load its JWKS. Resolution happens BEFORE the
	// entry is installed so a JWKS endpoint that is unreachable at create time
	// records the direction unresolved rather than poisoning the cache with a
	// resolved-nil at birth (ADR 0033, GH #264).
	if streamRec.IsReceiver() {
		entry := s.newReceiverEntry(ctx, streamRec)
		s.mu.Lock()
		s.receiverStreams[config.Id] = entry
		s.mu.Unlock()
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
		// When the resolved transmitter is marked strict (SSF §8.1.1.1) strip the
		// transmitter-owned iss/aud/issuerJWKSUrl from this publisher-leg POST.
		// The shared helper also clears Read-Only fields on every body.
		wireReq := model.StripTransmitterSupplied(transmitStreamReq, txServer != nil && txServer.StrictSsf)
		var reqBody []byte
		reqBody, err = json.Marshal(wireReq)
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
		respBody, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			if cleanupErr := s.DeleteStream(ctx, config.Id); cleanupErr != nil {
				ssLog.Error("failed to delete stream during cleanup", "id", config.Id, "error", cleanupErr)
			}
			return model.StreamConfiguration{}, fmt.Errorf("failed to read transmitter registration response: %v", readErr)
		}
		// Tolerate a string-valued aud (RFC 7519 §4.1.3) from the transmitter.
		if err := model.UnmarshalStreamConfigurationJSON(respBody, &txStreamResp); err != nil {
			if cleanupErr := s.DeleteStream(ctx, config.Id); cleanupErr != nil {
				ssLog.Error("failed to delete stream during cleanup", "id", config.Id, "error", cleanupErr)
			}
			return model.StreamConfiguration{}, fmt.Errorf("failed to decode transmitter registration response: %v", err)
		}

		// from the response, update config with the transmitters response values
		config.EventsDelivered = txStreamResp.EventsDelivered
		// aud/iss are transmitter-asserted, Read-Only (SSF 1.0 §7.1.1): accept the
		// values the transmitter returns, overriding what we requested.
		if len(txStreamResp.Aud) > 0 {
			config.Aud = txStreamResp.Aud
		}
		if txStreamResp.Iss != "" {
			config.Iss = txStreamResp.Iss
		}
		// Echo back what we asked the transmitter for, enumerated against the
		// transmitter's own catalog so a "*" shorthand never survives into the
		// stored configuration. An omitted events_requested keeps the full-catalog
		// default already resolved at registration time above.
		if len(request.EventsRequested) > 0 {
			txSupported := txStreamResp.EventsSupported
			if len(txSupported) == 0 {
				txSupported = txStreamResp.EventsDelivered
			}
			config.EventsRequested = expandRequestedEvents(request.EventsRequested, txSupported)
		}
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

// calculateDeliveredEvents resolves the requested event patterns against the
// supported event URIs. The glob semantics live in model.MatchDeliveredEvents so
// exactly one implementation of the pattern -> URI matching exists; this remains
// as the service-local spelling its callers already use.
func (s *StreamService) calculateDeliveredEvents(requested []string, supported []string) []string {
	return model.MatchDeliveredEvents(requested, supported)
}

// resolveStreamEvents turns a registration's events_requested into the
// (events_requested, events_delivered) pair that is persisted on the stream and
// returned to the caller.
//
// Two normalizations happen here:
//
//   - An absent events_requested means "everything you support". SSF 1.0 §7.1.1
//     leaves the field optional, and a stream registered without it previously
//     negotiated an empty events_delivered and so delivered nothing at all —
//     never what a receiver that omitted the field intended.
//   - "*" is a non-standard goSignals shorthand accepted on the way IN only.
//     events_requested and events_delivered are defined as sets of event type
//     URIs, so any wildcard pattern is expanded to the URIs it selects and a
//     returned configuration always enumerates rather than echoing a pattern.
//
// A requested URI carrying no wildcard is preserved verbatim even when this
// transmitter does not support it: events_requested records what the receiver
// asked for, and events_delivered is the subset that was granted.
func resolveStreamEvents(requested []string, supported []string) (events []string, delivered []string) {
	if len(requested) == 0 {
		return copyEvents(supported), copyEvents(supported)
	}
	return expandRequestedEvents(requested, supported),
		copyEvents(model.MatchDeliveredEvents(requested, supported))
}

// expandRequestedEvents replaces every pattern in requested with the concrete
// supported URIs it matches, preserving order and dropping duplicates
// case-insensitively. A requested set containing no pattern is returned
// unchanged.
//
// An entry is treated as a pattern when it is NOT itself one of the supported
// URIs yet still selects at least one of them. Testing for "*" would not do:
// events_requested is a REGULAR EXPRESSION language (see
// model.MatchesEventPattern), so "urn:ietf:params:scim:event:(feed|sig):add" is
// a perfectly legal pattern with no wildcard in it, and echoing it back would
// put a non-URI value in a field SSF 1.0 §7.1.1 defines as a set of event type
// URIs — breaking resolveStreamEvents' own enumerate-never-echo contract.
//
// An entry matching NOTHING is dropped when it is pattern-shaped and preserved
// verbatim otherwise. Both halves are load-bearing: a typo'd pattern must not be
// echoed into the configuration, while a concrete URI this transmitter does not
// support must survive the round trip, because events_requested records what the
// receiver asked for and events_delivered is the subset that was granted.
func expandRequestedEvents(requested []string, supported []string) []string {
	supportedSet := make(map[string]struct{}, len(supported))
	for _, uri := range supported {
		supportedSet[strings.ToLower(uri)] = struct{}{}
	}

	// Resolve each entry once — MatchDeliveredEvents compiles a regexp per call.
	const (
		keepVerbatim = iota
		expand
		drop
	)
	verdicts := make([]int, len(requested))
	expansions := make([][]string, len(requested))
	rewrite := false
	for i, req := range requested {
		if _, exact := supportedSet[strings.ToLower(req)]; exact {
			continue
		}
		if matched := model.MatchDeliveredEvents([]string{req}, supported); len(matched) > 0 {
			verdicts[i], expansions[i] = expand, matched
			rewrite = true
			continue
		}
		if isEventPattern(req) {
			verdicts[i] = drop
			rewrite = true
		}
	}
	if !rewrite {
		return requested
	}

	expanded := make([]string, 0, len(requested))
	seen := make(map[string]struct{}, len(requested))
	add := func(uri string) {
		key := strings.ToLower(uri)
		if _, dup := seen[key]; dup {
			return
		}
		seen[key] = struct{}{}
		expanded = append(expanded, uri)
	}
	for i, req := range requested {
		switch verdicts[i] {
		case drop:
		case expand:
			for _, uri := range expansions[i] {
				add(uri)
			}
		default:
			add(req)
		}
	}
	return expanded
}

// eventPatternMetachars are the regexp metacharacters whose presence marks an
// events_requested entry as a PATTERN rather than a concrete event-type URI.
//
// "." and ":" are deliberately absent even though "." is a live metacharacter:
// every event-type URI in the catalog contains both, so treating them as pattern
// evidence would classify ordinary URIs as patterns and silently drop the
// unsupported ones instead of recording them.
const eventPatternMetachars = `*()|[]?+^${}\`

// isEventPattern reports whether an events_requested entry is pattern-shaped.
// Only consulted for entries that matched no supported URI, to decide between
// dropping a typo'd pattern and preserving an unsupported concrete URI.
func isEventPattern(req string) bool {
	return strings.ContainsAny(req, eventPatternMetachars)
}

// copyEvents returns an independent copy so events_requested, events_delivered
// and events_supported never share a backing array — MatchDeliveredEvents
// returns supported as-is for the "*" shorthand, which would otherwise alias.
func copyEvents(events []string) []string {
	return append([]string{}, events...)
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

	// Per-receiver event-validation mode (spec #247 #250). Shape-checked ahead of
	// the SSTP dispatch so a malformed mode is rejected on both patch paths.
	if err := validateEventValidationMode(configReq.EventValidation); err != nil {
		return nil, err
	}

	// Same for events_requested patterns — checked ahead of the SSTP dispatch so
	// an uncompilable pattern cannot narrow events_delivered on either path.
	if err := validateEventPatterns(configReq.EventsRequested); err != nil {
		return nil, err
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
		// events_supported is Read-Only (SSF 1.0 §7.1.1): the request's copy is
		// ignored outright, so a PATCH body cannot widen — or narrow — what this
		// transmitter claims to support. CreateStream is server-authoritative the
		// same way. Empty events_requested is "not patched" here, so the
		// create-time full-catalog default does not apply.
		//
		// The LIVE catalog rather than the stream's stored events_supported: the
		// catalog can grow between create and patch (an operator adding a vocabulary
		// through EnvEventTypesExtra, issue #261), and re-negotiating against the
		// snapshot taken at create would make every pre-existing stream permanently
		// unable to reach the new types — delete-and-recreate as the only remedy.
		// The stored catalog is refreshed alongside so events_delivered stays a
		// subset of events_supported.
		supported := model.GetSupportedEvents()
		config.EventsSupported = supported
		config.EventsRequested, config.EventsDelivered = resolveStreamEvents(configReq.EventsRequested, supported)
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
		// Iss/Aud are transmitter-asserted (SSF 1.0 §7.1.1). For a receiver
		// stream the asserting transmitter is the foreign one; the CLI bridges
		// the two and may back-patch these once the publisher response is in
		// hand. Without this, inbound SETs fail audience/issuer validation.
		if len(configReq.Aud) > 0 {
			config.Aud = configReq.Aud
		}
		if configReq.Iss != "" {
			config.Iss = configReq.Iss
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
		if len(configReq.Aud) > 0 {
			config.Aud = configReq.Aud
		}
		if configReq.Iss != "" {
			config.Iss = configReq.Iss
		}
		if configReq.MinVerificationInterval != 0 {
			config.MinVerificationInterval = configReq.MinVerificationInterval
		}
		if configReq.InactivityTimeout > 0 {
			config.InactivityTimeout = configReq.InactivityTimeout
		}
	}

	// Signing-only posture (#184) is settable on receiver streams via update; it is a
	// no-op on transmitter streams. Normalize the NONE→empty JWKS-URL sentinel
	// exactly as CreateStream does — the invariant validator below assumes the
	// normalized form. Then apply the ADR-0066 §D2 invariant (i2goSignals#235)
	// so the "None + unverified" state is unreachable via update.
	switch config.Delivery.GetMethod() {
	case model.ReceivePoll, model.ReceivePush:
		config.SigningOnly = configReq.SigningOnly
	}
	normalizeStreamTrustFields(config)
	if err := validateBusinessStreamSecurity(*config); err != nil {
		return nil, err
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

	// Per-receiver event-validation mode (spec #247 #250). Receive-side only;
	// already shape-checked above by validateEventValidationMode.
	applyEventValidation(streamRec, configReq.EventValidation)

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
	s.evictReceiverEntries(streamID)
	return s.streamDAO.Delete(ctx, streamID)
}

// evictReceiverEntries removes every receiver-cache entry belonging to the
// stream named by streamID.
//
// Keying is the subtlety. A plain receiver's entry is keyed by its own SID, so
// deleting by that key worked. An SSTP pair's entry is keyed by the INBOUND SID
// (ADR 0018), which is not the document _id DeleteStream is called with — the
// HTTP delete handler and both pair-create rollback paths in
// stream_service_sstp.go all name the tx-side SID. Deleting by key alone
// therefore orphaned a pair's entry: the record was gone from the DAO while its
// cached JWKS and retry bookkeeping stayed resident for the life of the
// process, and a pair recreated on the same inbound SID would read the stale
// entry instead of resolving afresh.
//
// The sweep matches on the record's identities rather than on the map key, so
// eviction is correct whichever SID the caller names. It runs over receiver
// entries only — a handful per node — so the linear scan is not worth trading
// for a second index.
func (s *StreamService) evictReceiverEntries(streamID string) {
	if streamID == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.receiverStreams, streamID)
	for sid, entry := range s.receiverStreams {
		if entry != nil && recordIdentifiedBy(entry.record, streamID) {
			delete(s.receiverStreams, sid)
		}
	}
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
	s.mu.Lock()
	if entry, ok := s.receiverStreams[streamID]; ok {
		entry.record.Status = status
		entry.record.ErrorMsg = errorMsg
	}
	s.mu.Unlock()
}

func (s *StreamService) UpdateRemoteAddress(ctx context.Context, streamID string, addr *model.RemoteIP) {
	err := s.streamDAO.UpdateRemoteAddress(ctx, streamID, addr)
	if err != nil {
		ssLog.Error("Error updating remote address", "streamID", streamID, "error", err)
	}

	// Update cache if receiver stream
	s.mu.Lock()
	if entry, ok := s.receiverStreams[streamID]; ok {
		entry.record.RemoteAddress = addr
	}
	s.mu.Unlock()
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

	res := map[string]*receiverCacheEntry{}
	for _, streamState := range recs {
		state := streamState

		// ADR-0066 §D2 (i2goSignals#235) fail-closed startup guard: if a
		// persisted stream violates the "at least one active auth layer"
		// invariant — i.e. it was configured by an older validator that let
		// "None + unverified" through — disable it here rather than surface a
		// live unauthenticated event-injection endpoint. Operator must
		// reconfigure it (with a JWKS URL, or SigningOnly=false) before it
		// will accept traffic again. A single WARN with the SID + the concrete
		// violation makes the remediation obvious.
		if err := s.disableIfSecurityInvariantViolated(ctx, &state); err != nil {
			// Persisting the disabled status failed — do NOT surface the
			// stream: skip loading it entirely so it cannot serve requests.
			ssLog.Error("Fail-closed: skipping load of security-invariant-violating stream",
				"sid", state.StreamConfiguration.Id, "error", err)
			continue
		}

		// An SSTP pair receives on its inbound direction: preload the inbound JWKS
		// keyed under the rx-side SID (== SstpInbound.Id), the key the receive path
		// looks up (finding #1/#2/#10). The tx-side primary config holds no inbound
		// issuer, so loadJwksForReceiver would resolve nothing useful for it.
		if state.GetType() == model.DeliverySstpPair {
			if state.SstpInbound != nil {
				inboundView := state
				res[state.SstpInbound.Id] = s.newReceiverEntry(ctx, &inboundView)
			}
			continue
		}
		res[streamState.StreamConfiguration.Id] = s.newReceiverEntry(ctx, &state)
	}
	s.mu.Lock()
	s.receiverStreams = res
	s.mu.Unlock()

	out := make(map[string]*model.StreamStateRecord, len(res))
	for sid, entry := range res {
		out[sid] = entry.record
	}
	return out
}

// disableIfSecurityInvariantViolated re-validates a persisted receiver stream
// against ADR-0066 §D2 at load time and, if the invariant is violated, marks
// the stream disabled with a clear operator-visible error message. The
// resulting record is written back through the DAO so the disabled state
// survives a restart. Returns any DAO write error so the caller can decide
// whether to surface the stream at all.
//
// The invariant is applied to both the primary StreamConfiguration and the
// SstpInbound leg (an SSTP pair's rx-side has its own iss/JWKS/signing-only
// posture). If either violates, the pair is disabled — a partially-invariant
// pair cannot safely accept inbound events.
func (s *StreamService) disableIfSecurityInvariantViolated(
	ctx context.Context, rec *model.StreamStateRecord,
) error {
	normalizeStreamTrustFields(&rec.StreamConfiguration)
	if err := validateBusinessStreamSecurity(rec.StreamConfiguration); err != nil {
		return s.disableInvariantViolation(ctx, rec, "primary", err)
	}
	if rec.SstpInbound != nil {
		normalizeStreamTrustFields(rec.SstpInbound)
		if err := validateBusinessStreamSecurity(*rec.SstpInbound); err != nil {
			return s.disableInvariantViolation(ctx, rec, "sstp-inbound", err)
		}
	}
	return nil
}

// disableInvariantViolation writes the fail-closed disabled state back to the
// DAO and emits a single WARN naming the violation source ("primary" vs
// "sstp-inbound"), the stream SID, and the invariant error. Split out from
// disableIfSecurityInvariantViolated so both legs share the same disable
// path.
//
// The disable routes through applyStreamStatusToRecord so a pair is disabled in
// BOTH directions, which is what fail-closed requires here: inbound ingest is
// gated on InboundStatus ALONE (runner_sstp_server.go), so a pair carrying a
// disable only on Status would go on accepting inbound events on the very leg
// whose trust root is missing. Which leg the violation is on does not steer the
// routing, because a disable is pair-level either way (Q39); the leg is carried
// in the reason instead.
func (s *StreamService) disableInvariantViolation(
	ctx context.Context, rec *model.StreamStateRecord, leg string, invariantErr error,
) error {
	sid := rec.StreamConfiguration.Id
	ssLog.Warn("Fail-closed: disabling receiver stream that violates ADR-0066 §D2 (None + unverified)",
		"sid", sid, "leg", leg, "invariant", invariantErr.Error())
	applyStreamStatusToRecord(rec, sid, model.StreamStateDisable,
		"ADR-0066 §D2 invariant violation ("+leg+"): "+invariantErr.Error())
	if err := s.streamDAO.Update(ctx, rec); err != nil {
		return fmt.Errorf("persist disabled state: %w", err)
	}
	return nil
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

// receiveDirectionSnapshot is an immutable copy of everything one resolution
// attempt needs from a stream record. Resolution runs with the cache lock
// released (ADR 0033), so it must not touch the shared record at all: the
// caller snapshots the direction under the lock, resolves from the snapshot,
// and folds any record mutation back under the lock. Reading the record from
// the resolver instead would race UpdateStreamStatus and UpdateRemoteAddress,
// which write these same fields under s.mu.
type receiveDirectionSnapshot struct {
	sid     string
	iss     string
	jwksUrl string // already "NONE"-normalized

	// present is false when the record has no resolvable receive direction at
	// all — a nil record, or a pair with no inbound leg.
	present bool

	// enabled is the direction's OWN status: Status for a plain receiver,
	// InboundStatus for the inbound leg of an SSTP pair (findings #1/#2).
	enabled bool

	tlsSkipVerify bool
	tlsCert       string
}

// snapshotReceiveDirection copies the receive direction of rec. Callers must
// either hold s.mu or own rec exclusively (a freshly loaded record, or a local
// copy, that has not yet been published to the receiver cache).
func snapshotReceiveDirection(rec *model.StreamStateRecord) receiveDirectionSnapshot {
	if rec == nil {
		return receiveDirectionSnapshot{}
	}
	snap := receiveDirectionSnapshot{
		present:       true,
		tlsSkipVerify: rec.TxTLSSkipVerify,
		tlsCert:       rec.TxTLSCertificate,
	}
	if rec.GetType() == model.DeliverySstpPair {
		if rec.SstpInbound == nil {
			return receiveDirectionSnapshot{}
		}
		snap.sid = rec.SstpInbound.Id
		snap.iss = rec.SstpInbound.Iss
		snap.jwksUrl = normalizedJwksUrl(rec.SstpInbound.IssuerJWKSUrl)
		snap.enabled = rec.InboundStatus == model.StreamStateEnabled
		return snap
	}
	snap.sid = rec.StreamConfiguration.Id
	snap.iss = rec.StreamConfiguration.Iss
	snap.jwksUrl = normalizedJwksUrl(rec.StreamConfiguration.IssuerJWKSUrl)
	snap.enabled = rec.Status == model.StreamStateEnabled
	return snap
}

// newReceiverEntry resolves the receive direction of rec and returns a fully
// formed receiver-cache entry. It is the single place a cache slot is built, so
// the ADR 0033 discriminator and the retry bookkeeping cannot drift between the
// populate sites (the startup preload in LoadReceiverStreams, CreateStream, and
// both miss paths in GetIssuerJwksForReceiver). rec is owned exclusively by the
// caller at every one of those sites — it is not yet in the cache — so it is
// snapshotted, resolved, and mutated here without the lock.
func (s *StreamService) newReceiverEntry(ctx context.Context, rec *model.StreamStateRecord) *receiverCacheEntry {
	snap := snapshotReceiveDirection(rec)
	entry := &receiverCacheEntry{record: rec, jwksUrl: snap.jwksUrl}
	jwks, err := s.resolveSnapshotJwks(ctx, snap)
	entry.recordAttempt(s.now(), jwks, err)
	if reason, permanent := permanentJwksFailure(err); permanent {
		// snap.sid names the direction that failed, so the disable routes
		// through the same Q39 rule as every other status change.
		applyStreamStatusToRecord(rec, snap.sid, model.StreamStateDisable, reason)
		s.persistDisabledRecord(ctx, rec, snap.sid)
	}
	// Keep the record's ValidateJwks in step with the entry so nothing reading
	// the record observes material the entry has judged unusable. On the no-URL
	// branch the internal lookup is authoritative and its result is stored
	// verbatim, zero-key JWKS included (ADR 0033 leaves that branch alone).
	rec.ValidateJwks = entry.jwks
	return entry
}

// resolveSnapshotJwks performs one JWKS resolution attempt for a snapshotted
// receive direction. It reads no shared record and mutates nothing, so it is
// safe to call with the cache lock released. A direction that is absent or not
// enabled returns errDirectionNotEnabled without touching the network, keeping
// that outcome distinguishable from a failed fetch (ADR 0033 names it as the
// third of the three nils that must not be folded together).
func (s *StreamService) resolveSnapshotJwks(ctx context.Context, snap receiveDirectionSnapshot) (*keyfunc.JWKS, error) {
	if !snap.present || !snap.enabled {
		return nil, errDirectionNotEnabled
	}
	return s.fetchReceiverJwks(ctx, snap)
}

// permanentJwksFailure classifies a resolution error, returning the reason to
// persist when the error is one isPermanentJwksError treats as permanent. The
// classification is split out from the fetch so the caller decides WHEN to act
// on it: on the retry path the fetch runs unlocked and the record may have been
// deleted in the meantime, and writing the disable blind would resurrect it.
func permanentJwksFailure(err error) (string, bool) {
	if err == nil || errors.Is(err, errDirectionNotEnabled) || !isPermanentJwksError(err) {
		return "", false
	}
	return fmt.Sprintf("Error retrieving issuer JWKS public key: %s", err.Error()), true
}

// persistDisabledRecord writes a disabled record through the DAO. The caller
// must NOT hold s.mu: this is a database round trip, and the cache lock is on
// the inbound verification path.
func (s *StreamService) persistDisabledRecord(ctx context.Context, rec *model.StreamStateRecord, sid string) {
	if rec == nil {
		return
	}
	if uErr := s.streamDAO.Update(ctx, rec); uErr != nil {
		ssLog.Error("Error updating stream status in database", "sid", sid, "error", uErr)
	}
}

// fetchReceiverJwks resolves the verification JWKS for a snapshotted receive
// direction. It loads from the explicit iss_jwks_url when set, otherwise from
// the internally registered key for the issuer. It reads no shared record and
// mutates nothing — the caller classifies the returned error and owns any
// record mutation that follows (ADR 0033) — so it is safe to call with the
// cache lock released. A nil JWKS means "no JWKS available"; callers must NOT
// treat that as "verification disabled" (finding #2). Used for both plain
// receiver streams and the inbound direction of an SSTP pair.
func (s *StreamService) fetchReceiverJwks(ctx context.Context, snap receiveDirectionSnapshot) (*keyfunc.JWKS, error) {
	if snap.jwksUrl == "" {
		ssLog.Debug("Attempting to load JWKS internally", "iss", snap.iss)
		jwksJson := s.keyService.GetPublicJWKS(ctx, snap.iss)
		if jwksJson == nil {
			ssLog.Debug("No JWKS key found for issuer", "iss", snap.iss)
			return nil, nil
		}
		jwks, err := keyfunc.NewJSON(*jwksJson)
		if jwks == nil && err != nil {
			ssLog.Error("Unable to parse internal key", "iss", snap.iss, "err", err.Error())
			return nil, err
		}
		return jwks, nil
	}

	ssLog.Debug("Loading JWKS key", "url", snap.jwksUrl)
	// Honor the stream's transmitter TLS settings so the issuer JWKS can be
	// fetched even when the transmitter presents a self-signed certificate;
	// otherwise the load fails TLS verification and retries indefinitely.
	var jwksClient *http.Client
	skip := snap.tlsSkipVerify || TxTLSSkipVerifyDefault()
	if skip || snap.tlsCert != "" {
		jwksClient = oauthClient.GetBaseHTTPClientForServer(&model.Server{
			TLSSkipVerify:  skip,
			TLSCertificate: snap.tlsCert,
		})
	}
	jwks, err := goSet.GetJwksWithClient(snap.jwksUrl, jwksClient)
	if err != nil {
		if isPermanentJwksError(err) {
			ssLog.Error("Permanent error loading JWKS, disabling stream", "sid", snap.sid, "error", err.Error())
		} else {
			// Deliberately WARN, not ERROR (CONTEXT.md log-level policy: "a
			// stream that fails to connect on a single attempt — treat as WARN
			// until the retry budget is exhausted"). Since ADR 0033 this line
			// repeats on every backoff attempt rather than firing once, so
			// ERROR here would be a standing noise floor on a condition that
			// recovers itself. The exhausted-budget promotion to ERROR is the
			// permanent branch above.
			ssLog.Warn("Temporary error loading JWKS, will retry", "sid", snap.sid, "error", err.Error())
		}
		return nil, err
	}
	return jwks, nil
}

// GetIssuerJwksForReceiver returns the verification material for a receive SID,
// or nil when none is available (fail-closed: callers must reject rather than
// admit unverified).
//
// Entry PRESENCE is not the answer. An entry that expects verification material
// (ADR 0033: it has an issuer JWKS URL) and does not hold usable keys is
// *unresolved*, and a lookup past its backoff deadline re-attempts the fetch.
// That is what makes the "will retry" the transient-error log promises actually
// happen — before GH #264 the nil was cached under the SID and every later
// lookup was a hit on it for the life of the process.
func (s *StreamService) GetIssuerJwksForReceiver(ctx context.Context, sid string) *keyfunc.JWKS {
	s.mu.RLock()
	entry, ok := s.receiverStreams[sid]
	var (
		cached *keyfunc.JWKS
		due    bool
	)
	if ok {
		cached = entry.jwks
		due = entry.dueForRetry(s.now())
	}
	s.mu.RUnlock()
	if ok {
		if !due {
			return cached
		}
		return s.retryReceiverJwks(ctx, sid)
	}

	// An SSTP pair receives on its inbound direction whose SID (== SstpInbound.Id)
	// is NOT the document _id, so FindByID(sid) misses. Resolve the pair by its
	// inbound SID and load the JWKS from the inbound config so a forged inbound SET
	// is verified and rejected (finding #1/#2).
	if pair, pErr := s.streamDAO.FindByInboundSID(ctx, sid); pErr == nil && pair != nil {
		inboundView := *pair
		newEntry := s.newReceiverEntry(ctx, &inboundView)
		s.mu.Lock()
		s.receiverStreams[sid] = newEntry
		s.mu.Unlock()
		return newEntry.jwks
	}

	// Try to load the stream
	streamState, err := s.streamDAO.FindByID(ctx, sid)
	if err != nil {
		ssLog.Error("Error loading receiver stream during JWKS initialization", "sid", sid, "error", err)
		return nil
	}

	if streamState.IsReceiver() {
		newEntry := s.newReceiverEntry(ctx, streamState)
		s.mu.Lock()
		s.receiverStreams[sid] = newEntry
		s.mu.Unlock()
		return newEntry.jwks
	}

	return nil
}

// retryReceiverJwks re-attempts resolution for an unresolved cache entry whose
// backoff deadline has passed. The cache lock is deliberately NOT held across
// the network call: it is acquired once to claim the attempt (which also stops
// concurrent lookups stampeding the endpoint) and again to fold in the outcome.
// The second acquisition tolerates a concurrent writer having resolved,
// replaced, or evicted the entry in between (ADR 0033).
func (s *StreamService) retryReceiverJwks(ctx context.Context, sid string) *keyfunc.JWKS {
	s.mu.Lock()
	entry, ok := s.receiverStreams[sid]
	if !ok {
		s.mu.Unlock()
		return nil
	}
	if !entry.dueForRetry(s.now()) {
		jwks := entry.jwks
		s.mu.Unlock()
		return jwks
	}
	entry.inFlight = true
	rec := entry.record
	// Snapshot under the lock: the fetch below runs unlocked, and every field
	// it needs is also written by UpdateStreamStatus/UpdateRemoteAddress under
	// this same lock. Passing rec into the resolver instead would be a data
	// race on Status/InboundStatus/TxTLS*.
	snap := snapshotReceiveDirection(rec)
	s.mu.Unlock()

	ssLog.Debug("Re-attempting issuer JWKS resolution", "sid", sid, "url", snap.jwksUrl)
	jwks, err := s.resolveSnapshotJwks(ctx, snap)
	reason, permanent := permanentJwksFailure(err)

	s.mu.Lock()
	entry.inFlight = false
	current, stillCached := s.receiverStreams[sid]
	if !stillCached {
		// Evicted (DeleteStream) while the fetch was in flight. The outcome is
		// dropped rather than applied: writing a permanent-failure disable here
		// would resurrect a record the DAO has already deleted.
		s.mu.Unlock()
		return nil
	}
	if current != entry {
		// A concurrent writer replaced the entry; its result wins.
		jwks := current.jwks
		s.mu.Unlock()
		return jwks
	}
	if entry.resolved() {
		// A concurrent writer resolved this same entry while we were fetching.
		jwks := entry.jwks
		s.mu.Unlock()
		return jwks
	}
	entry.recordAttempt(s.now(), jwks, err)
	rec.ValidateJwks = entry.jwks
	// persistCopy is taken under the lock so the DAO round trip below marshals
	// a private copy rather than the record UpdateStreamStatus may be writing.
	var persistCopy *model.StreamStateRecord
	if permanent {
		// Still under s.mu: these are the fields UpdateStreamStatus writes.
		applyStreamStatusToRecord(rec, snap.sid, model.StreamStateDisable, reason)
		snapshotRec := *rec
		persistCopy = &snapshotRec
	}
	result := entry.jwks
	nowResolved := entry.resolved()
	s.mu.Unlock()

	if persistCopy != nil {
		// Outside the lock: a DAO round trip must not block the inbound
		// verification path that shares this mutex.
		s.persistDisabledRecord(ctx, persistCopy, sid)
	}
	if nowResolved {
		ssLog.Info("Issuer JWKS resolved on retry", "sid", sid)
	}
	return result
}

// OverlayJwksReadiness stamps this node's derived, never-persisted JWKS
// readiness onto a record's receive direction(s) (ADR 0033). The admin
// stream-state surfaces source their records from the DAO and never consult the
// receiver cache, so they must call this before serializing or readiness is
// always absent. Transmit-only streams are left untouched.
func (s *StreamService) OverlayJwksReadiness(rec *model.StreamStateRecord) {
	if s == nil || rec == nil {
		return
	}
	if rec.GetType() == model.DeliverySstpPair {
		// The cache is keyed by the inbound SID for a pair (ADR 0018), so the
		// pair's readiness is reported on the inbound twin.
		if rec.SstpInbound != nil {
			rec.InboundJwksReadiness = s.jwksReadinessFor(rec.SstpInbound.Id, rec.SstpInbound.IssuerJWKSUrl)
		}
		return
	}
	if rec.IsReceiver() {
		rec.JwksReadiness = s.jwksReadinessFor(rec.StreamConfiguration.Id, rec.StreamConfiguration.IssuerJWKSUrl)
	}
}

// jwksReadinessFor derives readiness for one receive direction: from the cache
// entry when this node holds one, otherwise from the configuration alone — a
// URL this node has not resolved is unresolved, never ready.
func (s *StreamService) jwksReadinessFor(sid, jwksUrl string) *model.JwksReadiness {
	s.mu.RLock()
	entry, ok := s.receiverStreams[sid]
	var readiness *model.JwksReadiness
	if ok {
		readiness = entry.readiness()
	}
	s.mu.RUnlock()
	if readiness != nil {
		return readiness
	}
	if !expectsVerificationMaterial(jwksUrl) {
		return &model.JwksReadiness{State: model.JwksReadinessNotConfigured}
	}
	return &model.JwksReadiness{State: model.JwksReadinessUnresolved}
}
