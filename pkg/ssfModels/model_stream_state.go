package model

import (
	"fmt"
	"net/http"
	"time"

	"github.com/MicahParks/keyfunc/v2"
	"go.mongodb.org/mongo-driver/v2/bson"
)

// RemoteIP holds the network address details of a remote peer on a stream connection.
type RemoteIP struct {
	Protocol  string `json:"protocol,omitempty" bson:"protocol,omitempty"`
	IP        string `json:"ip,omitempty" bson:"ip,omitempty"`
	Forwarded string `json:"forwarded,omitempty" bson:"forwarded,omitempty"`
}

// BuildRemoteIPFromRequest constructs a RemoteIP from an inbound HTTP request.
// Protocol is "https" when r.TLS != nil, otherwise "http".
// Forwarded is taken from X-Forwarded-For, falling back to X-Real-IP.
func BuildRemoteIPFromRequest(r *http.Request) *RemoteIP {
	proto := "http"
	if r.TLS != nil {
		proto = "https"
	}
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded == "" {
		forwarded = r.Header.Get("X-Real-IP")
	}
	return &RemoteIP{
		Protocol:  proto,
		IP:        r.RemoteAddr,
		Forwarded: forwarded,
	}
}

// BuildOutboundRemoteIP constructs a RemoteIP for an outbound connection (e.g. push transmitter).
// scheme is the URL scheme ("http" or "https"); capturedAddr is the dialed address.
// Forwarded is always empty for outbound connections.
func BuildOutboundRemoteIP(scheme, capturedAddr string) *RemoteIP {
	return &RemoteIP{
		Protocol: scheme,
		IP:       capturedAddr,
	}
}

// Equals reports whether r and other represent the same peer address.
func (r *RemoteIP) Equals(other *RemoteIP) bool {
	if r == nil || other == nil {
		return r == nil && other == nil
	}
	return r.IP == other.IP && r.Protocol == other.Protocol && r.Forwarded == other.Forwarded
}

func (r *RemoteIP) String() string {
	if r == nil {
		return ""
	}
	if r.Forwarded != "" {
		return fmt.Sprintf("%s://%s (forwarded via %s)", r.Protocol, r.Forwarded, r.IP)
	}
	return fmt.Sprintf("%s://%s", r.Protocol, r.IP)
}

// StreamStateRecord is stored in MongoProvider.streamCol
type StreamStateRecord struct {
	Id                  bson.ObjectID `bson:"_id" json:"id,omitempty"`
	ProjectId           string        `json:"project_id" bson:"project_id" json:"projectId,omitempty"` // ProjectId links SsfClient entities to streams.
	StreamConfiguration `bson:",inline"`
	StartDate           time.Time `json:"start_date" bson:"start_date" json:"startDate"`
	CreatedAt           time.Time `json:"created_at" bson:"created_at" json:"createdAt"`
	ModifiedAt          time.Time `json:"modified_at" bson:"modified_at" json:"modifiedAt"`

	// Status indicates the current operational status and is one of StreamStateEnabled, StreamStatePause, StreamStateDisable
	Status string `json:"status" bson:"status" json:"status,omitempty"`

	// ValidateJwks is used when in Inbound mode to validate the inbound issuer. This value acts like a cache
	ValidateJwks *keyfunc.JWKS `json:"-" bson:"-" json:"validateJwks,omitempty"` // not persisted

	// ErrorMsg holds the reason a stream has been paused
	ErrorMsg string `json:"reason,omitempty" bson:"error_msg,omitempty" json:"errorMsg,omitempty"`

	RemoteAddress *RemoteIP `json:"remote_address,omitempty" bson:"remote_address,omitempty"`

	// DefaultSubjects is the SSF subject-filtering baseline policy for a
	// transmitter stream: DefaultSubjectsAll or DefaultSubjectsNone. It is a
	// goSignals operator knob and is deliberately kept off the SSF wire-format
	// StreamConfiguration. An empty value means the default (ALL).
	DefaultSubjects string `json:"default_subjects,omitempty" bson:"default_subjects,omitempty"`

	// SubjectFilterMode governs how a receiver stream relays subject changes to
	// its upstream transmitter: SubjectFilterModePassthru, SubjectFilterModeLocal,
	// or SubjectFilterModeHybrid.
	SubjectFilterMode string `json:"subject_filter_mode,omitempty" bson:"subject_filter_mode,omitempty"`

	// EventSource describes where a transmitter stream's events originate.
	EventSource *EventSource `json:"event_source,omitempty" bson:"event_source,omitempty"`

	// SubjectRemovalGraceSeconds is the per-transmitter-stream override of the
	// SSF §9.3 removal grace period (PRD #97 issue #98). `0` (or unset) means
	// immediate enforcement and falls back to the server-wide
	// `I2SIG_SUBJECT_REMOVAL_GRACE` default. The override is honored only on
	// transmitter streams; an override set on a receiver stream is ignored at
	// CreateStream/UpdateStream with a WARN. No enforcement is wired up in this
	// slice — it is settable, persisted, and round-trippable.
	SubjectRemovalGraceSeconds int `json:"subject_removal_grace_seconds,omitempty" bson:"subject_removal_grace_seconds,omitempty"`
}

// EventSource describes where a transmitter stream's events originate. This is
// a distinct axis from RouteMode. Type is one of EventSourceDirect,
// EventSourceAudience, or EventSourceExplicit; when EventSourceExplicit,
// SourceStreamIds names the source stream SID(s).
type EventSource struct {
	Type            string   `json:"type,omitempty" bson:"type,omitempty"`
	SourceStreamIds []string `json:"source_stream_ids,omitempty" bson:"source_stream_ids,omitempty"`
}

// DeepCopy returns an independent copy of the EventSource, or nil when es is nil.
func (es *EventSource) DeepCopy() *EventSource {
	if es == nil {
		return nil
	}
	res := *es
	if es.SourceStreamIds != nil {
		res.SourceStreamIds = make([]string, len(es.SourceStreamIds))
		copy(res.SourceStreamIds, es.SourceStreamIds)
	}
	return &res
}

func (ss *StreamStateRecord) DeepCopy() *StreamStateRecord {
	if ss == nil {
		return nil
	}
	res := *ss
	res.StreamConfiguration = ss.StreamConfiguration.DeepCopy()
	res.EventSource = ss.EventSource.DeepCopy()
	return &res
}

func (ss *StreamStateRecord) Update(mod *StreamStateRecord) {
	// This is being done to preserve the handle on the PushStreams.
	ss.Status = mod.Status
	ss.ErrorMsg = mod.ErrorMsg
	// ss.Receiver = mod.Receiver - now handled by StreamConfiguration

	ss.ValidateJwks = mod.ValidateJwks

	ss.StreamConfiguration = mod.StreamConfiguration
	ss.StartDate = mod.StartDate
	ss.ModifiedAt = mod.ModifiedAt
	ss.RemoteAddress = mod.RemoteAddress
	ss.DefaultSubjects = mod.DefaultSubjects
	ss.SubjectFilterMode = mod.SubjectFilterMode
	ss.EventSource = mod.EventSource
	ss.SubjectRemovalGraceSeconds = mod.SubjectRemovalGraceSeconds
}

// GetType returns the delivery method for the stream state record. Returns one of ReceivePush, ReceivePoll, DeliveryPush, DeliveryPoll.
func (ss *StreamStateRecord) GetType() string {
	return ss.Delivery.GetMethod()
}

func (ss *StreamStateRecord) IsReceiver() bool {
	switch ss.GetType() {
	case ReceivePush, ReceivePoll:
		return true
	default:
		return false
	}
}

func (ss *StreamStateRecord) HasTxServer() bool {
	if ss.TxAlias != nil && *ss.TxAlias != "" {
		return true
	}
	if ss.TxWellKnownUrl != nil && *ss.TxWellKnownUrl != "" {
		return true
	}
	return false
}

func (ss *StreamStateRecord) GetRouteMode() string {
	return ss.StreamConfiguration.RouteMode
}

const (
	// DeliveryPoll indicates that a stream delivers events using HTTP Set Delivery via Polling using HTTP GET by the receiver. It defines an SSF transmitter.
	DeliveryPoll = "urn:ietf:rfc:8936"

	// DeliveryPush indicates that a stream delivers events using HTTP Set Delivery via Pushing using HTTP POST by the transmitter. It defines an SSF transmitter.
	DeliveryPush = "urn:ietf:rfc:8935"

	// ReceivePoll indicates that a stream receives events using HTTP Set Delivery via Polling using HTTP GET by the receiver. It defines an SSF receiver. This is used by goSignals to define the receiver half of a transmitter/receiver pair.
	ReceivePoll = "urn:ietf:rfc:8936:receive"

	// ReceivePush indicates that a stream receives events using HTTP Set Delivery via PUSH using HTTP POST by the transmitter. It defines an SSF receiver. This is used by goSignals to define the receiver half of a transmitter/receiver pair.
	ReceivePush = "urn:ietf:rfc:8935:receive"

	StreamStateEnabled  = "enabled"
	StreamStatePause    = "paused"
	StreamStateDisable  = "disabled"
	StreamPollBatchSize = 5
	RouteModeImport     = "IM" // Indicates the router will not further propagate the event and save to database for local use
	RouteModeForward    = "FW" // Indicates the router will move events received to other eligable streams
	RouteModePublish    = "PB" // Indicates the router will router to target streams and generate new JWS/JWE tokens

	// DefaultSubjects baseline policy values for a transmitter stream (SSF §8.1.3).
	DefaultSubjectsAll  = "ALL"  // Deliver every subject unless explicitly removed
	DefaultSubjectsNone = "NONE" // Deliver no subject unless explicitly added

	// SubjectFilterMode values for a receiver stream: how subject changes relay upstream.
	SubjectFilterModePassthru = "PASSTHRU" // Relay Add/Remove 1:1 upstream, no local filtering
	SubjectFilterModeLocal    = "LOCAL"    // Filter locally per stream, never relay upstream
	SubjectFilterModeHybrid   = "HYBRID"   // Relay upstream and filter locally

	// EventSource Type values: where a transmitter stream's events originate.
	EventSourceDirect   = "DIRECT"   // Events arrive directly on this stream
	EventSourceAudience = "AUDIENCE" // Events routed in by audience matching
	EventSourceExplicit = "EXPLICIT" // Events sourced from explicitly named stream SID(s)
)
