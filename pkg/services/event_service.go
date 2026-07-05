package services

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/logger"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
)

var esLog = logger.Sub("EVENT_SERVICE")

// ResetEgressObserver is notified once per event that ResetEventStream re-queues
// onto a stream. A stream reset re-delivers already-stored events as fresh
// chargeable egress (ADR 0055 Q91.4), but it re-queues them directly — bypassing
// the event-router fan-out where egress is normally metered — so ResetEventStream
// reports them here instead. The sink tags the resulting observation source:reset.
// A protocol replay (a re-poll of a still-pending, unacked event) never enters
// this path and stays free by construction.
type ResetEgressObserver interface {
	ObserveResetEgress(streamID string, event *model.EventRecord)
}

type EventService struct {
	eventDAO interfaces.EventDAO
	// resetEgressObserver, when non-nil, receives one call per event
	// ResetEventStream re-queues, so reset re-deliveries are metered as fresh
	// egress. nil (the default) leaves the reset path unmetered — the community
	// build registers none, mirroring the event-router metering observer.
	resetEgressObserver ResetEgressObserver
}

func NewEventService(eventDAO interfaces.EventDAO) *EventService {
	return &EventService{
		eventDAO: eventDAO,
	}
}

// SetResetEgressObserver installs (or clears, with nil) the sink notified per
// event re-queued by ResetEventStream. The event router wires itself here at
// construction so reset re-deliveries flow to the same metering observer the
// fan-out egress uses (ADR 0055 Q91.4).
func (s *EventService) SetResetEgressObserver(observer ResetEgressObserver) {
	s.resetEgressObserver = observer
}

func (s *EventService) AddEvent(ctx context.Context, event *goSet.SecurityEventToken, sid string, raw string) (*model.EventRecord, error) {
	return s.addEvent(ctx, event, sid, raw, false)
}

// AddOperationalEvent persists an operational event (Operational=true). Operational events are point-to-point
// SSF protocol events (verify, stream-updated) scoped to a single SSF endpoint relationship and are excluded
// from ResetDate/ResetJti replay queries.
func (s *EventService) AddOperationalEvent(ctx context.Context, event *goSet.SecurityEventToken, sid string, raw string) (*model.EventRecord, error) {
	return s.addEvent(ctx, event, sid, raw, true)
}

func (s *EventService) addEvent(ctx context.Context, event *goSet.SecurityEventToken, sid string, raw string, operational bool) (*model.EventRecord, error) {
	jti := event.ID
	keys := make([]string, 0, len(event.Events))
	for k := range event.Events {
		keys = append(keys, k)
	}

	// The event time for searching is in order of preference the toe, iat, or current time
	var sortTime time.Time
	if event.TimeOfEvent != nil {
		sortTime = event.TimeOfEvent.Time
	} else if event.IssuedAt != nil {
		sortTime = event.IssuedAt.Time
	} else {
		sortTime = time.Now()
	}

	rec := &model.EventRecord{
		Jti:         jti,
		Event:       *event,
		Original:    raw,
		Types:       keys,
		Sid:         sid,
		SortTime:    sortTime,
		Operational: operational,
	}

	err := s.eventDAO.Insert(ctx, rec)
	if err != nil {
		// JTI dedup: the record already exists. Load the original and surface
		// the typed sentinel so callers (router) can short-circuit without
		// counting the inbound or fanning out to outbound streams again.
		if errors.Is(err, interfaces.ErrDuplicateJTI) {
			esLog.Info("Duplicate JTI ingestion suppressed", "jti", jti, "sid", sid)
			existing, findErr := s.eventDAO.FindByJTI(ctx, jti)
			if findErr != nil {
				// Surface the lookup failure rather than the dup sentinel.
				// A nil record paired with the sentinel would let SubmitOperationalEvent
				// return (nil, nil) to its caller — indistinguishable from a successful
				// submission — and panic any caller that dereferences the record.
				esLog.Error("Error loading existing record after duplicate JTI", "jti", jti, "sid", sid, "error", findErr)
				return nil, findErr
			}
			return existing, interfaces.ErrDuplicateJTI
		}
		esLog.Error("Error inserting event", "error", err)
		return nil, err
	}

	return rec, nil
}

func (s *EventService) AddEventToStream(ctx context.Context, jti string, streamID string) error {
	err := s.eventDAO.AddPending(ctx, jti, streamID)
	if err != nil {
		esLog.Error("Error adding pending event to stream", "jti", jti, "streamID", streamID, "error", err)
	}
	return err
}

func (s *EventService) ClearPendingForStream(ctx context.Context, streamID string) (int64, error) {
	return s.eventDAO.ClearPendingForStream(ctx, streamID)
}

func (s *EventService) GetEvent(ctx context.Context, jti string) *goSet.SecurityEventToken {
	res, err := s.eventDAO.FindByJTI(ctx, jti)
	if err != nil || res == nil {
		return nil
	}
	return &res.Event
}

func (s *EventService) GetEvents(ctx context.Context, jtis []string) []*goSet.SecurityEventToken {
	records, err := s.eventDAO.FindByJTIs(ctx, jtis)
	if err != nil {
		esLog.Error("Error getting events", "error", err)
		return nil
	}

	res := make([]*goSet.SecurityEventToken, len(records))
	for i, rec := range records {
		event := rec.Event
		res[i] = &event
	}
	return res
}

func (s *EventService) GetEventRecord(ctx context.Context, jti string) *model.EventRecord {
	rec, err := s.eventDAO.FindByJTI(ctx, jti)
	if err != nil {
		esLog.Error("Error getting event record", "error", err)
		return nil
	}
	return rec
}

func (s *EventService) GetEventIds(ctx context.Context, streamID string, params model.PollParameters) ([]string, bool) {
	jtis, total, err := s.eventDAO.GetPendingForStream(ctx, streamID, params.MaxEvents)
	if err != nil {
		esLog.Error("Error getting event IDs", "error", err)
		return []string{}, false
	}

	more := false
	if int64(len(jtis)) < total {
		more = true
	}
	return jtis, more
}

func (s *EventService) AckEvent(ctx context.Context, jtiString string, streamID string, fencingToken int64) error {
	// TODO: Use fencingToken to verify lease ownership before marking delivered
	event, err := s.eventDAO.RemovePending(ctx, jtiString, streamID)
	if err != nil {
		esLog.Error("Error removing pending event", "error", err)
		return err
	}

	if event != nil {
		err = s.eventDAO.MarkDelivered(ctx, event, time.Now())
		if err != nil {
			esLog.Error("Error marking event as delivered", "jti", event.Jti, "error", err)
			return err
		}
	}
	return nil
}

func (s *EventService) WatchPending(ctx context.Context, callback func(jti string, streamID string)) {
	err := s.eventDAO.WatchPending(ctx, callback)
	if err != nil {
		esLog.Error("Error watching pending events", "error", err)
	}
}

// MatchesStream reports whether event should be routed to stream based on
// the stream's EventSource routing axis (ADR 0004), issuer, audience, and
// event-type filters. The predicate is pure: it touches no DAO state.
//
// EventSource branches (a nil EventSource resolves to effective DIRECT for
// routing, issue #199):
//   - DIRECT — the historical (iss, aud, event-type) filter, unchanged.
//   - AUDIENCE — the stream's own aud is the routing handle; the inbound
//     event's aud is NOT required to equal it (a minted/transmitter-assigned
//     aud must still route). The iss and event-type filters still apply.
//   - EXPLICIT — match when the inbound event's origin stream id
//     (EventRecord.Sid) is named in EventSource.SourceStreamIds. The
//     event-type filter still applies; the aud filter is not consulted.
//
// Issuer rule: iss matching is mandatory for RouteModeForward (FW) and ignored
// for RouteModePublish (PB). Other route modes (and unset) keep the historical
// "constrained iss with empty-as-wildcard" behavior.
//
// A receiver stream in RouteModeImport short-circuits to false (the event is
// consumed locally, not re-delivered). RemoteStreamId is a pairing pointer, not
// a routing selector, and is never consulted here.
func (s *EventService) MatchesStream(stream *model.StreamStateRecord, event *model.EventRecord) bool {
	if stream.IsReceiver() && stream.GetRouteMode() == model.RouteModeImport {
		return false
	}

	esType := effectiveEventSourceType(stream)

	if !matchesIss(stream, event) {
		return false
	}

	switch esType {
	case model.EventSourceExplicit:
		if !explicitSourceMatches(stream, event) {
			return false
		}
	case model.EventSourceAudience:
		// The stream's aud is the routing handle; the inbound event's aud is
		// not required to equal it. Only the event-type filter remains.
	default: // DIRECT or unset/nil — historical aud filter.
		if !matchesAud(stream, event) {
			return false
		}
	}

	return matchesEventType(stream, event)
}

// effectiveEventSourceType resolves the stream's EventSource type for routing.
// A nil EventSource resolves to DIRECT (issue #199); an empty Type tag likewise
// routes as DIRECT here.
func effectiveEventSourceType(stream *model.StreamStateRecord) string {
	if stream.EventSource == nil || stream.EventSource.Type == "" {
		return model.EventSourceDirect
	}
	return stream.EventSource.Type
}

// matchesIss applies the issuer filter. iss is mandatory for FW and ignored for
// PB; any other mode keeps the historical "constrained iss, empty-as-wildcard"
// rule (empty stream.Iss or empty event issuer is a wildcard).
func matchesIss(stream *model.StreamStateRecord, event *model.EventRecord) bool {
	if stream.GetRouteMode() == model.RouteModePublish {
		return true
	}
	if stream.Iss == "" {
		return true
	}
	compIss := event.Event.Issuer
	if compIss == "" {
		// Empty event issuer is a wildcard except in FW, where iss matching is
		// mandatory and a missing issuer cannot satisfy it.
		return stream.GetRouteMode() != model.RouteModeForward
	}
	return strings.EqualFold(stream.Iss, compIss)
}

// matchesAud applies the historical audience filter: an empty stream.Aud is a
// wildcard, and an empty event audience matches any constrained stream.
func matchesAud(stream *model.StreamStateRecord, event *model.EventRecord) bool {
	if len(stream.Aud) == 0 {
		return true
	}
	for _, value := range stream.Aud {
		if len(event.Event.Audience) == 0 || slices.Contains([]string(event.Event.Audience), value) {
			return true
		}
	}
	return false
}

// explicitSourceMatches reports whether the inbound event's origin stream id is
// named in the stream's EventSource.SourceStreamIds (EXPLICIT routing).
func explicitSourceMatches(stream *model.StreamStateRecord, event *model.EventRecord) bool {
	if stream.EventSource == nil {
		return false
	}
	return slices.Contains(stream.EventSource.SourceStreamIds, event.Sid)
}

// matchesEventType reports whether any of the event's types is in the stream's
// EventsDelivered set (case-insensitive).
func matchesEventType(stream *model.StreamStateRecord, event *model.EventRecord) bool {
	for _, eventType := range event.Types {
		for _, streamType := range stream.EventsDelivered {
			if strings.EqualFold(eventType, streamType) {
				return true
			}
		}
	}
	return false
}

func (s *EventService) ResetEventStream(ctx context.Context, streamID string, jti string, resetDate *time.Time, isStreamEvent func(*model.EventRecord) bool) error {
	// Validate the request
	if jti == "" && resetDate == nil {
		return errors.New("reset error: a date or jti must be provided")
	}
	if streamID == "" {
		return errors.New("reset error: invalid stream identifier specified")
	}

	// First clear any currently pending events
	deleteCount, err := s.eventDAO.ClearPendingForStream(ctx, streamID)
	if err != nil {
		return err
	}
	esLog.Debug("Removed pending events before reset", "count", deleteCount)

	// Now search and re-assign events from the event store
	var events []*model.EventRecord
	if jti != "" {
		// Reset to a JTI = re-queue that event and every following one (the CLI's
		// "reset to a JTI and include all following events"). Resolve the reference
		// JTI to its sort time and reuse the same time-range query — and so the same
		// metering path — as the date-based reset.
		ref, ferr := s.eventDAO.FindByJTI(ctx, jti)
		if ferr != nil {
			return ferr
		}
		if ref == nil {
			return errors.New("reset error: jti not found")
		}
		events, err = s.eventDAO.FindByTimeRange(ctx, ref.SortTime, nil, isStreamEvent)
		if err != nil {
			return err
		}
	} else if resetDate != nil {
		events, err = s.eventDAO.FindByTimeRange(ctx, *resetDate, nil, isStreamEvent)
		if err != nil {
			return err
		}
	} else {
		return errors.New("no reset date or JTI reset point provided")
	}

	// Re-add events to pending. Each successful re-queue is a fresh chargeable
	// egress (ADR 0055 Q91.4): reset bypasses the router fan-out where egress is
	// normally metered, so we report the re-delivery to the reset-egress observer
	// (tagged source:reset downstream). A failed re-queue is not re-delivered and
	// so is not metered.
	for _, event := range events {
		err = s.AddEventToStream(ctx, event.Jti, streamID)
		if err != nil {
			esLog.Error("Error re-adding event to stream during reset", "jti", event.Jti, "streamID", streamID, "error", err)
			continue
		}
		if s.resetEgressObserver != nil {
			s.resetEgressObserver.ObserveResetEgress(streamID, event)
		}
	}

	return nil
}
