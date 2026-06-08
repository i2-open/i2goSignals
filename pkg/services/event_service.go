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

type EventService struct {
	eventDAO interfaces.EventDAO
}

func NewEventService(eventDAO interfaces.EventDAO) *EventService {
	return &EventService{
		eventDAO: eventDAO,
	}
}

func (s *EventService) AddEvent(ctx context.Context, event *goSet.SecurityEventToken, sid string, raw string) (*model.AgEventRecord, error) {
	return s.addEvent(ctx, event, sid, raw, false)
}

// AddOperationalEvent persists an operational event (Operational=true). Operational events are point-to-point
// SSF protocol events (verify, stream-updated) scoped to a single SSF endpoint relationship and are excluded
// from ResetDate/ResetJti replay queries.
func (s *EventService) AddOperationalEvent(ctx context.Context, event *goSet.SecurityEventToken, sid string, raw string) (*model.AgEventRecord, error) {
	return s.addEvent(ctx, event, sid, raw, true)
}

func (s *EventService) addEvent(ctx context.Context, event *goSet.SecurityEventToken, sid string, raw string, operational bool) (*model.AgEventRecord, error) {
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

	rec := &model.AgEventRecord{
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

func (s *EventService) GetEventRecord(ctx context.Context, jti string) *model.AgEventRecord {
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
// direction, issuer, audience, and event-type filters. Empty stream.Iss or
// empty event.Event.Issuer is treated as a wildcard. A receiver stream in
// RouteModeImport short-circuits to false (the event is consumed locally,
// not re-delivered). The predicate is pure: it touches no DAO state.
func (s *EventService) MatchesStream(stream *model.StreamStateRecord, event *model.AgEventRecord) bool {
	if stream.IsReceiver() && stream.GetRouteMode() == model.RouteModeImport {
		return false
	}

	if stream.Iss != "" {
		compIss := event.Event.Issuer
		if compIss != "" && !strings.EqualFold(stream.Iss, compIss) {
			return false
		}
	}

	if len(stream.Aud) > 0 {
		audMatch := false
		for _, value := range stream.Aud {
			if len(event.Event.Audience) == 0 || slices.Contains([]string(event.Event.Audience), value) {
				audMatch = true
				break
			}
		}
		if !audMatch {
			return false
		}
	}

	for _, eventType := range event.Types {
		for _, streamType := range stream.EventsDelivered {
			if strings.EqualFold(eventType, streamType) {
				return true
			}
		}
	}
	return false
}

func (s *EventService) ResetEventStream(ctx context.Context, streamID string, jti string, resetDate *time.Time, isStreamEvent func(*model.AgEventRecord) bool) error {
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
	var events []*model.AgEventRecord
	if jti != "" {
		// TODO: Implement JTI-based reset (need to add to DAO)
		esLog.Warn("JTI-based reset not yet implemented, using time-based reset")
		return errors.New("JTI-based reset not yet implemented")
	} else if resetDate != nil {
		events, err = s.eventDAO.FindByTimeRange(ctx, *resetDate, nil, isStreamEvent)
		if err != nil {
			return err
		}
	} else {
		return errors.New("no reset date or JTI reset point provided")
	}

	// Re-add events to pending
	for _, event := range events {
		err = s.AddEventToStream(ctx, event.Jti, streamID)
		if err != nil {
			esLog.Error("Error re-adding event to stream during reset", "jti", event.Jti, "streamID", streamID, "error", err)
		}
	}

	return nil
}
