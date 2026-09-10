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

// newEventRecord builds the persisted record for one inbound SET.
func newEventRecord(event *goSet.SecurityEventToken, sid string, raw string, operational bool) *model.EventRecord {
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

	return &model.EventRecord{
		Jti:         event.ID,
		Event:       *event,
		Original:    raw,
		Types:       keys,
		Sid:         sid,
		SortTime:    sortTime,
		Operational: operational,
	}
}

func (s *EventService) addEvent(ctx context.Context, event *goSet.SecurityEventToken, sid string, raw string, operational bool) (*model.EventRecord, error) {
	rec := newEventRecord(event, sid, raw, operational)
	err := s.eventDAO.Insert(ctx, rec)
	if err != nil {
		if errors.Is(err, interfaces.ErrDuplicateJTI) {
			return s.existingAfterDuplicate(ctx, rec.Jti, sid)
		}
		esLog.Error("Error inserting event", "error", err)
		return nil, err
	}

	return rec, nil
}

// existingAfterDuplicate handles JTI dedup: the record already exists. Load the
// original and surface the typed sentinel so callers (router) can short-circuit
// without counting the inbound or fanning out to outbound streams again.
func (s *EventService) existingAfterDuplicate(ctx context.Context, jti string, sid string) (*model.EventRecord, error) {
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

// IngestBatch is one in-flight body write started by BeginAddEvents.
//
// The candidate records are built and returned synchronously so the caller can
// route them and write their pending markers while the body write is still in
// flight (ADR 0038); Wait joins the write and reports the same per-record
// outcome AddEvents reports. Candidates is immutable once BeginAddEvents
// returns — the result slice Wait reports is a separate slice — so a caller may
// read the candidates concurrently with the write.
type IngestBatch struct {
	candidates []*model.EventRecord
	done       chan struct{}
	recs       []*model.EventRecord
	errs       []error
}

// Candidates returns the records the batch is attempting to persist, index
// aligned with the events passed to BeginAddEvents. They are available before
// the write completes and are never mutated, so routing may read them while
// the write is in flight. A candidate is not yet known to be accepted: Wait
// decides that.
func (b *IngestBatch) Candidates() []*model.EventRecord {
	return b.candidates
}

// Wait blocks until the body write completes and returns the records and
// errors with exactly AddEvents' semantics. It may be called more than once.
func (b *IngestBatch) Wait() ([]*model.EventRecord, []error) {
	<-b.done
	return b.recs, b.errs
}

// BeginAddEvents starts persisting a batch of inbound SETs and returns before
// the write completes. events and raws are index-aligned. The caller must Wait
// on the returned batch before treating any record as accepted; a JTI that
// already exists comes back paired with ErrDuplicateJTI, and a batch that
// fails outright carries that error at every position.
//
// AddEvents is the synchronous form; the split exists so ingest can issue the
// body write and the pending-marker writes concurrently rather than serially
// (ADR 0038).
func (s *EventService) BeginAddEvents(ctx context.Context, events []*goSet.SecurityEventToken, sid string, raws []string) *IngestBatch {
	b := &IngestBatch{
		candidates: make([]*model.EventRecord, len(events)),
		recs:       make([]*model.EventRecord, len(events)),
		errs:       make([]error, len(events)),
		done:       make(chan struct{}),
	}
	for i, ev := range events {
		rec := newEventRecord(ev, sid, raws[i], false)
		b.candidates[i], b.recs[i] = rec, rec
	}
	if len(events) == 0 {
		close(b.done)
		return b
	}
	go func() {
		defer close(b.done)
		s.completeAddEvents(ctx, b, sid)
	}()
	return b
}

// completeAddEvents runs the bulk insert and folds the per-record outcomes into
// the batch's result slices.
func (s *EventService) completeAddEvents(ctx context.Context, b *IngestBatch, sid string) {
	perRec, batchErr := s.eventDAO.InsertMany(ctx, b.recs)
	if batchErr != nil {
		esLog.Error("Error inserting event batch", "sid", sid, "count", len(b.recs), "error", batchErr)
		for i := range b.errs {
			b.recs[i], b.errs[i] = nil, batchErr
		}
		return
	}
	for i, err := range perRec {
		if err == nil {
			continue
		}
		if errors.Is(err, interfaces.ErrDuplicateJTI) {
			b.recs[i], b.errs[i] = s.existingAfterDuplicate(ctx, b.recs[i].Jti, sid)
			continue
		}
		esLog.Error("Error inserting event", "jti", b.recs[i].Jti, "error", err)
		b.recs[i], b.errs[i] = nil, err
	}
}

// AddEvents persists a batch of inbound SETs in one DAO round trip. events and
// raws are index-aligned; the returned records and errors are index-aligned
// with them. A record whose JTI already exists comes back as the existing
// record paired with ErrDuplicateJTI, exactly as AddEvent reports it. When the
// batch itself fails before any record is attempted, every position carries
// that error and every record is nil.
func (s *EventService) AddEvents(ctx context.Context, events []*goSet.SecurityEventToken, sid string, raws []string) ([]*model.EventRecord, []error) {
	return s.BeginAddEvents(ctx, events, sid, raws).Wait()
}

// DiscardPending retracts one speculative delivery intent per JTI from
// streamID's pending list without recording anything as delivered. It is the
// compensating write for a pending marker whose event body was ultimately
// rejected — a duplicate JTI, or a failed body write — see ADR 0038. It undoes
// exactly one AddPending per JTI, so an older still-undelivered intent for the
// same JTI survives. AckEvents is the delivery-side counterpart: it also
// removes pending entries, but removes them all and records them as delivered.
func (s *EventService) DiscardPending(ctx context.Context, jtis []string, streamID string) error {
	if len(jtis) == 0 {
		return nil
	}
	// The error is returned, not logged: the router's commit phase logs it with
	// the stream and delivery mode attached, and CONTEXT.md's log-level policy
	// keeps ERROR an attention signal rather than a noise floor.
	return s.eventDAO.RetractPending(ctx, jtis, streamID)
}

func (s *EventService) AddEventToStream(ctx context.Context, jti string, streamID string) error {
	err := s.eventDAO.AddPending(ctx, jti, streamID)
	if err != nil {
		esLog.Error("Error adding pending event to stream", "jti", jti, "streamID", streamID, "error", err)
	}
	return err
}

// AddEventsToStream appends a batch of already-persisted JTIs to a stream's
// pending list in one DAO round trip, preserving order.
func (s *EventService) AddEventsToStream(ctx context.Context, jtis []string, streamID string) error {
	if len(jtis) == 0 {
		return nil
	}
	err := s.eventDAO.AddPendingMany(ctx, jtis, streamID)
	if err != nil {
		esLog.Error("Error adding pending events to stream", "count", len(jtis), "streamID", streamID, "error", err)
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

// GetEventRecords fetches the records behind jtis in one read. Unknown JTIs
// are simply absent from the result, whose order is unspecified; callers
// index it by Jti. A read error logs and returns nil.
func (s *EventService) GetEventRecords(ctx context.Context, jtis []string) []*model.EventRecord {
	if len(jtis) == 0 {
		return nil
	}
	records, err := s.eventDAO.FindByJTIs(ctx, jtis)
	if err != nil {
		esLog.Error("Error getting event records", "error", err)
		return nil
	}
	return records
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

// AckEvents acknowledges jtis for streamID as one batch: the pending entries
// are removed and recorded as delivered in a bounded number of DAO round trips
// rather than three per JTI. A JTI not pending for the stream is ignored,
// exactly as AckEvent ignores it. An empty jtis is a no-op.
func (s *EventService) AckEvents(ctx context.Context, jtis []string, streamID string, fencingToken int64) error {
	// TODO: Use fencingToken to verify lease ownership before marking delivered
	if len(jtis) == 0 {
		return nil
	}
	events, err := s.eventDAO.RemovePendingMany(ctx, jtis, streamID)
	if err != nil {
		esLog.Error("Error removing pending events", "count", len(jtis), "streamID", streamID, "error", err)
		return err
	}
	if len(events) == 0 {
		return nil
	}
	if err = s.eventDAO.MarkDeliveredMany(ctx, events, time.Now()); err != nil {
		esLog.Error("Error marking events as delivered", "count", len(events), "streamID", streamID, "error", err)
		return err
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
