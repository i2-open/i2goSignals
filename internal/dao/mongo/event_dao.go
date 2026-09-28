package mongo

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/logger"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/writeconcern"
)

var eLog = logger.Sub("EVENT_DAO")

// pendingDoc is the on-disk shape of a DeliverableEvent inside Mongo. It keeps
// `sid` as bson.ObjectID for backward compatibility with existing data; the
// public DAO interface exposes only string IDs and converts at the boundary.
type pendingDoc struct {
	Jti string        `bson:"jti"`
	Sid bson.ObjectID `bson:"sid"`
}

// deliveredDoc is the on-disk shape of a DeliveredEvent. The fields are spelled
// out rather than embedding pendingDoc: the driver's struct codec ignores an
// unexported embedded struct even with `bson:",inline"`, which silently wrote
// documents carrying only ackDate.
type deliveredDoc struct {
	Jti     string        `bson:"jti"`
	Sid     bson.ObjectID `bson:"sid"`
	AckDate time.Time     `bson:"ackDate"`
}

// EventStoreWriteConcern is the write concern of the ingest durability
// contract (ADR 0038): events and pending markers are majority-acknowledged
// and journaled before a SET is acked. It returns a fresh value so no caller
// can mutate a shared one.
func EventStoreWriteConcern() *writeconcern.WriteConcern {
	journal := true
	return &writeconcern.WriteConcern{W: "majority", Journal: &journal}
}

// oneTripBulkWriteOptions are the options of the one-trip events+pending
// bulkWrite. A client-level bulkWrite ignores the collection handles' write
// concern and uses the client's, and the client carries none (#332), so the
// call must request majority+journal itself or it would fall to the server
// default and weaken ADR 0038.
func oneTripBulkWriteOptions() *options.ClientBulkWriteOptionsBuilder {
	return options.ClientBulkWrite().SetOrdered(true).SetWriteConcern(EventStoreWriteConcern())
}

var errEventNotInit = errors.New("mongo collection not initialized")

type EventDAOMongo struct {
	events    collectionRef
	pending   collectionRef
	delivered collectionRef

	// oneTrip selects the InsertWithPending strategy (ADR 0043): true issues
	// one client-level bulkWrite across the events and pending namespaces
	// (MongoDB >= 8.0); false uses the two-write fallback. The provider sets
	// it from the server version at connect; the zero value is the fallback,
	// which works on every supported server.
	oneTrip atomic.Bool
}

// SetOneTripIngest selects the InsertWithPending strategy: true for the
// single multi-namespace bulkWrite (MongoDB >= 8.0 only), false for the
// two-write fallback.
func (d *EventDAOMongo) SetOneTripIngest(enabled bool) {
	d.oneTrip.Store(enabled)
}

// OneTripIngest reports the strategy SetOneTripIngest last selected.
func (d *EventDAOMongo) OneTripIngest() bool {
	return d.oneTrip.Load()
}

func NewEventDAO(eventCol, pendingCol, deliveredCol *mongo.Collection) interfaces.EventDAO {
	d := &EventDAOMongo{}
	d.events.set(eventCol)
	d.pending.set(pendingCol)
	d.delivered.set(deliveredCol)
	return d
}

// SetCollections rebinds all three collections used by EventDAOMongo. The
// rebind is atomic per-collection; in-flight callers see consistent values
// for the collection they originally loaded.
func (d *EventDAOMongo) SetCollections(eventCol, pendingCol, deliveredCol *mongo.Collection) {
	d.events.set(eventCol)
	d.pending.set(pendingCol)
	d.delivered.set(deliveredCol)
}

func (d *EventDAOMongo) eventColLoad() (*mongo.Collection, error) {
	c := d.events.load()
	if c == nil {
		return nil, errEventNotInit
	}
	return c, nil
}

func (d *EventDAOMongo) pendingColLoad() (*mongo.Collection, error) {
	c := d.pending.load()
	if c == nil {
		return nil, errEventNotInit
	}
	return c, nil
}

func (d *EventDAOMongo) deliveredColLoad() (*mongo.Collection, error) {
	c := d.delivered.load()
	if c == nil {
		return nil, errEventNotInit
	}
	return c, nil
}

func (d *EventDAOMongo) Insert(ctx context.Context, record *model.EventRecord) error {
	c, err := d.eventColLoad()
	if err != nil {
		return err
	}
	_, err = c.InsertOne(ctx, record)
	if err != nil {
		// JTI is the persistence-layer dedup key (RFC 8417 §2.2). The
		// sparse-unique eventJtiUnique index installed by createIndexes is
		// the authoritative race breaker; translate Mongo's duplicate-key
		// error to the shared interfaces.ErrDuplicateJTI sentinel so the
		// service layer can fetch the original via FindByJTI and the router
		// can short-circuit. Precedent: cluster_coordinator.go uses the same
		// mongo.IsDuplicateKeyError translation pattern.
		if mongo.IsDuplicateKeyError(err) {
			return interfaces.ErrDuplicateJTI
		}
		eLog.Error("Error inserting event", "error", err)
	}
	return err
}

// InsertMany persists records as one unordered bulk insert. Per-record
// outcomes are index-aligned with records; a duplicate JTI is reported as
// interfaces.ErrDuplicateJTI at its index while the other records still land.
func (d *EventDAOMongo) InsertMany(ctx context.Context, records []*model.EventRecord) ([]error, error) {
	if len(records) == 0 {
		return nil, nil
	}
	c, err := d.eventColLoad()
	if err != nil {
		return nil, err
	}
	docs := make([]any, len(records))
	for i, rec := range records {
		docs[i] = rec
	}
	_, err = c.InsertMany(ctx, docs, options.InsertMany().SetOrdered(false))
	if err == nil {
		return make([]error, len(records)), nil
	}
	var bwe mongo.BulkWriteException
	if !errors.As(err, &bwe) {
		eLog.Error("Error bulk inserting events", "error", err)
		return nil, err
	}
	if bwe.WriteConcernError != nil {
		eLog.Error("Write concern error bulk inserting events", "error", bwe.WriteConcernError)
		return nil, bwe.WriteConcernError
	}
	results := make([]error, len(records))
	for _, we := range bwe.WriteErrors {
		if we.Index < 0 || we.Index >= len(results) {
			continue
		}
		if mongo.IsDuplicateKeyError(we.WriteError) {
			results[we.Index] = interfaces.ErrDuplicateJTI
		} else {
			results[we.Index] = errors.New(we.WriteError.Error())
		}
	}
	return results, nil
}

// InsertWithPending persists records and their pending markers (ADR 0043).
// On MongoDB >= 8.0 it is one ordered client-level bulkWrite spanning the
// events and pending namespaces; below 8.0 it is the two-write fallback. Both
// strategies store the same documents and report the same per-record outcomes.
func (d *EventDAOMongo) InsertWithPending(ctx context.Context, records []*model.EventRecord, pending map[string][]string) ([]error, error) {
	if len(records) == 0 {
		return nil, nil
	}
	ec, err := d.eventColLoad()
	if err != nil {
		return nil, err
	}
	pc, err := d.pendingColLoad()
	if err != nil {
		return nil, err
	}
	streams, err := pendingSids(interfaces.StreamsByJti(pending))
	if err != nil {
		return nil, err
	}
	if d.oneTrip.Load() {
		return insertWithPendingOneTrip(ctx, ec, pc, records, streams)
	}
	return d.insertWithPendingTwoWrite(ctx, records, streams)
}

// pendingSids converts the JTI -> stream-ID map to JTI -> ObjectID, the
// on-disk sid type, failing the batch on a malformed stream ID before anything
// is written.
func pendingSids(byJti map[string][]string) (map[string][]bson.ObjectID, error) {
	out := make(map[string][]bson.ObjectID, len(byJti))
	for jti, streamIDs := range byJti {
		sids := make([]bson.ObjectID, len(streamIDs))
		for i, streamID := range streamIDs {
			sid, err := ParseObjectID(streamID)
			if err != nil {
				return nil, err
			}
			sids[i] = sid
		}
		out[jti] = sids
	}
	return out, nil
}

// oneTripOp is one insert of insertWithPendingOneTrip: the events-collection
// body (marker == false) or one pending marker of records[rec].
type oneTripOp struct {
	rec    int
	marker bool
	w      mongo.ClientBulkWrite
}

// insertWithPendingOneTrip writes every body, then every pending marker, as
// ONE ordered multi-namespace bulkWrite (ADR 0043). Grouping the ops by
// namespace lets mongod batch consecutive same-namespace inserts into one
// storage write unit per namespace; interleaving body and markers per record
// alternates namespaces on every op and defeats that batching.
//
// Ordering is what keeps a duplicate from leaving an orphan marker (ADR 0017):
// an ordered bulkWrite stops at the first failed op, and every marker follows
// every body, so a rejected body is never followed by a written marker. On a
// failure at op k, every op before k is stored; op k's record gets its error
// and its remaining ops are dropped; every other op after k, including the
// markers of records whose bodies already landed, is resubmitted in the same
// order. A record is reported successful only once its body and all its
// markers are durable (ADR 0038). A batch with k per-record failures costs k+1
// round trips and the common case costs one.
func insertWithPendingOneTrip(ctx context.Context, ec, pc *mongo.Collection, records []*model.EventRecord, streams map[string][]bson.ObjectID) ([]error, error) {
	client := ec.Database().Client()
	evNS := mongo.ClientBulkWrite{Database: ec.Database().Name(), Collection: ec.Name()}
	pNS := mongo.ClientBulkWrite{Database: pc.Database().Name(), Collection: pc.Name()}
	opts := oneTripBulkWriteOptions()

	// A JTI repeated in the batch needs no special casing: the repeat's body
	// insert fails the unique JTI index, and its markers are dropped before
	// the resubmit.
	ops := make([]oneTripOp, 0, len(records))
	var marks []oneTripOp
	for i, rec := range records {
		w := evNS
		w.Model = mongo.NewClientInsertOneModel().SetDocument(rec)
		ops = append(ops, oneTripOp{rec: i, w: w})
		for _, sid := range streams[rec.Jti] {
			m := pNS
			m.Model = mongo.NewClientInsertOneModel().SetDocument(&pendingDoc{Jti: rec.Jti, Sid: sid})
			marks = append(marks, oneTripOp{rec: i, marker: true, w: m})
		}
	}
	ops = append(ops, marks...)

	results := make([]error, len(records))
	for len(ops) > 0 {
		writes := make([]mongo.ClientBulkWrite, len(ops))
		for k, op := range ops {
			writes[k] = op.w
		}
		_, err := client.BulkWrite(ctx, writes, opts)
		if err == nil {
			return results, nil
		}
		var cbe mongo.ClientBulkWriteException
		if !errors.As(err, &cbe) || cbe.WriteError != nil || len(cbe.WriteConcernErrors) > 0 || len(cbe.WriteErrors) != 1 {
			eLog.Error("Error bulk writing events with pending markers", "error", err)
			return nil, err
		}
		failed, we := -1, mongo.WriteError{}
		for k, e := range cbe.WriteErrors {
			failed, we = k, e
		}
		if failed < 0 || failed >= len(ops) {
			eLog.Error("Bulk write reported an out-of-range failure index", "index", failed, "ops", len(ops))
			return nil, err
		}
		bad := ops[failed]
		switch {
		case !bad.marker && mongo.IsDuplicateKeyError(we):
			results[bad.rec] = interfaces.ErrDuplicateJTI
		case !bad.marker:
			results[bad.rec] = errors.New(we.Error())
		default:
			// The body landed but a marker did not: not acknowledgeable.
			results[bad.rec] = fmt.Errorf("pending marker write failed: %s", we.Error())
		}
		rest := make([]oneTripOp, 0, len(ops)-failed-1)
		for _, op := range ops[failed+1:] {
			if op.rec != bad.rec {
				rest = append(rest, op)
			}
		}
		ops = rest
	}
	return results, nil
}

// insertWithPendingTwoWrite is the pre-8.0 fallback: insert the bodies, then
// write markers for the records that were actually stored. Markers are only
// ever written after their body is known to be accepted, so no speculative
// marker exists and nothing needs retracting (ADR 0043 supersedes the ADR 0038
// concurrent-write mechanism).
func (d *EventDAOMongo) insertWithPendingTwoWrite(ctx context.Context, records []*model.EventRecord, streams map[string][]bson.ObjectID) ([]error, error) {
	results, err := d.InsertMany(ctx, records)
	if err != nil {
		return nil, err
	}
	pc, err := d.pendingColLoad()
	if err != nil {
		return nil, err
	}
	var docs []any
	var owners []int // record index each doc belongs to
	for i, rec := range records {
		if results[i] != nil {
			continue
		}
		for _, sid := range streams[rec.Jti] {
			docs = append(docs, &pendingDoc{Jti: rec.Jti, Sid: sid})
			owners = append(owners, i)
		}
	}
	if len(docs) == 0 {
		return results, nil
	}
	_, err = pc.InsertMany(ctx, docs)
	if err == nil {
		return results, nil
	}
	var bwe mongo.BulkWriteException
	if !errors.As(err, &bwe) || bwe.WriteConcernError != nil {
		eLog.Error("Error bulk inserting pending markers", "error", err)
		return nil, err
	}
	// Ordered insert: every doc before the first failure is stored; the
	// failed doc's record and every record whose markers came after it are
	// not acknowledgeable.
	first := len(docs)
	for _, we := range bwe.WriteErrors {
		if we.Index >= 0 && we.Index < first {
			first = we.Index
		}
	}
	for k := first; k < len(docs); k++ {
		if results[owners[k]] == nil {
			results[owners[k]] = fmt.Errorf("pending marker write failed: %w", err)
		}
	}
	return results, nil
}

func (d *EventDAOMongo) FindByJTI(ctx context.Context, jti string) (*model.EventRecord, error) {
	c, err := d.eventColLoad()
	if err != nil {
		return nil, err
	}
	filter := bson.M{"jti": jti}
	var res model.EventRecord
	cursor := c.FindOne(ctx, filter)
	err = cursor.Decode(&res)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, nil
		}
		eLog.Error("Error decoding event record", "error", err)
		return nil, err
	}
	return &res, nil
}

func (d *EventDAOMongo) FindByJTIs(ctx context.Context, jtis []string) ([]*model.EventRecord, error) {
	c, err := d.eventColLoad()
	if err != nil {
		return nil, err
	}
	filter := bson.M{"jti": bson.M{"$in": jtis}}
	cursor, err := c.Find(ctx, filter)
	if err != nil {
		eLog.Error("Error finding events", "error", err)
		return nil, err
	}

	var records []*model.EventRecord
	err = cursor.All(ctx, &records)
	if err != nil {
		eLog.Error("Error parsing event records", "error", err)
		return nil, err
	}
	return records, nil
}

func (d *EventDAOMongo) FindByTimeRange(ctx context.Context, from time.Time, to *time.Time, filter func(*model.EventRecord) bool) ([]*model.EventRecord, error) {
	c, err := d.eventColLoad()
	if err != nil {
		return nil, err
	}
	var queryFilter bson.D
	if to != nil {
		queryFilter = bson.D{
			bson.E{Key: "sortTime", Value: bson.D{
				bson.E{Key: "$gte", Value: from},
				bson.E{Key: "$lte", Value: to},
			}},
		}
	} else {
		queryFilter = bson.D{
			bson.E{Key: "sortTime", Value: bson.D{bson.E{Key: "$gte", Value: from}}},
		}
	}

	opts := options.Find().SetSort(bson.D{bson.E{Key: "jti", Value: 1}})
	cursor, err := c.Find(ctx, queryFilter, opts)
	if err != nil {
		eLog.Error("Error finding events by time range", "error", err)
		return nil, err
	}

	var allRecords []*model.EventRecord
	err = cursor.All(ctx, &allRecords)
	if err != nil {
		eLog.Error("Error parsing events", "error", err)
		return nil, err
	}

	if filter == nil {
		return allRecords, nil
	}

	// Apply custom filter
	var filtered []*model.EventRecord
	for _, rec := range allRecords {
		if filter(rec) {
			filtered = append(filtered, rec)
		}
	}
	return filtered, nil
}

func (d *EventDAOMongo) AddPending(ctx context.Context, jti string, streamID string) error {
	c, err := d.pendingColLoad()
	if err != nil {
		return err
	}
	sid, err := ParseObjectID(streamID)
	if err != nil {
		return err
	}
	doc := pendingDoc{Jti: jti, Sid: sid}
	_, err = c.InsertOne(ctx, &doc)
	return err
}

func (d *EventDAOMongo) AddPendingMany(ctx context.Context, jtis []string, streamID string) error {
	if len(jtis) == 0 {
		return nil
	}
	c, err := d.pendingColLoad()
	if err != nil {
		return err
	}
	sid, err := ParseObjectID(streamID)
	if err != nil {
		return err
	}
	docs := make([]any, len(jtis))
	for i, jti := range jtis {
		docs[i] = &pendingDoc{Jti: jti, Sid: sid}
	}
	_, err = c.InsertMany(ctx, docs)
	return err
}

func (d *EventDAOMongo) GetPendingForStream(ctx context.Context, streamID string, limit int32) (jtis []string, total int64, err error) {
	c, err := d.pendingColLoad()
	if err != nil {
		return nil, 0, err
	}
	sid, err := ParseObjectID(streamID)
	if err != nil {
		return nil, 0, err
	}

	filter := bson.M{"sid": sid}

	totalCount, err := c.CountDocuments(ctx, filter, options.Count())
	if err != nil {
		eLog.Error("Error counting pending events", "error", err)
		return nil, 0, err
	}

	if totalCount == 0 {
		return []string{}, 0, nil
	}

	// Sort by jti, explicitly. jtis are UUIDv7 (goSet.GenerateJti), so
	// ascending jti IS ascending issue order, and the {sid:1,jti:1} index
	// supplies that order directly — the sort adds no blocking stage and no
	// round trip. The sort is stated rather than inherited because without it
	// the order is whatever plan the query planner happens to pick: an
	// unsorted find on this filter returned insertion order when the
	// collection carried the legacy {sid:1} index and returns jti order under
	// the compound one. Delivery order is a contract receivers reason about
	// (ADR 0040), so it may not be a side effect of index selection.
	opts := options.Find().SetSort(bson.D{{Key: "jti", Value: 1}})
	if limit > 0 {
		opts.SetLimit(int64(limit))
	}

	var docs []pendingDoc
	cursor, err := c.Find(ctx, filter, opts)
	if err != nil {
		eLog.Error("Error getting event batch", "error", err)
		return nil, 0, err
	}

	err = cursor.All(ctx, &docs)
	if err != nil {
		eLog.Error("Error parsing pending events", "error", err)
		return nil, 0, err
	}

	ids := make([]string, len(docs))
	for i, v := range docs {
		ids[i] = v.Jti
	}

	return ids, totalCount, nil
}

func (d *EventDAOMongo) RemovePending(ctx context.Context, jti string, streamID string) (*interfaces.DeliverableEvent, error) {
	c, err := d.pendingColLoad()
	if err != nil {
		return nil, err
	}
	sid, err := ParseObjectID(streamID)
	if err != nil {
		return nil, err
	}

	filter := bson.M{
		"jti": jti,
		"sid": sid,
	}

	res := c.FindOne(ctx, filter)
	if res.Err() != nil {
		if errors.Is(res.Err(), mongo.ErrNoDocuments) {
			return nil, nil
		}
		return nil, res.Err()
	}

	var doc pendingDoc
	err = res.Decode(&doc)
	if err != nil {
		eLog.Error("Error decoding deliverable event", "error", err)
		return nil, err
	}

	_, err = c.DeleteOne(ctx, filter)
	if err != nil {
		eLog.Error("Error deleting pending event", "error", err)
		return nil, err
	}

	return &interfaces.DeliverableEvent{Jti: doc.Jti, StreamId: doc.Sid.Hex()}, nil
}

// RemovePendingMany finds streamID's pending entries for jtis in one query,
// deletes exactly those in one DeleteMany, and returns them — two round trips
// for the batch instead of two per JTI.
func (d *EventDAOMongo) RemovePendingMany(ctx context.Context, jtis []string, streamID string) ([]interfaces.DeliverableEvent, error) {
	if len(jtis) == 0 {
		return nil, nil
	}
	c, err := d.pendingColLoad()
	if err != nil {
		return nil, err
	}
	sid, err := ParseObjectID(streamID)
	if err != nil {
		return nil, err
	}

	cursor, err := c.Find(ctx, bson.M{"sid": sid, "jti": bson.M{"$in": jtis}})
	if err != nil {
		eLog.Error("Error finding pending events", "error", err)
		return nil, err
	}
	var docs []pendingDoc
	if err = cursor.All(ctx, &docs); err != nil {
		eLog.Error("Error decoding pending events", "error", err)
		return nil, err
	}
	if len(docs) == 0 {
		return nil, nil
	}

	removed := make([]interfaces.DeliverableEvent, len(docs))
	found := make([]string, len(docs))
	for i, doc := range docs {
		removed[i] = interfaces.DeliverableEvent{Jti: doc.Jti, StreamId: doc.Sid.Hex()}
		found[i] = doc.Jti
	}
	if _, err = c.DeleteMany(ctx, bson.M{"sid": sid, "jti": bson.M{"$in": found}}); err != nil {
		eLog.Error("Error deleting pending events", "error", err)
		return nil, err
	}
	return removed, nil
}

func (d *EventDAOMongo) ClearPendingForStream(ctx context.Context, streamID string) (int64, error) {
	c, err := d.pendingColLoad()
	if err != nil {
		return 0, err
	}
	sid, err := ParseObjectID(streamID)
	if err != nil {
		return 0, err
	}

	filter := bson.D{bson.E{Key: "sid", Value: sid}}
	many, err := c.DeleteMany(ctx, filter)
	if err != nil {
		eLog.Error("Error clearing pending events", "error", err)
		return 0, err
	}
	return many.DeletedCount, nil
}

func (d *EventDAOMongo) MarkDelivered(ctx context.Context, event *interfaces.DeliverableEvent, ackDate time.Time) error {
	c, err := d.deliveredColLoad()
	if err != nil {
		return err
	}
	sid, err := ParseObjectID(event.StreamId)
	if err != nil {
		return err
	}
	doc := deliveredDoc{Jti: event.Jti, Sid: sid, AckDate: ackDate}
	_, err = c.InsertOne(ctx, &doc)
	return err
}

// MarkDeliveredMany inserts one delivered document per event in a single
// InsertMany.
func (d *EventDAOMongo) MarkDeliveredMany(ctx context.Context, events []interfaces.DeliverableEvent, ackDate time.Time) error {
	if len(events) == 0 {
		return nil
	}
	c, err := d.deliveredColLoad()
	if err != nil {
		return err
	}
	docs := make([]any, len(events))
	for i, event := range events {
		sid, err := ParseObjectID(event.StreamId)
		if err != nil {
			return err
		}
		docs[i] = &deliveredDoc{Jti: event.Jti, Sid: sid, AckDate: ackDate}
	}
	_, err = c.InsertMany(ctx, docs)
	return err
}

// ackBulkWriteOptions are the options of the one-trip ack bulkWrite. Verbose
// results are what report, per JTI, whether a pending marker was deleted. The
// call runs at w:1, the delivered collection's concern (#332): a client-level
// bulkWrite takes a single concern, and an ack is post-persistence (ADR 0038
// governs ingest only), so a pending delete rolled back on failover costs a
// redelivery, which the receiver dedups by JTI, never a lost SET.
func ackBulkWriteOptions() *options.ClientBulkWriteOptionsBuilder {
	return options.ClientBulkWrite().SetOrdered(true).SetVerboseResults(true).SetWriteConcern(writeconcern.W1())
}

// AckDelivered removes streamID's pending markers for jtis and records the
// acked JTIs as delivered at ackDate. On MongoDB 8.0+ (the strategy
// SetOneTripIngest selects) this is ONE multi-namespace bulkWrite; below 8.0
// it is RemovePendingMany followed by MarkDeliveredMany.
func (d *EventDAOMongo) AckDelivered(ctx context.Context, jtis []string, streamID string, ackDate time.Time) ([]string, error) {
	if len(jtis) == 0 {
		return nil, nil
	}
	if d.oneTrip.Load() {
		return d.ackDeliveredOneTrip(ctx, jtis, streamID, ackDate)
	}
	removed, err := d.RemovePendingMany(ctx, jtis, streamID)
	if err != nil || len(removed) == 0 {
		return nil, err
	}
	if err = d.MarkDeliveredMany(ctx, removed, ackDate); err != nil {
		return nil, err
	}
	acked := make([]string, len(removed))
	for i, ev := range removed {
		acked[i] = ev.Jti
	}
	return acked, nil
}

// ackDeliveredOneTrip issues, as one ordered bulkWrite, a delete of each
// JTI's pending markers for the stream followed by an insert of each JTI's
// delivered record. A bulkWrite cannot make an insert conditional on a
// delete, so the delivered insert is written for every JTI in the batch; the
// verbose per-op delete counts then say which JTIs were really pending, and
// the delivered records of any that were not (unknown or already acked, ADR
// 0017) are retracted by _id in one follow-up delete. The common case, where
// every acked JTI was pending, costs one round trip. Retracting by the _id
// this call inserted never touches another ack's delivered record.
func (d *EventDAOMongo) ackDeliveredOneTrip(ctx context.Context, jtis []string, streamID string, ackDate time.Time) ([]string, error) {
	pc, err := d.pendingColLoad()
	if err != nil {
		return nil, err
	}
	dc, err := d.deliveredColLoad()
	if err != nil {
		return nil, err
	}
	sid, err := ParseObjectID(streamID)
	if err != nil {
		return nil, err
	}

	unique := make([]string, 0, len(jtis))
	seen := make(map[string]struct{}, len(jtis))
	for _, jti := range jtis {
		if _, dup := seen[jti]; !dup {
			seen[jti] = struct{}{}
			unique = append(unique, jti)
		}
	}

	n := len(unique)
	pNS := mongo.ClientBulkWrite{Database: pc.Database().Name(), Collection: pc.Name()}
	dNS := mongo.ClientBulkWrite{Database: dc.Database().Name(), Collection: dc.Name()}
	writes := make([]mongo.ClientBulkWrite, 2*n)
	for i, jti := range unique {
		del := pNS
		del.Model = mongo.NewClientDeleteManyModel().SetFilter(bson.M{"sid": sid, "jti": jti})
		writes[i] = del
		ins := dNS
		ins.Model = mongo.NewClientInsertOneModel().SetDocument(&deliveredDoc{Jti: jti, Sid: sid, AckDate: ackDate})
		writes[n+i] = ins
	}
	res, err := pc.Database().Client().BulkWrite(ctx, writes, ackBulkWriteOptions())
	if err != nil {
		eLog.Error("Error bulk writing ack", "count", n, "streamID", streamID, "error", err)
		return nil, err
	}

	acked := make([]string, 0, n)
	var retract []any
	for i, jti := range unique {
		if res.DeleteResults[i].DeletedCount > 0 {
			acked = append(acked, jti)
			continue
		}
		ins, ok := res.InsertResults[n+i]
		if !ok {
			return nil, fmt.Errorf("ack bulkWrite: no insert result for op %d", n+i)
		}
		retract = append(retract, ins.InsertedID)
	}
	if len(retract) > 0 {
		if _, err = dc.DeleteMany(ctx, bson.M{"_id": bson.M{"$in": retract}}); err != nil {
			eLog.Error("Error retracting delivered records of non-pending acks", "count", len(retract), "streamID", streamID, "error", err)
			return nil, err
		}
	}
	return acked, nil
}

// ListDeliveredForStream returns streamID's delivered (post-ack) events with
// their AckDate — the retention purge clock's enumerator (ADR 0055).
func (d *EventDAOMongo) ListDeliveredForStream(ctx context.Context, streamID string) ([]interfaces.DeliveredEvent, error) {
	c, err := d.deliveredColLoad()
	if err != nil {
		return nil, err
	}
	sid, err := ParseObjectID(streamID)
	if err != nil {
		return nil, err
	}
	cursor, err := c.Find(ctx, bson.M{"sid": sid})
	if err != nil {
		eLog.Error("Error listing delivered events", "error", err)
		return nil, err
	}
	var docs []deliveredDoc
	if err = cursor.All(ctx, &docs); err != nil {
		eLog.Error("Error parsing delivered events", "error", err)
		return nil, err
	}
	out := make([]interfaces.DeliveredEvent, len(docs))
	for i, doc := range docs {
		out[i] = interfaces.DeliveredEvent{
			DeliverableEvent: interfaces.DeliverableEvent{Jti: doc.Jti, StreamId: doc.Sid.Hex()},
			AckDate:          doc.AckDate,
		}
	}
	return out, nil
}

// RemoveDelivered drops streamID's delivered entry for jti (its retention clock
// firing). The global body is left untouched.
func (d *EventDAOMongo) RemoveDelivered(ctx context.Context, jti string, streamID string) error {
	c, err := d.deliveredColLoad()
	if err != nil {
		return err
	}
	sid, err := ParseObjectID(streamID)
	if err != nil {
		return err
	}
	_, err = c.DeleteOne(ctx, bson.M{"jti": jti, "sid": sid})
	if err != nil {
		eLog.Error("Error removing delivered event", "error", err)
	}
	return err
}

// DeleteBodyIfUnreferenced deletes the global body for jti only when no stream
// still references it in pending or delivered (refcount 0).
func (d *EventDAOMongo) DeleteBodyIfUnreferenced(ctx context.Context, jti string) (bool, error) {
	pendingCol, err := d.pendingColLoad()
	if err != nil {
		return false, err
	}
	deliveredCol, err := d.deliveredColLoad()
	if err != nil {
		return false, err
	}
	eventCol, err := d.eventColLoad()
	if err != nil {
		return false, err
	}

	pendingRefs, err := pendingCol.CountDocuments(ctx, bson.M{"jti": jti})
	if err != nil {
		eLog.Error("Error counting pending refs", "error", err)
		return false, err
	}
	if pendingRefs > 0 {
		return false, nil
	}
	deliveredRefs, err := deliveredCol.CountDocuments(ctx, bson.M{"jti": jti})
	if err != nil {
		eLog.Error("Error counting delivered refs", "error", err)
		return false, err
	}
	if deliveredRefs > 0 {
		return false, nil
	}

	res, err := eventCol.DeleteOne(ctx, bson.M{"jti": jti})
	if err != nil {
		eLog.Error("Error deleting event body", "error", err)
		return false, err
	}
	return res.DeletedCount > 0, nil
}

// CountRetainedForStream counts streamID's delivered (post-ack-retained) JTIs.
func (d *EventDAOMongo) CountRetainedForStream(ctx context.Context, streamID string) (int64, error) {
	c, err := d.deliveredColLoad()
	if err != nil {
		return 0, err
	}
	sid, err := ParseObjectID(streamID)
	if err != nil {
		return 0, err
	}
	return c.CountDocuments(ctx, bson.M{"sid": sid})
}

func (d *EventDAOMongo) WatchPending(ctx context.Context, callback func(jti string, streamID string)) error {
	c, err := d.pendingColLoad()
	if err != nil {
		return err
	}
	matchInserts := bson.D{
		bson.E{
			Key: "$match", Value: bson.D{
				bson.E{Key: "operationType", Value: "insert"}},
		},
	}

	opts := options.ChangeStream().SetFullDocument(options.UpdateLookup)
	eventStream, err := c.Watch(ctx, mongo.Pipeline{matchInserts}, opts)
	if err != nil {
		eLog.Error("Unable to initialize background event stream", "error", err)
		return err
	}
	defer func(eventStream *mongo.ChangeStream, ctx context.Context) {
		err := eventStream.Close(ctx)
		if err != nil {
			eLog.Error("Error closing background event stream", "error", err)
		}
	}(eventStream, ctx)

	eLog.Info("Background pending event watcher started")

	for eventStream.Next(ctx) {
		var change bson.M
		if err := eventStream.Decode(&change); err != nil {
			eLog.Error("Error decoding change event", "error", err)
			continue
		}

		fullDoc, ok := change["fullDocument"].(bson.M)
		if !ok {
			continue
		}

		jti, _ := fullDoc["jti"].(string)
		sid, _ := fullDoc["sid"].(bson.ObjectID)

		if jti != "" && !sid.IsZero() {
			callback(jti, sid.Hex())
		}
	}

	if err := eventStream.Err(); err != nil {
		eLog.Error("Background event stream stopped with error", "error", err)
		return err
	}

	eLog.Info("Background event stream stopped")
	return nil
}
