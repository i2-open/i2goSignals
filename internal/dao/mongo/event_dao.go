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

// deliveryDoc is the on-disk shape of one delivery reference in the
// deliveries collection (#359): one document per (stream, inbound JTI),
// pending until acknowledged by ackJti, then delivered. `sid` stays
// bson.ObjectID like the old pending/delivered documents; the public DAO
// interface exposes only string IDs and converts at the boundary.
type deliveryDoc struct {
	Sid       bson.ObjectID `bson:"sid"`
	Jti       string        `bson:"jti"`
	AckJti    string        `bson:"ackJti"`
	State     string        `bson:"state"`
	CreatedAt time.Time     `bson:"createdAt"`
	AckDate   *time.Time    `bson:"ackDate,omitempty"`
	ExpireAt  *time.Time    `bson:"expireAt,omitempty"`
}

func (doc *deliveryDoc) ref() interfaces.PendingRef {
	ackJti := doc.AckJti
	if ackJti == "" {
		ackJti = doc.Jti
	}
	return interfaces.PendingRef{Jti: doc.Jti, AckJti: ackJti, EnqueuedAt: doc.CreatedAt}
}

func (doc *deliveryDoc) deliverable() interfaces.DeliverableEvent {
	r := doc.ref()
	return interfaces.DeliverableEvent{Jti: r.Jti, StreamId: doc.Sid.Hex(), AckJti: r.AckJti, CreatedAt: r.EnqueuedAt}
}

// pendingDeliveryDoc builds the pending document of ref for sid. An empty
// AckJti is stored as Jti and a zero EnqueuedAt as now.
func pendingDeliveryDoc(sid bson.ObjectID, ref interfaces.PendingRef, now time.Time) *deliveryDoc {
	doc := &deliveryDoc{Sid: sid, Jti: ref.Jti, AckJti: ref.AckJti, State: interfaces.DeliveryStatePending, CreatedAt: ref.EnqueuedAt}
	if doc.AckJti == "" {
		doc.AckJti = doc.Jti
	}
	if doc.CreatedAt.IsZero() {
		doc.CreatedAt = now
	}
	return doc
}

// EventStoreWriteConcern is the write concern of the ingest durability
// contract (ADR 0038): events and pending references are majority-acknowledged
// and journaled before a SET is acked. It returns a fresh value so no caller
// can mutate a shared one.
func EventStoreWriteConcern() *writeconcern.WriteConcern {
	journal := true
	return &writeconcern.WriteConcern{W: "majority", Journal: &journal}
}

// oneTripBulkWriteOptions are the options of the one-trip events+deliveries
// bulkWrite. A client-level bulkWrite ignores the collection handles' write
// concern and uses the client's, and the client carries none (#332), so the
// call must request majority+journal itself or it would fall to the server
// default and weaken ADR 0038.
func oneTripBulkWriteOptions() *options.ClientBulkWriteOptionsBuilder {
	return options.ClientBulkWrite().SetOrdered(true).SetWriteConcern(EventStoreWriteConcern())
}

// ackBulkWriteOptions are the options of the one-trip ack bulkWrite (#359):
// one conditional updateMany on deliveries plus the copy inserts, unordered so
// a duplicate copy never stops the state update. It runs at w:1: an ack is
// post-persistence (ADR 0038 governs ingest only), so a state flip rolled back
// on failover costs a redelivery, which the receiver dedups by JTI, never a
// lost SET.
func ackBulkWriteOptions() *options.ClientBulkWriteOptionsBuilder {
	return options.ClientBulkWrite().SetOrdered(false).SetWriteConcern(writeconcern.W1())
}

var errEventNotInit = errors.New("mongo collection not initialized")

// errSweepNotImplemented and errMigrateNotImplemented mark the S2 methods
// whose bodies land in later slices of spec #112.
var (
	errSweepNotImplemented   = errors.New("SweepExpired is not implemented yet (i2goSignals #360)")
	errMigrateNotImplemented = errors.New("MigrateLegacyDeliveries is not implemented yet (i2goSignals #361)")
)

type EventDAOMongo struct {
	events     collectionRef
	deliveries collectionRef

	// oneTrip selects the InsertWithPending and Ack strategy (ADR 0043): true
	// issues one client-level bulkWrite across the events and deliveries
	// namespaces (MongoDB >= 8.0); false uses the two-write fallback. The
	// provider sets it from the server version at connect; the zero value is
	// the fallback, which works on every supported server.
	oneTrip atomic.Bool
}

// SetOneTripIngest selects the InsertWithPending / Ack strategy: true for the
// single multi-namespace bulkWrite (MongoDB >= 8.0 only), false for the
// two-write fallback.
func (d *EventDAOMongo) SetOneTripIngest(enabled bool) {
	d.oneTrip.Store(enabled)
}

// OneTripIngest reports the strategy SetOneTripIngest last selected.
func (d *EventDAOMongo) OneTripIngest() bool {
	return d.oneTrip.Load()
}

func NewEventDAO(eventCol, deliveriesCol *mongo.Collection) interfaces.EventDAO {
	d := &EventDAOMongo{}
	d.events.set(eventCol)
	d.deliveries.set(deliveriesCol)
	return d
}

// SetCollections rebinds the collections used by EventDAOMongo. The rebind is
// atomic per-collection; in-flight callers see consistent values for the
// collection they originally loaded.
func (d *EventDAOMongo) SetCollections(eventCol, deliveriesCol *mongo.Collection) {
	d.events.set(eventCol)
	d.deliveries.set(deliveriesCol)
}

func (d *EventDAOMongo) eventColLoad() (*mongo.Collection, error) {
	c := d.events.load()
	if c == nil {
		return nil, errEventNotInit
	}
	return c, nil
}

func (d *EventDAOMongo) deliveriesColLoad() (*mongo.Collection, error) {
	c := d.deliveries.load()
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

// InsertWithPending persists records and their pending delivery references
// (ADR 0043). On MongoDB >= 8.0 it is one ordered client-level bulkWrite
// spanning the events and deliveries namespaces; below 8.0 it is the two-write
// fallback. Both strategies store the same documents and report the same
// per-record outcomes. The unique (sid, jti) index rejects a second reference
// for the same stream exactly as the old pendingSidJti index did.
func (d *EventDAOMongo) InsertWithPending(ctx context.Context, records []*model.EventRecord, pending map[string][]interfaces.PendingRef) ([]error, error) {
	if len(records) == 0 {
		return nil, nil
	}
	ec, err := d.eventColLoad()
	if err != nil {
		return nil, err
	}
	dc, err := d.deliveriesColLoad()
	if err != nil {
		return nil, err
	}
	streams, err := pendingDocs(interfaces.StreamsByJti(pending), time.Now())
	if err != nil {
		return nil, err
	}
	if d.oneTrip.Load() {
		return insertWithPendingOneTrip(ctx, ec, dc, records, streams)
	}
	return d.insertWithPendingTwoWrite(ctx, dc, records, streams)
}

// pendingDocs converts the JTI -> stream references map to JTI -> pending
// delivery documents, failing the batch on a malformed stream ID before
// anything is written.
func pendingDocs(byJti map[string][]interfaces.StreamPending, now time.Time) (map[string][]*deliveryDoc, error) {
	out := make(map[string][]*deliveryDoc, len(byJti))
	for jti, targets := range byJti {
		docs := make([]*deliveryDoc, len(targets))
		for i, t := range targets {
			sid, err := ParseObjectID(t.StreamID)
			if err != nil {
				return nil, err
			}
			docs[i] = pendingDeliveryDoc(sid, t.Ref, now)
		}
		out[jti] = docs
	}
	return out, nil
}

// oneTripOp is one insert of insertWithPendingOneTrip: the events-collection
// body (marker == false) or one pending delivery reference of records[rec].
type oneTripOp struct {
	rec    int
	marker bool
	w      mongo.ClientBulkWrite
}

// insertWithPendingOneTrip writes every body, then every pending reference, as
// ONE ordered multi-namespace bulkWrite (ADR 0043). Grouping the ops by
// namespace lets mongod batch consecutive same-namespace inserts into one
// storage write unit per namespace; interleaving body and references per
// record alternates namespaces on every op and defeats that batching.
//
// Ordering is what keeps a duplicate from leaving an orphan reference (ADR
// 0017): an ordered bulkWrite stops at the first failed op, and every
// reference follows every body, so a rejected body is never followed by a
// written reference. On a failure at op k, every op before k is stored; op
// k's record gets its error and its remaining ops are dropped; every other op
// after k, including the references of records whose bodies already landed,
// is resubmitted in the same order. A record is reported successful only once
// its body and all its references are durable (ADR 0038). A batch with k
// per-record failures costs k+1 round trips and the common case costs one.
func insertWithPendingOneTrip(ctx context.Context, ec, dc *mongo.Collection, records []*model.EventRecord, streams map[string][]*deliveryDoc) ([]error, error) {
	client := ec.Database().Client()
	evNS := mongo.ClientBulkWrite{Database: ec.Database().Name(), Collection: ec.Name()}
	dNS := mongo.ClientBulkWrite{Database: dc.Database().Name(), Collection: dc.Name()}
	opts := oneTripBulkWriteOptions()

	// A JTI repeated in the batch needs no special casing: the repeat's body
	// insert fails the unique JTI index, and its references are dropped before
	// the resubmit.
	ops := make([]oneTripOp, 0, len(records))
	var marks []oneTripOp
	for i, rec := range records {
		w := evNS
		w.Model = mongo.NewClientInsertOneModel().SetDocument(rec)
		ops = append(ops, oneTripOp{rec: i, w: w})
		for _, doc := range streams[rec.Jti] {
			m := dNS
			m.Model = mongo.NewClientInsertOneModel().SetDocument(doc)
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
			eLog.Error("Error bulk writing events with pending references", "error", err)
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
			// The body landed but a reference did not: not acknowledgeable.
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
// write references for the records that were actually stored. References are
// only ever written after their body is known to be accepted, so no
// speculative reference exists and nothing needs retracting (ADR 0043
// supersedes the ADR 0038 concurrent-write mechanism).
func (d *EventDAOMongo) insertWithPendingTwoWrite(ctx context.Context, dc *mongo.Collection, records []*model.EventRecord, streams map[string][]*deliveryDoc) ([]error, error) {
	results, err := d.InsertMany(ctx, records)
	if err != nil {
		return nil, err
	}
	var docs []any
	var owners []int // record index each doc belongs to
	for i, rec := range records {
		if results[i] != nil {
			continue
		}
		for _, doc := range streams[rec.Jti] {
			docs = append(docs, doc)
			owners = append(owners, i)
		}
	}
	if len(docs) == 0 {
		return results, nil
	}
	_, err = dc.InsertMany(ctx, docs)
	if err == nil {
		return results, nil
	}
	var bwe mongo.BulkWriteException
	if !errors.As(err, &bwe) || bwe.WriteConcernError != nil {
		eLog.Error("Error bulk inserting pending references", "error", err)
		return nil, err
	}
	// Ordered insert: every doc before the first failure is stored; the
	// failed doc's record and every record whose references came after it are
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

	// An outbound re-signed copy (originalJti set, stored by Ack) is not an
	// inbound event: replay and reset never select it.
	queryFilter = append(queryFilter, bson.E{Key: "originalJti", Value: bson.D{{Key: "$exists", Value: false}}})

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

// pendingUpsertFilter and pendingUpsertPipeline are the AddPending upsert of
// a reference: a pipeline update so createdAt can depend on the stored state. An absent or delivered
// row gets createdAt; an already-pending row keeps its own. ackDate and
// expireAt are removed, so a delivered row returns to pending cleanly.
func pendingUpsertFilter(sid bson.ObjectID, jti string) bson.D {
	return bson.D{{Key: "sid", Value: sid}, {Key: "jti", Value: jti}}
}

func pendingUpsertPipeline(doc *deliveryDoc) mongo.Pipeline {
	return mongo.Pipeline{
		{{Key: "$set", Value: bson.D{
			{Key: "sid", Value: doc.Sid},
			{Key: "jti", Value: bson.D{{Key: "$literal", Value: doc.Jti}}},
			{Key: "ackJti", Value: bson.D{{Key: "$literal", Value: doc.AckJti}}},
			{Key: "createdAt", Value: bson.D{{Key: "$cond", Value: bson.A{
				bson.D{{Key: "$eq", Value: bson.A{"$state", interfaces.DeliveryStatePending}}},
				"$createdAt",
				doc.CreatedAt,
			}}}},
			{Key: "state", Value: interfaces.DeliveryStatePending},
		}}},
		{{Key: "$unset", Value: bson.A{"ackDate", "expireAt"}}},
	}
}

// AddPending upserts the (streamID, ref.Jti) reference to state pending with
// ref.AckJti (see the EventDAO contract for the createdAt rule).
func (d *EventDAOMongo) AddPending(ctx context.Context, ref interfaces.PendingRef, streamID string) error {
	c, err := d.deliveriesColLoad()
	if err != nil {
		return err
	}
	sid, err := ParseObjectID(streamID)
	if err != nil {
		return err
	}
	doc := pendingDeliveryDoc(sid, ref, time.Now())
	_, err = c.UpdateOne(ctx, pendingUpsertFilter(sid, doc.Jti), pendingUpsertPipeline(doc), options.UpdateOne().SetUpsert(true))
	if err != nil {
		eLog.Error("Error adding pending reference", "jti", ref.Jti, "streamID", streamID, "error", err)
	}
	return err
}

// AddPendingMany is AddPending for every ref, in one bulk write.
func (d *EventDAOMongo) AddPendingMany(ctx context.Context, refs []interfaces.PendingRef, streamID string) error {
	if len(refs) == 0 {
		return nil
	}
	c, err := d.deliveriesColLoad()
	if err != nil {
		return err
	}
	sid, err := ParseObjectID(streamID)
	if err != nil {
		return err
	}
	now := time.Now()
	models := make([]mongo.WriteModel, len(refs))
	for i, ref := range refs {
		doc := pendingDeliveryDoc(sid, ref, now)
		models[i] = mongo.NewUpdateOneModel().SetFilter(pendingUpsertFilter(sid, doc.Jti)).
			SetUpdate(pendingUpsertPipeline(doc)).SetUpsert(true)
	}
	if _, err = c.BulkWrite(ctx, models); err != nil {
		eLog.Error("Error adding pending references", "count", len(refs), "streamID", streamID, "error", err)
	}
	return err
}

// EnsurePending upserts one pending reference per stream that holds no
// deliveries document for jti in either state (#331). The upsert is keyed on
// (sid, jti) with $setOnInsert, so an existing document (its ackJti and
// createdAt included) is untouched and a concurrent duplicate cannot produce a
// second reference. The bulk write's UpsertedIDs name the queued streams.
func (d *EventDAOMongo) EnsurePending(ctx context.Context, jti string, ackJtis map[string]string) ([]string, error) {
	if len(ackJtis) == 0 {
		return nil, nil
	}
	c, err := d.deliveriesColLoad()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	streamIDs := make([]string, 0, len(ackJtis))
	models := make([]mongo.WriteModel, 0, len(ackJtis))
	for streamID, ackJti := range ackJtis {
		sid, err := ParseObjectID(streamID)
		if err != nil {
			return nil, err
		}
		doc := pendingDeliveryDoc(sid, interfaces.PendingRef{Jti: jti, AckJti: ackJti}, now)
		streamIDs = append(streamIDs, streamID)
		models = append(models, mongo.NewUpdateOneModel().SetFilter(pendingUpsertFilter(sid, jti)).
			SetUpdate(bson.D{{Key: "$setOnInsert", Value: doc}}).SetUpsert(true))
	}
	res, err := c.BulkWrite(ctx, models, options.BulkWrite().SetOrdered(false))
	if err != nil {
		var bwe mongo.BulkWriteException
		if !errors.As(err, &bwe) || bwe.WriteConcernError != nil || !allDuplicateKey(bwe.WriteErrors) {
			eLog.Error("Error re-queuing pending references", "jti", jti, "error", err)
			return nil, err
		}
		// A duplicate key is a concurrent upsert that won the race: that
		// stream already holds its reference, so it is not queued here.
	}
	if res == nil {
		return nil, nil
	}
	var queued []string
	for idx := range res.UpsertedIDs {
		if idx >= 0 && int(idx) < len(streamIDs) {
			queued = append(queued, streamIDs[idx])
		}
	}
	return queued, nil
}

func allDuplicateKey(wes []mongo.BulkWriteError) bool {
	for _, we := range wes {
		if !mongo.IsDuplicateKeyError(we.WriteError) {
			return false
		}
	}
	return true
}

// GetPendingForStream returns one page of streamID's pending references.
//
// Sort by jti, explicitly. jtis are UUIDv7 (goSet.GenerateJti), so ascending
// jti IS ascending issue order, and the {sid,state,jti} index supplies that
// order directly. The sort is stated rather than inherited because without it
// the order is whatever plan the query planner happens to pick. Delivery order
// is a contract receivers reason about (ADR 0040), so it may not be a side
// effect of index selection. A limit <= 0 reads every pending reference.
func (d *EventDAOMongo) GetPendingForStream(ctx context.Context, streamID string, limit int32) (interfaces.PendingPage, error) {
	page := interfaces.PendingPage{Refs: []interfaces.PendingRef{}}
	c, err := d.deliveriesColLoad()
	if err != nil {
		return page, err
	}
	sid, err := ParseObjectID(streamID)
	if err != nil {
		return page, err
	}
	filter := bson.D{{Key: "sid", Value: sid}, {Key: "state", Value: interfaces.DeliveryStatePending}}

	page.Total, err = c.CountDocuments(ctx, filter)
	if err != nil {
		eLog.Error("Error counting pending references", "error", err)
		return page, err
	}
	if page.Total == 0 {
		return page, nil
	}

	opts := options.Find().SetSort(bson.D{{Key: "jti", Value: 1}})
	if limit > 0 {
		opts.SetLimit(int64(limit))
	}
	cursor, err := c.Find(ctx, filter, opts)
	if err != nil {
		eLog.Error("Error getting pending references", "error", err)
		return page, err
	}
	var docs []deliveryDoc
	if err = cursor.All(ctx, &docs); err != nil {
		eLog.Error("Error parsing pending references", "error", err)
		return page, err
	}
	for i := range docs {
		page.Refs = append(page.Refs, docs[i].ref())
	}

	if page.Total > int64(len(page.Refs)) && len(page.Refs) > 0 {
		last := page.Refs[len(page.Refs)-1].Jti
		beyond := bson.D{
			{Key: "sid", Value: sid},
			{Key: "state", Value: interfaces.DeliveryStatePending},
			{Key: "jti", Value: bson.D{{Key: "$gt", Value: last}}},
		}
		var oldest deliveryDoc
		err = c.FindOne(ctx, beyond, options.FindOne().SetSort(bson.D{{Key: "createdAt", Value: 1}})).Decode(&oldest)
		switch {
		case err == nil:
			page.OldestBeyond = oldest.CreatedAt
		case errors.Is(err, mongo.ErrNoDocuments):
			// Drained between the count and this read.
		default:
			eLog.Error("Error reading oldest pending reference beyond the page", "error", err)
			return page, err
		}
	}
	return page, nil
}

// RemovePendingMany finds streamID's pending references for jtis in one query,
// deletes exactly those in one DeleteMany, and returns them. Delivered
// references are never touched.
func (d *EventDAOMongo) RemovePendingMany(ctx context.Context, jtis []string, streamID string) ([]interfaces.DeliverableEvent, error) {
	if len(jtis) == 0 {
		return nil, nil
	}
	c, err := d.deliveriesColLoad()
	if err != nil {
		return nil, err
	}
	sid, err := ParseObjectID(streamID)
	if err != nil {
		return nil, err
	}
	filter := bson.D{
		{Key: "sid", Value: sid},
		{Key: "state", Value: interfaces.DeliveryStatePending},
		{Key: "jti", Value: bson.D{{Key: "$in", Value: jtis}}},
	}
	cursor, err := c.Find(ctx, filter)
	if err != nil {
		eLog.Error("Error finding pending references", "error", err)
		return nil, err
	}
	var docs []deliveryDoc
	if err = cursor.All(ctx, &docs); err != nil {
		eLog.Error("Error decoding pending references", "error", err)
		return nil, err
	}
	if len(docs) == 0 {
		return nil, nil
	}
	removed := make([]interfaces.DeliverableEvent, len(docs))
	found := make([]string, len(docs))
	for i := range docs {
		removed[i] = docs[i].deliverable()
		found[i] = docs[i].Jti
	}
	del := bson.D{
		{Key: "sid", Value: sid},
		{Key: "state", Value: interfaces.DeliveryStatePending},
		{Key: "jti", Value: bson.D{{Key: "$in", Value: found}}},
	}
	if _, err = c.DeleteMany(ctx, del); err != nil {
		eLog.Error("Error deleting pending references", "error", err)
		return nil, err
	}
	return removed, nil
}

// ClearPendingForStream deletes every pending reference of streamID.
func (d *EventDAOMongo) ClearPendingForStream(ctx context.Context, streamID string) (int64, error) {
	c, err := d.deliveriesColLoad()
	if err != nil {
		return 0, err
	}
	sid, err := ParseObjectID(streamID)
	if err != nil {
		return 0, err
	}
	many, err := c.DeleteMany(ctx, bson.D{{Key: "sid", Value: sid}, {Key: "state", Value: interfaces.DeliveryStatePending}})
	if err != nil {
		eLog.Error("Error clearing pending references", "error", err)
		return 0, err
	}
	return many.DeletedCount, nil
}

// ackFilterUpdate is the conditional state flip of an ack batch.
func ackFilterUpdate(sid bson.ObjectID, batch interfaces.AckBatch) (bson.D, bson.D) {
	filter := bson.D{
		{Key: "sid", Value: sid},
		{Key: "ackJti", Value: bson.D{{Key: "$in", Value: batch.Jtis}}},
		{Key: "state", Value: interfaces.DeliveryStatePending},
	}
	set := bson.D{
		{Key: "state", Value: interfaces.DeliveryStateDelivered},
		{Key: "ackDate", Value: batch.AckDate},
	}
	if batch.ExpireAt != nil {
		set = append(set, bson.E{Key: "expireAt", Value: *batch.ExpireAt})
	}
	return filter, bson.D{{Key: "$set", Value: set}}
}

// Ack acknowledges one stream's batch with one conditional write: every
// pending reference of the stream whose ackJti is in batch.Jtis becomes
// delivered, and batch.Copies are stored in events. There is no read and no
// retract, so two concurrent acks of the same JTI move it exactly once. On
// MongoDB 8.0+ (the strategy SetOneTripIngest selects) it is ONE unordered
// client bulkWrite; below 8.0 the copies are an unordered insertMany followed
// by the updateMany. Both run at w:1 (see ackBulkWriteOptions). A duplicate
// key on a copy counts as stored.
func (d *EventDAOMongo) Ack(ctx context.Context, batch interfaces.AckBatch) (int64, error) {
	if len(batch.Jtis) == 0 && len(batch.Copies) == 0 {
		return 0, nil
	}
	dc, err := d.deliveriesColLoad()
	if err != nil {
		return 0, err
	}
	ec, err := d.eventColLoad()
	if err != nil {
		return 0, err
	}
	sid, err := ParseObjectID(batch.StreamID)
	if err != nil {
		return 0, err
	}
	if d.oneTrip.Load() {
		return ackOneTrip(ctx, ec, dc, sid, batch)
	}
	return ackTwoWrite(ctx, ec, dc, sid, batch)
}

func ackOneTrip(ctx context.Context, ec, dc *mongo.Collection, sid bson.ObjectID, batch interfaces.AckBatch) (int64, error) {
	evNS := mongo.ClientBulkWrite{Database: ec.Database().Name(), Collection: ec.Name()}
	dNS := mongo.ClientBulkWrite{Database: dc.Database().Name(), Collection: dc.Name()}
	writes := make([]mongo.ClientBulkWrite, 0, len(batch.Copies)+1)
	if len(batch.Jtis) > 0 {
		filter, update := ackFilterUpdate(sid, batch)
		w := dNS
		w.Model = mongo.NewClientUpdateManyModel().SetFilter(filter).SetUpdate(update)
		writes = append(writes, w)
	}
	for _, rec := range batch.Copies {
		w := evNS
		w.Model = mongo.NewClientInsertOneModel().SetDocument(rec)
		writes = append(writes, w)
	}
	res, err := dc.Database().Client().BulkWrite(ctx, writes, ackBulkWriteOptions())
	if err == nil {
		if res == nil {
			return 0, nil
		}
		return res.ModifiedCount, nil
	}
	var cbe mongo.ClientBulkWriteException
	if !errors.As(err, &cbe) || cbe.WriteError != nil || len(cbe.WriteConcernErrors) > 0 {
		eLog.Error("Error bulk writing ack", "streamID", batch.StreamID, "error", err)
		return 0, err
	}
	for _, we := range cbe.WriteErrors {
		if !mongo.IsDuplicateKeyError(we) {
			eLog.Error("Error bulk writing ack", "streamID", batch.StreamID, "error", err)
			return 0, err
		}
	}
	if cbe.PartialResult == nil {
		return 0, nil
	}
	return cbe.PartialResult.ModifiedCount, nil
}

func ackTwoWrite(ctx context.Context, ec, dc *mongo.Collection, sid bson.ObjectID, batch interfaces.AckBatch) (int64, error) {
	w1 := options.Collection().SetWriteConcern(writeconcern.W1())
	if len(batch.Copies) > 0 {
		docs := make([]any, len(batch.Copies))
		for i, rec := range batch.Copies {
			docs[i] = rec
		}
		_, err := ec.Clone(w1).InsertMany(ctx, docs, options.InsertMany().SetOrdered(false))
		if err != nil {
			var bwe mongo.BulkWriteException
			if !errors.As(err, &bwe) || bwe.WriteConcernError != nil || !allDuplicateKey(bwe.WriteErrors) {
				eLog.Error("Error storing ack copies", "streamID", batch.StreamID, "error", err)
				return 0, err
			}
		}
	}
	if len(batch.Jtis) == 0 {
		return 0, nil
	}
	filter, update := ackFilterUpdate(sid, batch)
	res, err := dc.Clone(w1).UpdateMany(ctx, filter, update)
	if err != nil {
		eLog.Error("Error acking pending references", "streamID", batch.StreamID, "error", err)
		return 0, err
	}
	return res.ModifiedCount, nil
}

// ResetPendingAckJti sets ackJti = jti on every pending reference of streamID
// whose ackJti differs, in one pipeline updateMany at the collection's
// (majority) concern. Delivered references are untouched.
func (d *EventDAOMongo) ResetPendingAckJti(ctx context.Context, streamID string) (int64, error) {
	c, err := d.deliveriesColLoad()
	if err != nil {
		return 0, err
	}
	sid, err := ParseObjectID(streamID)
	if err != nil {
		return 0, err
	}
	filter := bson.D{
		{Key: "sid", Value: sid},
		{Key: "state", Value: interfaces.DeliveryStatePending},
		{Key: "$expr", Value: bson.D{{Key: "$ne", Value: bson.A{"$ackJti", "$jti"}}}},
	}
	update := mongo.Pipeline{{{Key: "$set", Value: bson.D{{Key: "ackJti", Value: "$jti"}}}}}
	res, err := c.UpdateMany(ctx, filter, update)
	if err != nil {
		eLog.Error("Error resetting pending ackJti", "streamID", streamID, "error", err)
		return 0, err
	}
	return res.ModifiedCount, nil
}

// SweepExpired is implemented by #360.
func (d *EventDAOMongo) SweepExpired(_ context.Context, _ time.Time, _ time.Time, _ int) (interfaces.SweepResult, error) {
	return interfaces.SweepResult{}, errSweepNotImplemented
}

// MigrateLegacyDeliveries is implemented by #361.
func (d *EventDAOMongo) MigrateLegacyDeliveries(_ context.Context, _ func(streamID string, ackDate time.Time) *time.Time) (interfaces.MigrationResult, error) {
	return interfaces.MigrationResult{}, errMigrateNotImplemented
}

// ListDeliveredForStream returns streamID's delivered (post-ack) references
// with their AckDate — the retention purge clock's enumerator (ADR 0055).
func (d *EventDAOMongo) ListDeliveredForStream(ctx context.Context, streamID string) ([]interfaces.DeliveredEvent, error) {
	c, err := d.deliveriesColLoad()
	if err != nil {
		return nil, err
	}
	sid, err := ParseObjectID(streamID)
	if err != nil {
		return nil, err
	}
	cursor, err := c.Find(ctx, bson.D{{Key: "sid", Value: sid}, {Key: "state", Value: interfaces.DeliveryStateDelivered}})
	if err != nil {
		eLog.Error("Error listing delivered references", "error", err)
		return nil, err
	}
	var docs []deliveryDoc
	if err = cursor.All(ctx, &docs); err != nil {
		eLog.Error("Error parsing delivered references", "error", err)
		return nil, err
	}
	out := make([]interfaces.DeliveredEvent, len(docs))
	for i := range docs {
		out[i] = interfaces.DeliveredEvent{DeliverableEvent: docs[i].deliverable(), ExpireAt: docs[i].ExpireAt}
		if docs[i].AckDate != nil {
			out[i].AckDate = *docs[i].AckDate
		}
	}
	return out, nil
}

// RemoveDelivered drops streamID's delivered reference for jti (its retention
// clock firing). A pending reference and the global body are left untouched.
func (d *EventDAOMongo) RemoveDelivered(ctx context.Context, jti string, streamID string) error {
	c, err := d.deliveriesColLoad()
	if err != nil {
		return err
	}
	sid, err := ParseObjectID(streamID)
	if err != nil {
		return err
	}
	_, err = c.DeleteOne(ctx, bson.D{{Key: "sid", Value: sid}, {Key: "jti", Value: jti}, {Key: "state", Value: interfaces.DeliveryStateDelivered}})
	if err != nil {
		eLog.Error("Error removing delivered reference", "error", err)
	}
	return err
}

// DeleteBodyIfUnreferenced deletes the global body for jti only when no stream
// still references it in either state (refcount 0).
func (d *EventDAOMongo) DeleteBodyIfUnreferenced(ctx context.Context, jti string) (bool, error) {
	dc, err := d.deliveriesColLoad()
	if err != nil {
		return false, err
	}
	ec, err := d.eventColLoad()
	if err != nil {
		return false, err
	}
	refs, err := dc.CountDocuments(ctx, bson.D{{Key: "jti", Value: jti}}, options.Count().SetLimit(1))
	if err != nil {
		eLog.Error("Error counting delivery references", "error", err)
		return false, err
	}
	if refs > 0 {
		return false, nil
	}
	res, err := ec.DeleteOne(ctx, bson.D{{Key: "jti", Value: jti}})
	if err != nil {
		eLog.Error("Error deleting event body", "error", err)
		return false, err
	}
	return res.DeletedCount > 0, nil
}

// CountRetainedForStream counts streamID's delivered (post-ack-retained) JTIs.
func (d *EventDAOMongo) CountRetainedForStream(ctx context.Context, streamID string) (int64, error) {
	c, err := d.deliveriesColLoad()
	if err != nil {
		return 0, err
	}
	sid, err := ParseObjectID(streamID)
	if err != nil {
		return 0, err
	}
	return c.CountDocuments(ctx, bson.D{{Key: "sid", Value: sid}, {Key: "state", Value: interfaces.DeliveryStateDelivered}})
}

// WatchPending watches deliveries for inserts, updates and replaces whose
// document is pending, and calls back with each reference.
func (d *EventDAOMongo) WatchPending(ctx context.Context, callback func(ref interfaces.PendingRef, streamID string)) error {
	c, err := d.deliveriesColLoad()
	if err != nil {
		return err
	}
	match := bson.D{{Key: "$match", Value: bson.D{
		{Key: "operationType", Value: bson.D{{Key: "$in", Value: bson.A{"insert", "update", "replace"}}}},
		{Key: "fullDocument.state", Value: interfaces.DeliveryStatePending},
	}}}

	opts := options.ChangeStream().SetFullDocument(options.UpdateLookup)
	eventStream, err := c.Watch(ctx, mongo.Pipeline{match}, opts)
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
		var change struct {
			FullDocument *deliveryDoc `bson:"fullDocument"`
		}
		if err := eventStream.Decode(&change); err != nil {
			eLog.Error("Error decoding change event", "error", err)
			continue
		}
		doc := change.FullDocument
		if doc == nil || doc.Jti == "" || doc.Sid.IsZero() || doc.State != interfaces.DeliveryStatePending {
			continue
		}
		callback(doc.ref(), doc.Sid.Hex())
	}

	if err := eventStream.Err(); err != nil {
		eLog.Error("Background event stream stopped with error", "error", err)
		return err
	}

	eLog.Info("Background event stream stopped")
	return nil
}
