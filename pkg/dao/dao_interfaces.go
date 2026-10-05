package dao

import (
	"context"
	"crypto"
	"crypto/rsa"
	"errors"
	"net/url"
	"time"

	"github.com/i2-open/i2goSignals/pkg/ssfModels"
)

var (
	ErrNotFound    = errors.New("not found")
	ErrKeyNotFound = errors.New("key not found")
	// ErrDuplicateJTI is returned by EventDAO.Insert when the record's JTI
	// already exists in the events collection. The JTI is the persistence-layer
	// dedup key (RFC 8417 §2.2 globally unique). Callers MUST handle this
	// sentinel; the existing record is retrievable via EventDAO.FindByJTI(jti).
	ErrDuplicateJTI = errors.New("duplicate jti")
)

// StreamDAO handles stream configuration data access
type StreamDAO interface {
	// Basic CRUD
	Create(ctx context.Context, state *model.StreamStateRecord) error
	FindByID(ctx context.Context, id string) (*model.StreamStateRecord, error)
	Update(ctx context.Context, state *model.StreamStateRecord) error
	Delete(ctx context.Context, id string) error
	List(ctx context.Context) ([]model.StreamStateRecord, error)

	// Queries
	FindByProjectID(ctx context.Context, projectID string) ([]model.StreamStateRecord, error)

	// FindByInboundSID returns the SSTP pair record whose receive-side
	// (SstpInbound.Id) equals sid, or ErrNotFound. Only SSTP pair records carry
	// an SstpInbound, so non-SSTP records are never matched. (PRD #154 Q24)
	FindByInboundSID(ctx context.Context, sid string) (*model.StreamStateRecord, error)

	// FindByPairId returns the record whose PairId equals pairId, or ErrNotFound.
	// PairId is the on-wire SSF stream_id for an SSTP pair. (PRD #154 Q24)
	FindByPairId(ctx context.Context, pairId string) (*model.StreamStateRecord, error)

	// Status updates

	// UpdateStatus writes status and errorMsg and clears transmitter_caused
	// (#310): an ordinary status write is never the transmitter's report. It
	// also clears key_unavailable_since (#312).
	UpdateStatus(ctx context.Context, id string, status string, errorMsg string) error

	// UpdateTransmitterCausedStatus writes a paused or disabled status the
	// transmitter's status endpoint reported, setting transmitter_caused with
	// the status and errorMsg (#310). It clears key_unavailable_since (#312).
	UpdateTransmitterCausedStatus(ctx context.Context, id string, status string, errorMsg string) error

	// UpdateKeyUnavailablePause writes a key-unavailable pause (#312): status
	// paused with errorMsg, and key_unavailable_since set to since unless the
	// stored record already carries an earlier time, so a repeat failure keeps
	// the first. It clears transmitter_caused.
	UpdateKeyUnavailablePause(ctx context.Context, id string, errorMsg string, since time.Time) error

	// UpdateIfStatus replaces the stored record with state, as Update does, but
	// only while the stored status is still status, atomically: it reports
	// whether the write applied. An unknown stream is ErrNotFound. The
	// background key check's pause uses it so an operator change made after
	// the check read the stream wins (#318).
	UpdateIfStatus(ctx context.Context, state *model.StreamStateRecord, status string) (bool, error)

	// UpdateRemoteAddress persists only the remote_address sub-document for the given stream.
	UpdateRemoteAddress(ctx context.Context, id string, addr *model.RemoteIP) error
}

// EventDAO handles event data access
type EventDAO interface {
	// Event storage
	//
	// Insert persists a single event record. The JTI is the persistence-layer
	// dedup key for the events collection: implementations MUST return
	// ErrDuplicateJTI when the JTI already exists, and MUST NOT overwrite the
	// existing record. Callers MUST handle ErrDuplicateJTI; the existing
	// record is retrievable via FindByJTI(jti).
	Insert(ctx context.Context, record *model.EventRecord) error
	// InsertMany persists records in slice order as one bulk write, continuing
	// past per-record failures. The returned slice is index-aligned with
	// records: nil for a stored record, ErrDuplicateJTI when that JTI already
	// existed (the existing record is untouched and retrievable via
	// FindByJTI), or the record's own write error. A non-nil error means the
	// batch as a whole could not be attempted (the per-record slice is then
	// nil). An empty batch returns (nil, nil).
	InsertMany(ctx context.Context, records []*model.EventRecord) ([]error, error)
	// InsertWithPending persists records together with their delivery
	// references (ADR 0043). pending maps a stream document ID to the
	// references of records that must be queued on that stream: one
	// deliveries document per (stream, reference) in state pending, carrying
	// the reference's AckJti (Jti when empty) and createdAt (EnqueuedAt, or
	// the adapter clock when zero). The returned slice is index-aligned with
	// records:
	//
	//   - nil: the record AND every pending reference for its JTI are stored.
	//   - ErrDuplicateJTI: the JTI already existed (ADR 0017); the existing
	//     record is untouched and NO reference was written for it.
	//   - any other error: the record, or one of its references, was not
	//     stored, so the SET must not be acknowledged (ADR 0038).
	//
	// When a JTI appears more than once in records, its references are
	// written once, with the copy that is stored; later copies report
	// ErrDuplicateJTI. A reference with no matching record is ignored. A
	// non-nil error means the batch as a whole failed (the per-record slice
	// is then nil). An empty batch returns (nil, nil).
	InsertWithPending(ctx context.Context, records []*model.EventRecord, pending map[string][]PendingRef) ([]error, error)
	FindByJTI(ctx context.Context, jti string) (*model.EventRecord, error)
	FindByJTIs(ctx context.Context, jtis []string) ([]*model.EventRecord, error)
	// FindByTimeRange returns records whose sort time falls in [from, to]
	// and that pass filter. Stored outbound copies (records carrying
	// OriginalJti) are excluded, so a reset never re-queues a copy.
	FindByTimeRange(ctx context.Context, from time.Time, to *time.Time, filter func(*model.EventRecord) bool) ([]*model.EventRecord, error)

	// Pending references (deliveries in state pending)
	//
	// AddPending upserts the (streamID, ref.Jti) reference to state pending
	// with ref.AckJti, unsetting ackDate and expireAt. createdAt is set when
	// the row is inserted, re-set when a delivered row returns to pending,
	// and left unchanged when the row is already pending.
	AddPending(ctx context.Context, ref PendingRef, streamID string) error
	// AddPendingMany is AddPending for every ref, in one bulk write. An empty
	// refs is a no-op.
	AddPendingMany(ctx context.Context, refs []PendingRef, streamID string) error
	// EnsurePending queues jti on every stream of ackJtis (stream ID ->
	// ackJti) that holds no deliveries document for it in either state, and
	// returns the stream IDs it queued on (order unspecified). An existing
	// document is left untouched, including its ackJti and createdAt, so the
	// call is idempotent. It is the ADR 0043 residual repair (#331). An empty
	// ackJtis returns (nil, nil).
	EnsurePending(ctx context.Context, jti string, ackJtis map[string]string) ([]string, error) // stream ID -> ackJti
	// GetPendingForStream returns one page of streamID's pending references
	// in ascending Jti order (see PendingPage).
	GetPendingForStream(ctx context.Context, streamID string, limit int32) (PendingPage, error)
	// RemovePendingMany deletes every entry of jtis (inbound JTIs) that is
	// pending for streamID and returns the removed entries (order
	// unspecified). A JTI not pending for the stream is skipped. An empty
	// jtis returns (nil, nil).
	RemovePendingMany(ctx context.Context, jtis []string, streamID string) ([]DeliverableEvent, error)
	// ClearPendingForStream deletes every pending reference of streamID and
	// returns the count. Delivered references are untouched.
	ClearPendingForStream(ctx context.Context, streamID string) (int64, error)

	// Ack acknowledges one stream's batch: every deliveries document of
	// batch.StreamID whose ackJti is in batch.Jtis and whose state is pending
	// becomes delivered at batch.AckDate (with batch.ExpireAt when set), and
	// batch.Copies are stored in events (a duplicate key counts as stored).
	// It is one conditional write with no read and no retract; it returns
	// the number of references moved to delivered. A JTI not pending for the
	// stream is skipped. Empty Jtis and empty Copies returns (0, nil).
	Ack(ctx context.Context, batch AckBatch) (acked int64, err error)
	// ResetPendingAckJti sets ackJti = jti on every pending reference of
	// streamID whose ackJti differs, in one write, and returns the modified
	// count. Delivered references are untouched.
	ResetPendingAckJti(ctx context.Context, streamID string) (modified int64, err error)
	// SweepExpired removes references with expireAt <= now, then deletes at
	// most maxBodies unreferenced bodies older than bodyCutoff.
	SweepExpired(ctx context.Context, now time.Time, bodyCutoff time.Time, maxBodies int) (SweepResult, error)
	// MigrateLegacyDeliveries carries pendingEvents / deliveredEvents rows
	// into deliveries and drops the old collections; idempotent.
	MigrateLegacyDeliveries(ctx context.Context, expireAt func(streamID string, ackDate time.Time) *time.Time) (MigrationResult, error)

	// --- Ack-anchored retention purge + occupancy sampling (ADR 0055) ---

	// ListDeliveredForStream returns streamID's delivered (post-ack,
	// not-yet-purged) references, each carrying its AckDate. Order is
	// unspecified.
	ListDeliveredForStream(ctx context.Context, streamID string) ([]DeliveredEvent, error)

	// RemoveDelivered drops streamID's delivered reference for jti. It does
	// NOT touch the global event body; body deletion is refcount-gated via
	// DeleteBodyIfUnreferenced. Removing an entry that does not exist (or is
	// pending) is not an error.
	RemoveDelivered(ctx context.Context, jti string, streamID string) error

	// DeleteBodyIfUnreferenced deletes the global event body for jti ONLY
	// when no deliveries document in either state has that jti. It reports
	// whether the body was deleted; a still-referenced or absent body is not
	// an error.
	DeleteBodyIfUnreferenced(ctx context.Context, jti string) (deleted bool, err error)

	// CountRetainedForStream returns the number of delivered references of
	// streamID (pending excluded).
	CountRetainedForStream(ctx context.Context, streamID string) (int64, error)

	// WatchPending reports every deliveries insert or update that leaves a
	// row in state pending; the callback receives the row's jti and ackJti.
	WatchPending(ctx context.Context, callback func(ref PendingRef, streamID string)) error
}

// Delivery reference states stored in deliveries.state. state is a string so
// a later state needs no migration.
const (
	DeliveryStatePending   = "pending"
	DeliveryStateDelivered = "delivered"
)

// PendingPage is one pending read for a stream.
type PendingPage struct {
	Refs         []PendingRef // state pending, ascending Jti, at most limit
	Total        int64        // every pending row of the stream
	OldestBeyond time.Time    // earliest createdAt among pending rows after the last of Refs; zero when Total == len(Refs)
}

// AckBatch is one stream's acknowledgement batch.
type AckBatch struct {
	StreamID string
	Jtis     []string // acknowledgement JTIs: matched against deliveries.ackJti
	AckDate  time.Time
	ExpireAt *time.Time           // nil: keep forever
	Copies   []*model.EventRecord // outbound re-signed copies to store; may be nil
}

// SweepResult reports one SweepExpired pass.
type SweepResult struct {
	References int64 // deliveries removed because expireAt <= now
	Bodies     int64 // events documents deleted
}

// MigrationResult reports one MigrateLegacyDeliveries pass.
type MigrationResult struct {
	Pending   int64 // rows carried from pendingEvents
	Delivered int64 // rows carried from deliveredEvents
	Dropped   bool  // both old collections are gone
}

// PendingRef names one delivery reference. Jti is the inbound JTI (the events
// key). AckJti is the JTI the SET carries on the wire for that stream and the
// JTI the receiver acknowledges with. An empty AckJti is stored as Jti; every
// read returns it non-empty. EnqueuedAt is the enqueue time (deliveries.createdAt):
// a writer sets it from its own clock when it builds the reference; a zero
// value is stored as the adapter's clock at the write; every read returns the
// stored value.
type PendingRef struct {
	Jti        string
	AckJti     string
	EnqueuedAt time.Time
}

// SubjectFilterDAO handles per-stream SSF §8.1.3 subject filter entries. The
// store is keyed by (stream_id, canonical_key) so simple-subject membership is
// an indexed point lookup, never a collection scan (ADR-0003).
type SubjectFilterDAO interface {
	// Add inserts or replaces the subject entry for its (stream, canonical key).
	Add(ctx context.Context, entry *model.SubjectFilterEntry) error
	// Get returns the entry for a stream + canonical key, or ErrNotFound.
	Get(ctx context.Context, streamID, canonicalKey string) (*model.SubjectFilterEntry, error)
	// Remove deletes the entry for a stream + canonical key. Removing an entry
	// that does not exist is not an error.
	Remove(ctx context.Context, streamID, canonicalKey string) error
	// ClearForStream deletes every subject filter entry for the given stream.
	// It is the storage side of the defaultSubjects-flip filter clear.
	ClearForStream(ctx context.Context, streamID string) error
	// ListComplex returns the non-simple (complex and aliases) entries for a
	// stream. Simple entries are deliberately excluded — they are reached by
	// indexed Get; the complex/aliases entries need the field-wise scan path
	// (ADR-0003).
	ListComplex(ctx context.Context, streamID string) ([]*model.SubjectFilterEntry, error)
	// ListPendingDue returns every entry for streamID whose EnforceAt is set
	// and has elapsed at now — the SSF §9.3 sweep enumerator (PRD #97 issue
	// #100). It is the lookup that lets the push-transmitter lease owner
	// discover deferred HYBRID upstream removes due to be relayed. The mongo
	// adapter rides the sparse partial index on enforce_at so the call stays
	// cheap even when the full filter table holds millions of active entries.
	ListPendingDue(ctx context.Context, streamID string, now time.Time) ([]*model.SubjectFilterEntry, error)
	// ListPending returns every entry for streamID currently inside its SSF
	// §9.3 grace window — EnforceAt set and strictly in the future at now.
	// It is the admin-review enumerator (PRD #97 issue #101): the bounded list
	// of subjects mid-removal. The boundary is exclusive, the complement of
	// ListPendingDue's inclusive boundary, so an entry exactly at EnforceAt is
	// considered elapsed (sweep-eligible), not pending.
	ListPending(ctx context.Context, streamID string, now time.Time) ([]*model.SubjectFilterEntry, error)
	// Count returns the total entry count for streamID and the count of
	// entries currently inside their §9.3 grace window (PRD #97 issue #101).
	// The pending count uses the same predicate as ListPending — EnforceAt
	// strictly after now — so the admin review's counts and pending list
	// agree.
	Count(ctx context.Context, streamID string, now time.Time) (total, pending int64, err error)
}

// KeyDAO handles cryptographic key data access
type KeyDAO interface {
	Insert(ctx context.Context, keyRec *JwkKeyRec) error
	FindByKid(ctx context.Context, kid string) (*JwkKeyRec, error)
	FindByKeyName(ctx context.Context, keyName string) ([]*JwkKeyRec, error)
	FindLatestByKeyName(ctx context.Context, keyName string) (*JwkKeyRec, error)
	FindByStreamID(ctx context.Context, streamID string) (*JwkKeyRec, error)
	DeleteByKid(ctx context.Context, kid string) error
	DeleteByKeyName(ctx context.Context, keyName string) error
	// DeleteByKeyNameAndAlg removes every record under keyName whose Alg equals
	// alg, the stored discriminator ("" is RSA), and leaves the keyName's records
	// of other algorithms in place. Returns ErrKeyNotFound when none matched.
	DeleteByKeyNameAndAlg(ctx context.Context, keyName string, alg string) error
	// SetKeyStatus sets the lifecycle timestamps on matching key record(s). A nil
	// pointer leaves that field unchanged; a non-nil pointer sets it (pass the
	// zero time to clear — in practice only SuspendedAt is ever cleared). When
	// kid is non-empty only that record is updated; otherwise every record under
	// keyName is updated. RevokedAt is write-once: a record that already carries
	// a RevokedAt is never re-stamped or cleared. Returns the number of records
	// changed, or ErrKeyNotFound when no record matched keyName/kid. The status
	// predicate (transition rules) lives in KeyService, not here.
	SetKeyStatus(ctx context.Context, keyName string, kid string, suspendedAt *time.Time, revokedAt *time.Time) (int, error)
	ListKids(ctx context.Context) ([]string, error)
	ListKeyNames(ctx context.Context) ([]string, error)
	KeySummary(ctx context.Context, keyName string) (*KeySummary, error)
	ListSummaries(ctx context.Context) ([]KeySummary, error)
}

// ClientDAO handles client registration data access
type ClientDAO interface {
	Insert(ctx context.Context, client *model.SsfClient) error
	FindByID(ctx context.Context, id string) (*model.SsfClient, error)
	FindByProjectID(ctx context.Context, projectID string) ([]*model.SsfClient, error)
	Delete(ctx context.Context, id string) error
}

// TokenDAO handles token management data access
type TokenDAO interface {
	Insert(ctx context.Context, record *model.TokenRecord) error
	FindByJTI(ctx context.Context, jti string) (*model.TokenRecord, error)
	Revoke(ctx context.Context, jti string) error
	// RevokeAt stamps revoked_at to a caller-supplied instant. A future instant
	// implements rotate-on-GET deferred revocation (ADR 0022 §2): the old bearer
	// stays valid until the grace elapses. A now/past instant revokes
	// immediately, matching Revoke.
	RevokeAt(ctx context.Context, jti string, at time.Time) error
	// RecordRedemption captures a token redemption: it increments
	// redemption_count and overwrites last_redemption_ip/last_redemption_at.
	// Per ADR 0007 this is the "where is it used" signal (not issuance).
	RecordRedemption(ctx context.Context, jti string, ip string, at time.Time) error
	DeleteExpired(ctx context.Context) error
	FindByProjectID(ctx context.Context, projectID string) ([]*model.TokenRecord, error)
	FindByClientID(ctx context.Context, clientID string) ([]*model.TokenRecord, error)
	// FindAll returns every tracked token regardless of project. Used by the
	// caller-scoped list for admin/root callers who see all projects.
	FindAll(ctx context.Context) ([]*model.TokenRecord, error)
}

// ServerDAO handles server configuration data access
type ServerDAO interface {
	Create(ctx context.Context, server *model.Server) error
	FindByID(ctx context.Context, id string) (*model.Server, error)
	FindByAlias(ctx context.Context, alias string) (*model.Server, error)
	Update(ctx context.Context, server *model.Server) error
	Delete(ctx context.Context, id string) error
	List(ctx context.Context) ([]model.Server, error)
}

// JwkKeyRec represents a cryptographic key record.
//
// Id is an opaque 24-character hex string (see pkg/dao/ids). The Mongo
// adapter stores this internally as a bson.ObjectID via a private doc type
// for backward compatibility with existing data; callers must not assume
// the Mongo serialization format.
// Key lifecycle status values. Status is DERIVED from the SuspendedAt/RevokedAt
// timestamps on a JwkKeyRec (see JwkKeyRec.Status) and is never stored — the
// timestamp representation mirrors TokenRecord/ADR 0022 and leaves room for
// future-dated or windowed policy without a schema change (ADR 0028).
const (
	KeyStatusActive    = "active"    // signing candidate; published in all JWKS
	KeyStatusSuspended = "suspended" // reversible; not a signing candidate; still published for verification
	KeyStatusRevoked   = "revoked"   // terminal; not a signing candidate; excluded from JWKS

	// The validity statuses are derived against a clock (see StatusAt), never
	// from a stored stamp (i2goSignals#318). Neither is a signing candidate;
	// both stay published for verification.
	KeyStatusExpired     = "expired"       // past NotAfter
	KeyStatusNotYetValid = "not-yet-valid" // before NotBefore
)

type JwkKeyRec struct {
	Id              string `json:"id"`
	KeyName         string `json:"keyName"`       // primary identifier; replaces Iss/Aud
	Kid             string `json:"kid,omitempty"` // = KeyName by default; after rotation: KeyName-{id}
	Use             string `json:"use,omitempty"` // "sig" | "enc"
	ProjectId       string `json:"projectId,omitempty"`
	StreamId        string `json:"streamId,omitempty"`
	KeyBytes        []byte `json:"keyBytes,omitempty"`        // private key; nil for public-only or external
	PubKeyBytes     []byte `json:"pubKeyBytes,omitempty"`     // public key; nil for external-only
	ReceiverJwksUrl string `json:"receiverJwksUrl,omitempty"` // external JWKS URL

	// Alg names the signature algorithm the key material belongs to, and with
	// it the encoding of KeyBytes/PubKeyBytes. It is the discriminator that
	// lets one key store hold both classical and post-quantum keys for the
	// same issuer:
	//
	//   ""          RSA (the pre-RFC-9964 shape, and what every existing
	//               record decodes as): KeyBytes is PKCS#1 private, PubKeyBytes
	//               PKCS#1 public.
	//   "ES256"     ECDSA on P-256: KeyBytes is the SEC 1 private key,
	//               PubKeyBytes the PKIX public key (PKCS#1 is RSA-only).
	//   "ML-DSA-65" FIPS 204 / RFC 9964: KeyBytes is the 32-byte ML-DSA seed,
	//               PubKeyBytes the 1952-byte public key encoding.
	//
	// Empty rather than "RS256" for the RSA case on purpose — an absent member
	// is how a document written before this field existed decodes, so the zero
	// value has to be the legacy meaning.
	Alg string `json:"alg,omitempty"`

	// SuspendedAt (reversible) and RevokedAt (terminal, once set never cleared)
	// are the lifecycle timestamps. Both zero => active. The material and audit
	// trail are always retained: revoke/suspend never delete the record. See
	// ADR 0028.
	SuspendedAt time.Time `json:"suspendedAt,omitzero"`
	RevokedAt   time.Time `json:"revokedAt,omitzero"`

	// CreatedAt is when the key record was minted. KeyService stamps it before
	// the insert and nothing changes it afterwards; a status transition never
	// touches it. Records written before the field existed decode as the zero
	// time, and NewerThan falls back to id order for them. See ADR 0028.
	CreatedAt time.Time `json:"createdAt,omitzero"`

	// NotBefore and NotAfter bound the period in which a signing key may sign
	// (i2goSignals#318, ADR 0042). A zero bound is open: a record with neither
	// never expires, which is how every record written before the fields
	// existed reads. An uploaded certificate supplies both; a generated key or
	// a certificate-less private key gets NotAfter = creation + lifetime.
	// Validity is derived against a clock on every read (ValidAt, StatusAt),
	// never stored as a status.
	NotBefore time.Time `json:"notBefore,omitzero"`
	NotAfter  time.Time `json:"notAfter,omitzero"`
}

// NewerThan reports whether key is a newer record than other. It is the single
// rule every "newest record for a keyName" choice uses — signing selection, the
// use a rotation carries over, JWKS kid-collision order and each
// FindLatestByKeyName — so they all pick the same record (i2goSignals#316):
//
//   - both carry a CreatedAt: the later one is newer, and equal times fall
//     back to the higher id;
//   - only one carries a CreatedAt: that one is newer;
//   - neither does: the higher id is newer.
//
// Times are compared at millisecond precision, the precision Mongo stores, so
// a record orders the same before and after it round-trips through storage.
// A creation time outranks id order because records minted by v0.11.0 through
// v0.12.0-alpha.19 carry random ids that can sort above any id minted since.
// Any record is newer than a nil other.
func (key *JwkKeyRec) NewerThan(other *JwkKeyRec) bool {
	if other == nil {
		return true
	}
	mine, theirs := key.CreatedAt.Truncate(time.Millisecond), other.CreatedAt.Truncate(time.Millisecond)
	switch {
	case mine.IsZero() != theirs.IsZero():
		return theirs.IsZero()
	case !mine.Equal(theirs):
		return mine.After(theirs)
	default:
		return key.Id > other.Id
	}
}

// IsRevoked reports whether the key has been terminally revoked.
func (key *JwkKeyRec) IsRevoked() bool { return !key.RevokedAt.IsZero() }

// IsActive reports whether the key is neither suspended nor revoked and is thus
// a candidate for signing/issuance.
func (key *JwkKeyRec) IsActive() bool { return key.RevokedAt.IsZero() && key.SuspendedAt.IsZero() }

// Status derives the lifecycle status from the timestamps. Revocation wins over
// suspension; an untouched record is active.
func (key *JwkKeyRec) Status() string {
	return lifecycleStatus(key.SuspendedAt, key.RevokedAt)
}

// lifecycleStatus is the lifecycle status the SuspendedAt/RevokedAt stamps
// derive: revocation wins over suspension; neither stamp is active. It is the
// one rule JwkKeyRec.Status and KeyState.StatusAt share.
func lifecycleStatus(suspendedAt, revokedAt time.Time) string {
	switch {
	case !revokedAt.IsZero():
		return KeyStatusRevoked
	case !suspendedAt.IsZero():
		return KeyStatusSuspended
	default:
		return KeyStatusActive
	}
}

// ValidityPeriod is a signing key's validity period [NotBefore, NotAfter],
// both bounds inclusive as in RFC 5280 (i2goSignals#318, ADR 0042). A zero bound is open, so the zero value is the
// period of a key that never expires. It is the single rule every validity
// question — signing selection, derived status, the stranding guard — asks.
type ValidityPeriod struct {
	NotBefore time.Time
	NotAfter  time.Time
}

// NotYetValidAt reports whether now is before a set NotBefore.
func (p ValidityPeriod) NotYetValidAt(now time.Time) bool {
	return !p.NotBefore.IsZero() && now.Before(p.NotBefore)
}

// ValidAt reports whether now falls inside the period: at or after NotBefore
// and at or before NotAfter, a zero bound being open.
func (p ValidityPeriod) ValidAt(now time.Time) bool {
	return !p.NotYetValidAt(now) && (p.NotAfter.IsZero() || !now.After(p.NotAfter))
}

// statusAt is the status at now of a key with lifecycle status status: an
// active key outside the period is expired or not-yet-valid; any other status
// stands whatever the dates.
func (p ValidityPeriod) statusAt(status string, now time.Time) string {
	switch {
	case status != KeyStatusActive, p.ValidAt(now):
		return status
	case p.NotYetValidAt(now):
		return KeyStatusNotYetValid
	default:
		return KeyStatusExpired
	}
}

// Validity is the record's validity period.
func (key *JwkKeyRec) Validity() ValidityPeriod {
	return ValidityPeriod{NotBefore: key.NotBefore, NotAfter: key.NotAfter}
}

// ValidAt reports whether now falls inside the record's validity period
// (see ValidityPeriod.ValidAt). A record with neither bound is valid at every
// instant (i2goSignals#318).
func (key *JwkKeyRec) ValidAt(now time.Time) bool {
	return key.Validity().ValidAt(now)
}

// StatusAt derives the status at now. The lifecycle status (Status) outranks
// the validity period, so a revoked or suspended key reads as such whatever its
// dates; an otherwise active key outside its period is expired or
// not-yet-valid. A record with no validity period reads exactly as Status().
func (key *JwkKeyRec) StatusAt(now time.Time) string {
	return key.Validity().statusAt(key.Status(), now)
}

// ToKeyState projects the per-kid state carried on a KeySummary as the raw
// stored state: Status is the lifecycle status alone (Status), with the
// validity bounds carried alongside and no clock consulted. The status against
// a clock is derived by the reader — KeyService re-derives it with its own
// clock (KeyState.StatusAt) when it reports a summary — so one clock decides.
func (key *JwkKeyRec) ToKeyState() KeyState {
	return KeyState{
		Kid:         key.Kid,
		Status:      key.Status(),
		SuspendedAt: key.SuspendedAt,
		RevokedAt:   key.RevokedAt,
		NotBefore:   key.NotBefore,
		NotAfter:    key.NotAfter,
	}
}

// ToKeyStateAt projects the per-kid state with the status derived at now.
func (key *JwkKeyRec) ToKeyStateAt(now time.Time) KeyState {
	st := key.ToKeyState()
	st.Status = st.StatusAt(now)
	return st
}

func (key *JwkKeyRec) ToSummary() KeySummary {
	keyType := "jwksurl"
	if key.KeyBytes != nil {
		keyType = "pair"
	} else if key.PubKeyBytes != nil {
		keyType = "public"
	}

	var streamIds []string
	if key.StreamId != "" {
		streamIds = []string{key.StreamId}
	}

	return KeySummary{
		Kids:      []string{key.Kid},
		KeyName:   key.KeyName,
		Use:       key.Use,
		ProjectId: key.ProjectId,
		StreamIds: streamIds,
		Type:      keyType,
		JwksUrl:   key.ReceiverJwksUrl,
		KeyStates: []KeyState{key.ToKeyState()},
	}
}

// KeyState carries the derived lifecycle status and timestamps for a single kid
// so a KeySummary reports per-kid state without a second round trip (ADR 0028).
type KeyState struct {
	Kid         string    `json:"kid"`
	Status      string    `json:"status"` // "active" | "suspended" | "revoked" | "expired" | "not-yet-valid"
	SuspendedAt time.Time `json:"suspendedAt,omitzero"`
	RevokedAt   time.Time `json:"revokedAt,omitzero"`
	NotBefore   time.Time `json:"not_before,omitzero"`
	NotAfter    time.Time `json:"not_after,omitzero"`
}

// Validity is the state's validity period.
func (st KeyState) Validity() ValidityPeriod {
	return ValidityPeriod{NotBefore: st.NotBefore, NotAfter: st.NotAfter}
}

// StatusAt re-derives the state's status at now: revoked and suspended stand,
// otherwise the validity period decides between active, expired and
// not-yet-valid, as JwkKeyRec.StatusAt does.
func (st KeyState) StatusAt(now time.Time) string {
	return st.Validity().statusAt(lifecycleStatus(st.SuspendedAt, st.RevokedAt), now)
}

// KeySummary is used to report a key registry entry and its capabilities without exposing key material
type KeySummary struct {
	Kids      []string   `json:"kid"`
	KeyName   string     `json:"keyName"`
	Use       string     `json:"use,omitempty"` // "sig" | "enc"
	ProjectId string     `json:"projectId,omitempty"`
	StreamIds []string   `json:"streamIds,omitempty"`
	Type      string     `json:"type"` // "pair" | "public" | "external"
	JwksUrl   string     `json:"jwksUrl,omitempty"`
	Rotations int        `json:"rotations,omitempty"`
	KeyStates []KeyState `json:"keyStates,omitempty"` // per-kid lifecycle status + timestamps
}

func (key KeySummary) AdjustBase(baseUrl *url.URL) KeySummary {
	jwksUrl := key.JwksUrl
	if jwksUrl == "" {
		// "/jwks/{keyname}
		if baseUrl != nil {
			path := "/jwks/" + url.QueryEscape(key.KeyName)
			jwksURL, _ := baseUrl.Parse(path)
			if jwksURL != nil {
				key.JwksUrl = jwksURL.String()
			}
		}
	}
	return key
}

// DeliverableEvent represents an event pending delivery.
//
// StreamId is an opaque 24-character hex string. The Mongo adapter stores
// this internally as a bson.ObjectID via a private doc type for backward
// compatibility with existing data.
type DeliverableEvent struct {
	Jti       string    `json:"jti"`
	StreamId  string    `json:"sid"`
	AckJti    string    `json:"ackJti,omitempty" bson:"ackJti,omitempty"`
	CreatedAt time.Time `json:"createdAt,omitzero" bson:"createdAt,omitempty"`
}

// DeliveredEvent represents a delivered/acknowledged event
type DeliveredEvent struct {
	DeliverableEvent
	AckDate  time.Time  `json:"ackDate"`
	ExpireAt *time.Time `json:"expireAt,omitempty"`
}

// KeyPairData holds a private/public key pair. PrivateKey is a crypto.Signer
// so the DAO surface names "a key that can sign" rather than one algorithm;
// the public half stays *rsa.PublicKey because the stored JWK encoding is the
// RSA n/e form.
type KeyPairData struct {
	PrivateKey crypto.Signer
	PublicKey  *rsa.PublicKey
	Kid        string
}
