package dao

import (
	"context"
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
	UpdateStatus(ctx context.Context, id string, status string, errorMsg string) error

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
	FindByJTI(ctx context.Context, jti string) (*model.EventRecord, error)
	FindByJTIs(ctx context.Context, jtis []string) ([]*model.EventRecord, error)
	FindByTimeRange(ctx context.Context, from time.Time, to *time.Time, filter func(*model.EventRecord) bool) ([]*model.EventRecord, error)

	// Pending events
	AddPending(ctx context.Context, jti string, streamID string) error
	GetPendingForStream(ctx context.Context, streamID string, limit int32) (jtis []string, total int64, err error)
	RemovePending(ctx context.Context, jti string, streamID string) (*DeliverableEvent, error)
	ClearPendingForStream(ctx context.Context, streamID string) (int64, error)

	// Delivered events
	MarkDelivered(ctx context.Context, event *DeliverableEvent, ackDate time.Time) error

	// --- Ack-anchored retention purge + occupancy sampling (ADR 0055) ---

	// ListDeliveredForStream returns streamID's delivered (post-ack,
	// not-yet-purged) events, each carrying its AckDate. It is the enumerator the
	// per-(stream, JTI) retention clock reads to decide expiry. Order is
	// unspecified.
	ListDeliveredForStream(ctx context.Context, streamID string) ([]DeliveredEvent, error)

	// RemoveDelivered drops streamID's delivered entry for jti when its
	// retention clock fires. It does NOT touch the global event body; body
	// deletion is refcount-gated via DeleteBodyIfUnreferenced. Removing an entry
	// that does not exist is not an error.
	RemoveDelivered(ctx context.Context, jti string, streamID string) error

	// DeleteBodyIfUnreferenced deletes the global event body for jti ONLY when no
	// stream still references it in pending or delivered (refcount 0 — the body
	// survives to the maximum effective window across all referencing streams).
	// Because pending is never purged, a still-pending JTI always keeps its body.
	// It reports whether the body was deleted; a still-referenced or absent body
	// is not an error.
	DeleteBodyIfUnreferenced(ctx context.Context, jti string) (deleted bool, err error)

	// CountRetainedForStream returns the number of post-ack-retained (delivered,
	// not-yet-purged) JTIs for streamID — the daily occupancy sampler's per-stream
	// retained_count (pending excluded).
	CountRetainedForStream(ctx context.Context, streamID string) (int64, error)

	// Change streams
	WatchPending(ctx context.Context, callback func(jti string, streamID string)) error
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
)

type JwkKeyRec struct {
	Id              string `json:"id"`
	KeyName         string `json:"keyName"`       // primary identifier; replaces Iss/Aud
	Kid             string `json:"kid,omitempty"` // = KeyName by default; after rotation: KeyName-{id}
	Use             string `json:"use,omitempty"` // "sig" | "enc"
	ProjectId       string `json:"projectId,omitempty"`
	StreamId        string `json:"streamId,omitempty"`
	KeyBytes        []byte `json:"keyBytes,omitempty"`        // private key (PKCS1); nil for public-only or external
	PubKeyBytes     []byte `json:"pubKeyBytes,omitempty"`     // public key (PKCS1); nil for external-only
	ReceiverJwksUrl string `json:"receiverJwksUrl,omitempty"` // external JWKS URL

	// SuspendedAt (reversible) and RevokedAt (terminal, once set never cleared)
	// are the lifecycle timestamps. Both zero => active. The material and audit
	// trail are always retained: revoke/suspend never delete the record. See
	// ADR 0028.
	SuspendedAt time.Time `json:"suspendedAt,omitzero"`
	RevokedAt   time.Time `json:"revokedAt,omitzero"`
}

// IsRevoked reports whether the key has been terminally revoked.
func (key *JwkKeyRec) IsRevoked() bool { return !key.RevokedAt.IsZero() }

// IsActive reports whether the key is neither suspended nor revoked and is thus
// a candidate for signing/issuance.
func (key *JwkKeyRec) IsActive() bool { return key.RevokedAt.IsZero() && key.SuspendedAt.IsZero() }

// Status derives the lifecycle status from the timestamps. Revocation wins over
// suspension; an untouched record is active.
func (key *JwkKeyRec) Status() string {
	if !key.RevokedAt.IsZero() {
		return KeyStatusRevoked
	}
	if !key.SuspendedAt.IsZero() {
		return KeyStatusSuspended
	}
	return KeyStatusActive
}

// ToKeyState projects the per-kid lifecycle state carried on a KeySummary.
func (key *JwkKeyRec) ToKeyState() KeyState {
	return KeyState{
		Kid:         key.Kid,
		Status:      key.Status(),
		SuspendedAt: key.SuspendedAt,
		RevokedAt:   key.RevokedAt,
	}
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
	Status      string    `json:"status"` // "active" | "suspended" | "revoked"
	SuspendedAt time.Time `json:"suspendedAt,omitzero"`
	RevokedAt   time.Time `json:"revokedAt,omitzero"`
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
	Jti      string `json:"jti"`
	StreamId string `json:"sid"`
}

// DeliveredEvent represents a delivered/acknowledged event
type DeliveredEvent struct {
	DeliverableEvent
	AckDate time.Time `json:"ackDate"`
}

// KeyPairData holds a private/public key pair
type KeyPairData struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
	Kid        string
}
