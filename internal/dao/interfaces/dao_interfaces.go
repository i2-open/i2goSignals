package interfaces

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
    Insert(ctx context.Context, record *model.AgEventRecord) error
    FindByJTI(ctx context.Context, jti string) (*model.AgEventRecord, error)
    FindByJTIs(ctx context.Context, jtis []string) ([]*model.AgEventRecord, error)
    FindByTimeRange(ctx context.Context, from time.Time, to *time.Time, filter func(*model.AgEventRecord) bool) ([]*model.AgEventRecord, error)

    // Pending events
    AddPending(ctx context.Context, jti string, streamID string) error
    GetPendingForStream(ctx context.Context, streamID string, limit int32) (jtis []string, total int64, err error)
    RemovePending(ctx context.Context, jti string, streamID string) (*DeliverableEvent, error)
    ClearPendingForStream(ctx context.Context, streamID string) (int64, error)

    // Delivered events
    MarkDelivered(ctx context.Context, event *DeliverableEvent, ackDate time.Time) error

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
// Id is an opaque 24-character hex string (see internal/dao/ids). The Mongo
// adapter stores this internally as a bson.ObjectID via a private doc type
// for backward compatibility with existing data; callers must not assume
// the Mongo serialization format.
type JwkKeyRec struct {
    Id              string `json:"id"`
    KeyName         string `json:"keyName"`         // primary identifier; replaces Iss/Aud
    Kid             string `json:"kid,omitempty"`   // = KeyName by default; after rotation: KeyName-{id}
    Use             string `json:"use,omitempty"`   // "sig" | "enc"
    ProjectId       string `json:"projectId,omitempty"`
    StreamId        string `json:"streamId,omitempty"`
    KeyBytes        []byte `json:"keyBytes,omitempty"`        // private key (PKCS1); nil for public-only or external
    PubKeyBytes     []byte `json:"pubKeyBytes,omitempty"`     // public key (PKCS1); nil for external-only
    ReceiverJwksUrl string `json:"receiverJwksUrl,omitempty"` // external JWKS URL
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
    }
}

// KeySummary is used to report a key registry entry and its capabilities without exposing key material
type KeySummary struct {
    Kids      []string `json:"kid"`
    KeyName   string   `json:"keyName"`
    Use       string   `json:"use,omitempty"` // "sig" | "enc"
    ProjectId string   `json:"projectId,omitempty"`
    StreamIds []string `json:"streamIds,omitempty"`
    Type      string   `json:"type"` // "pair" | "public" | "external"
    JwksUrl   string   `json:"jwksUrl,omitempty"`
    Rotations int      `json:"rotations,omitempty"`
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
