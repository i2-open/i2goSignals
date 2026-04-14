package interfaces

import (
	"context"
	"crypto/rsa"
	"errors"
	"net/url"
	"time"

	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"go.mongodb.org/mongo-driver/v2/bson"
)

var (
	ErrNotFound    = errors.New("not found")
	ErrKeyNotFound = errors.New("key not found")
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
	FindReceiverStreams(ctx context.Context) ([]model.StreamStateRecord, error)

	// Status updates
	UpdateStatus(ctx context.Context, id string, status string, errorMsg string) error
}

// EventDAO handles event data access
type EventDAO interface {
	// Event storage
	Insert(ctx context.Context, record *model.EventRecord) error
	FindByJTI(ctx context.Context, jti string) (*model.EventRecord, error)
	FindByJTIs(ctx context.Context, jtis []string) ([]*model.EventRecord, error)
	FindByTimeRange(ctx context.Context, from time.Time, to *time.Time, filter func(*model.EventRecord) bool) ([]*model.EventRecord, error)

	// Pending events
	AddPending(ctx context.Context, jti string, streamID bson.ObjectID) error
	GetPendingForStream(ctx context.Context, streamID string, limit int32) (jtis []string, total int64, err error)
	RemovePending(ctx context.Context, jti string, streamID string) (*DeliverableEvent, error)
	ClearPendingForStream(ctx context.Context, streamID string) (int64, error)

	// Delivered events
	MarkDelivered(ctx context.Context, event *DeliverableEvent, ackDate time.Time) error

	// Change streams
	WatchPending(ctx context.Context, callback func(jti string, streamID bson.ObjectID)) error
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
	DeleteExpired(ctx context.Context) error
	FindByProjectID(ctx context.Context, projectID string) ([]*model.TokenRecord, error)
	FindByClientID(ctx context.Context, clientID string) ([]*model.TokenRecord, error)
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

// JwkKeyRec represents a cryptographic key record
type JwkKeyRec struct {
	Id              bson.ObjectID `json:"id" bson:"_id"`
	KeyName         string        `json:"keyName" bson:"key_name"`  // primary identifier; replaces Iss/Aud
	Kid             string        `json:"kid,omitempty" bson:"kid"` // = KeyName by default; after rotation: KeyName-{objectid}
	Use             string        `json:"use,omitempty" bson:"use"` // "sig" | "enc"
	ProjectId       string        `json:"projectId,omitempty" bson:"project_id"`
	StreamId        string        `json:"streamId,omitempty" bson:"stream_id"`
	KeyBytes        []byte        `json:"keyBytes,omitempty" bson:"key_bytes"`                // private key (PKCS1); nil for public-only or external
	PubKeyBytes     []byte        `json:"pubKeyBytes,omitempty" bson:"pub_jwks"`              // public key (PKCS1); nil for external-only
	ReceiverJwksUrl string        `json:"receiverJwksUrl,omitempty" bson:"receiver_jwks_url"` // external JWKS URL
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

// DeliverableEvent represents an event pending delivery
type DeliverableEvent struct {
	Jti      string        `json:"jti" bson:"jti"`
	StreamId bson.ObjectID `json:"sid" bson:"sid"`
}

// DeliveredEvent represents a delivered/acknowledged event
type DeliveredEvent struct {
	DeliverableEvent
	AckDate time.Time `json:"ackDate" bson:"ackDate"`
}

// KeyPairData holds a private/public key pair
type KeyPairData struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
	Kid        string
}
