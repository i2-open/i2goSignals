package interfaces

import (
	"context"
	"crypto/rsa"
	"time"

	"github.com/i2-open/i2goSignals/internal/model"
	"go.mongodb.org/mongo-driver/v2/bson"
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
	// Key pair operations
	Insert(ctx context.Context, keyRec *JwkKeyRec) error
	FindByIssuer(ctx context.Context, issuer string) ([]*JwkKeyRec, error)
	FindLatestByIssuer(ctx context.Context, issuer string) (*JwkKeyRec, error)
	DeleteByIssuer(ctx context.Context, issuer string) error
	ListIssuers(ctx context.Context) ([]string, error)

	// Receiver keys
	InsertReceiverKey(ctx context.Context, streamID string, audience string, jwksUri string) error
	FindReceiverKeyByStreamID(ctx context.Context, streamID string) (*JwkKeyRec, error)
}

// ClientDAO handles client registration data access
type ClientDAO interface {
	Insert(ctx context.Context, client *model.SsfClient) error
	FindByID(ctx context.Context, id string) (*model.SsfClient, error)
	FindByProjectID(ctx context.Context, projectID string) ([]*model.SsfClient, error)
	Delete(ctx context.Context, id string) error
}

// JwkKeyRec represents a cryptographic key record
type JwkKeyRec struct {
	Id              bson.ObjectID `json:"id" bson:"_id"`
	Iss             string        `json:"iss,omitempty" bson:"iss"`
	Kid             string        `json:"kid,omitempty" bson:"kid"`
	Aud             string        `json:"aud,omitempty" bson:"aud"`
	ProjectId       string        `bson:"project_id" json:"projectId,omitempty"`
	StreamId        string        `json:"streamId" bson:"stream_id"`
	KeyBytes        []byte        `json:"keyBytes" bson:"key_bytes"`
	PubKeyBytes     []byte        `json:"pubJwks" bson:"pub_jwks"`
	ReceiverJwksUrl string        `json:"receiverJwksUrl" bson:"receiver_jwks_url"`
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
