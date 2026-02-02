package dbProviders

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"net/url"
	"time"

	"github.com/i2-open/i2goSignals/internal/authUtil"
	"github.com/i2-open/i2goSignals/internal/model"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/MicahParks/keyfunc"
)

type DbProviderInterface interface {
	Name() string
	Check() error
	Close() error

	DeleteIssuer(issuer string) error
	GetPublicTransmitterJWKS(issuer string) *json.RawMessage
	GetIssuerPrivateKey(issuer string) (*rsa.PrivateKey, error)
	GetAuthValidatorPubKey() *keyfunc.JWKS
	GetAuthIssuer() *authUtil.AuthIssuer
	GetIssuerJwksForReceiver(sid string) *keyfunc.JWKS
	CreateIssuerJwkKeyPair(issuer string, projectId string) (*rsa.PrivateKey, error)
	RotateIssuerKey(issuer string, projectId string) (*rsa.PrivateKey, string, error)
	GetIssuerKeyNames() []string
	GetIssuerPrivateKeyWithKid(issuer string) (*rsa.PrivateKey, string, error)
	AddIssuerKey(issuer string, kid string, privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey, projectId string) error

	RegisterClient(request model.SsfClient, projectId string) *model.RegisterResponse
	CreateStream(request model.StreamConfiguration, projectId string) (model.StreamConfiguration, error)
	UpdateStream(streamId string, projectId string, configReq model.StreamConfiguration) (*model.StreamConfiguration, error)
	DeleteStream(streamId string) error
	GetStream(id string) (*model.StreamConfiguration, error)

	GetStreamState(id string) (*model.StreamStateRecord, error)
	UpdateStreamStatus(streamId string, status string, errorMsg string)
	GetStatus(streamId string) (*model.StreamStatus, error)
	ListStreams() []model.StreamConfiguration
	GetStateMap() map[string]model.StreamStateRecord

	GetEventIds(streamId string, params model.PollParameters) ([]string, bool)
	GetEvent(jti string) *goSet.SecurityEventToken
	GetEvents(jtis []string) []*goSet.SecurityEventToken
	GetEventRecord(jti string) *model.EventRecord
	AckEvent(jtiString string, streamId string, fencingToken int64) error
	AddEvent(event *goSet.SecurityEventToken, sid string, raw string) (eventRecord *model.EventRecord, err error)
	AddEventToStream(jti string, streamId bson.ObjectID) error
	WatchPending(ctx context.Context, callback func(jti string, streamId bson.ObjectID))
	ResetEventStream(streamId string, jti string, resetDate *time.Time, isStreamEvent func(*model.EventRecord) bool) error

	ResetDb(initialize bool) error

	// --- Cluster coordination (Mongo-backed leases) ---
	// TryAcquireOrRenewLease atomically acquires the lease if it is expired/unowned, or renews it if already owned by nodeId.
	// Returns (acquired=true, fencingToken) only when this node is (or remains) owner.
	TryAcquireOrRenewLease(resource string, nodeId string, leaseDuration time.Duration) (acquired bool, fencingToken int64, err error)

	// ReleaseLeaseIfOwned clears/shortens the lease if (and only if) it's owned by nodeId.
	ReleaseLeaseIfOwned(resource string, nodeId string) error

	// RegisterNode updates the node registry with heartbeats and metadata.
	RegisterNode(node model.ClusterNode) error

	// GetActiveNodeCount returns the number of nodes that have heartbeated within the last 60 seconds.
	GetActiveNodeCount() (int64, error)
	SetBaseUrl(u *url.URL)
}
