package dbProviders

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"net/url"
	"time"

	"github.com/i2-open/i2goSignals/internal/authUtil"
	"github.com/i2-open/i2goSignals/internal/dao/interfaces"
	"github.com/i2-open/i2goSignals/internal/services"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/MicahParks/keyfunc/v2"
)

type DbProviderInterface interface {
	Name() string
	Check() error
	Close() error

	DeleteKeysByName(keyName string) error
	GetPublicJWKS(keyName string) *json.RawMessage
	GetPrivateKey(keyName string) (*rsa.PrivateKey, error)
	GetAuthValidatorPubKey() *keyfunc.JWKS
	GetAuthIssuer() *authUtil.AuthIssuer
	GetIssuerJwksForReceiver(sid string) *keyfunc.JWKS
	CreateKeyPair(keyName string, use string, projectId string) (*rsa.PrivateKey, error)
	RotateKey(keyName string, projectId string) (*rsa.PrivateKey, string, error)
	ListKeyNames() []string
	ListSummaries() ([]interfaces.KeySummary, error)
	StoreExternalKey(keyName string, kids []string, streamID string, use string, jwksUri string) error

	GetPrivateKeyWithKid(keyName string) (*rsa.PrivateKey, string, error)
	AddKey(keyName string, use string, kid string, privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey, projectId string) error

	RegisterClient(request model.SsfClient, projectId string) *model.RegisterResponse
	CreateStream(request model.StreamConfiguration, authCtx *authUtil.AuthContext) (model.StreamConfiguration, error)
	UpdateStream(streamId string, projectId string, configReq model.StreamConfiguration) (*model.StreamConfiguration, error)
	DeleteStream(streamId string) error
	GetStream(id string) (*model.StreamConfiguration, error)

	GetStreamState(id string) (*model.StreamStateRecord, error)
	UpdateStreamStatus(streamId string, status string, errorMsg string)
	UpdateRemoteAddress(streamId string, addr *model.RemoteIP)
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
	ClearPending(streamId string) error
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

	// GetActiveNodes returns the nodes that have heartbeated within the last 60 seconds.
	GetActiveNodes() ([]model.ClusterNode, error)

	// GetLeaseOwner returns the owner node ID and lease expiration time for a resource.
	GetLeaseOwner(resource string) (ownerNodeId string, leaseUntil time.Time, fencingToken int64, err error)

	// GetNode returns a node by its ID.
	GetNode(nodeId string) (*model.ClusterNode, error)

	SetBaseUrl(u *url.URL)

	CreateServer(ctx context.Context, server *model.Server) error
	GetServer(ctx context.Context, id string) (*model.Server, error)
	GetServerByAlias(ctx context.Context, alias string) (*model.Server, error)
	UpdateServer(ctx context.Context, server *model.Server) error
	DeleteServer(ctx context.Context, id string) error
	ListServers(ctx context.Context) ([]model.Server, error)

	GetTokenService() *services.TokenService
}
