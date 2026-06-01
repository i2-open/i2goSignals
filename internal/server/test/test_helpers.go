package test

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/i2-open/i2goSignals/internal/authUtil"
	daoInterfaces "github.com/i2-open/i2goSignals/internal/dao/interfaces"
	"github.com/i2-open/i2goSignals/internal/providers/dbProviders"
	"github.com/i2-open/i2goSignals/internal/services"
	"github.com/i2-open/i2goSignals/pkg/authSupport"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	ssef "github.com/i2-open/i2goSignals/internal/server"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/i2-open/i2goSignals/pkg/tlsSupport"
	"go.mongodb.org/mongo-driver/v2/bson"
)

var TestDbUrl = "mongodb://root:dockTest@mongo1:30001,mongo2:30002,mongo3:30003/?retryWrites=true&replicaSet=dbrs&readPreference=primary&serverSelectionTimeoutMS=5000&connectTimeoutMS=10000&authSource=admin&authMechanism=SCRAM-SHA-256"

var testLog = log.New(os.Stdout, "TEST: ", log.Ldate|log.Ltime)

// ssfInstance holds a running test server and direct references to the
// services backing it. Tests should call services through these fields rather
// than via a single god-interface (the legacy provider façade was removed in
// PRD #39 PR4 phase D).
type ssfInstance struct {
	ts              *httptest.Server
	host            string
	client          *http.Client
	persistence     *dbProviders.Persistence
	stream          model.StreamConfiguration
	app             *ssef.SignalsApplication
	streamToken     string
	streamMgmtToken string
	iatToken        string
	projectId       string
	startTime       *time.Time
}

// streamSvc/keySvc/eventSvc/serverSvc are convenience accessors so test code
// can write `instance.streamSvc().GetStreamState(ctx, id)` without piping
// through the persistence struct each time.
func (instance *ssfInstance) streamSvc() *services.StreamService { return instance.persistence.StreamService }
func (instance *ssfInstance) keySvc() *services.KeyService       { return instance.persistence.KeyService }
func (instance *ssfInstance) eventSvc() *services.EventService   { return instance.persistence.EventService }
func (instance *ssfInstance) serverSvc() *services.ServerService { return instance.persistence.ServerService }
func (instance *ssfInstance) clientSvc() *services.ClientService { return instance.persistence.ClientService }
func (instance *ssfInstance) tokenSvc() *services.TokenService   { return instance.persistence.TokenService }

// The methods below preserve the call shape that test files used to reach
// through `instance.provider.X` so the per-test diff is mechanical. Each
// forwards to the appropriate service with a fresh context.

func (instance *ssfInstance) Name() string {
	if instance.persistence != nil && instance.persistence.Storage != nil {
		return instance.persistence.Storage.Name()
	}
	return ""
}

func (instance *ssfInstance) GetAuthIssuer() *authUtil.AuthIssuer {
	return instance.keySvc().GetAuthIssuer()
}

func (instance *ssfInstance) CreateStream(request model.StreamConfiguration, authCtx *authUtil.AuthContext) (model.StreamConfiguration, error) {
	ctx := context.WithValue(context.Background(), authUtil.AuthContextKey, authCtx)
	projectId := ""
	if authCtx != nil {
		projectId = authCtx.ProjectId
	}
	return instance.streamSvc().CreateStream(ctx, model.StreamStateRecord{StreamConfiguration: request}, projectId, nil)
}

func (instance *ssfInstance) GetStream(id string) (*model.StreamConfiguration, error) {
	return instance.streamSvc().GetStream(context.Background(), id)
}

func (instance *ssfInstance) GetStreamState(id string) (*model.StreamStateRecord, error) {
	return instance.streamSvc().GetStreamState(context.Background(), id)
}

func (instance *ssfInstance) UpdateStreamStatus(streamId string, status string, errorMsg string) {
	instance.streamSvc().UpdateStreamStatus(context.Background(), streamId, status, errorMsg)
}

func (instance *ssfInstance) DeleteStream(streamId string) error {
	return instance.streamSvc().DeleteStream(context.Background(), streamId)
}

func (instance *ssfInstance) GetEventIds(streamId string, params model.PollParameters) ([]string, bool) {
	return instance.eventSvc().GetEventIds(context.Background(), streamId, params)
}

func (instance *ssfInstance) GetEvent(jti string) *goSet.SecurityEventToken {
	return instance.eventSvc().GetEvent(context.Background(), jti)
}

func (instance *ssfInstance) GetEventRecord(jti string) *model.AgEventRecord {
	return instance.eventSvc().GetEventRecord(context.Background(), jti)
}

func (instance *ssfInstance) ClearPending(streamId string) error {
	_, err := instance.eventSvc().ClearPendingForStream(context.Background(), streamId)
	return err
}

func (instance *ssfInstance) ResetEventStream(streamId, jti string, resetDate *time.Time, isStreamEvent func(*model.AgEventRecord) bool) error {
	return instance.eventSvc().ResetEventStream(context.Background(), streamId, jti, resetDate, isStreamEvent)
}

func (instance *ssfInstance) GetPrivateKey(keyName string) (*rsa.PrivateKey, error) {
	return instance.keySvc().GetPrivateKey(context.Background(), keyName)
}

func (instance *ssfInstance) GetPublicJWKS(keyName string) *json.RawMessage {
	return instance.keySvc().GetPublicJWKS(context.Background(), keyName)
}

func (instance *ssfInstance) ListSummaries() ([]daoInterfaces.KeySummary, error) {
	return instance.keySvc().ListSummaries(context.Background())
}


func (instance *ssfInstance) GetPollUrl(stream model.StreamConfiguration) string {
	if stream.Delivery == nil || stream.Delivery.PollTransmitMethod == nil {
		return ""
	}
	endpoint := stream.Delivery.PollTransmitMethod.EndpointUrl
	if strings.HasPrefix(endpoint, "http") {
		return endpoint
	}
	return instance.ts.URL + endpoint
}

func (instance *ssfInstance) GetPushUrl(stream model.StreamConfiguration) string {
	if stream.Delivery == nil || stream.Delivery.PushReceiveMethod == nil {
		return ""
	}
	endpoint := stream.Delivery.PushReceiveMethod.EndpointUrl
	if strings.HasPrefix(endpoint, "http") {
		return endpoint
	}
	return instance.ts.URL + endpoint
}

func createServer(t *testing.T, dbName string, resetDb bool) (*ssfInstance, error) {
	t.Helper()
	var err error
	var instance ssfInstance

	dbUrl := "memorydb:"
	if os.Getenv("TEST_MONGO_CLUSTER") != "" {
		// MONGO_URL is set by CI (single-node mongo:7); local devs running the
		// docker-compose cluster fall back to TestDbUrl.
		if u := os.Getenv("MONGO_URL"); u != "" {
			dbUrl = u
		} else {
			dbUrl = TestDbUrl
		}
		// Route the watchtokens resume file into a per-test tempdir so
		// mongo_provider.Open does not leak resources/mongo_token.json.
		t.Setenv("I2SIG_STORE_MONGO_RESUME_FILE", filepath.Join(t.TempDir(), "mongo_token.json"))
	} else {
		// When using memory provider, use a temporary directory for persistence
		// to avoid leaving files in the source tree.
		t.Setenv("I2SIG_STORE_MEM_DIRECTORY", t.TempDir())
	}
	persistence, err := dbProviders.OpenPersistence(dbUrl, dbName)
	if err != nil {
		t.Error("Mongo client error: " + err.Error())
		return nil, err
	}

	if resetDb && persistence.Storage != nil {
		_ = persistence.Storage.ResetDb(true)
		// The in-memory adapter rebuilds its services on reset; refresh the
		// cached service references so NewApplication sees the live ones.
		persistence.Refresh()
	}

	// Build application and wrap with httptest.Server
	app := ssef.NewApplication(persistence, "")
	ts := httptest.NewServer(app.Handler)
	instance.ts = ts
	instance.app = app
	u, _ := url.Parse(ts.URL)
	instance.host = u.Host
	// Set BaseUrl on app for any logic that depends on it
	baseUrl, _ := url.Parse(ts.URL + "/")
	app.SetBaseUrl(baseUrl)
	instance.client = ts.Client()
	tlsSupport.CheckCaInstalled(instance.client)
	instance.persistence = persistence
	nowTime := time.Now()
	instance.startTime = &nowTime

	authIssuer := persistence.KeyService.GetAuthIssuer()
	instance.iatToken, err = authIssuer.IssueProjectIat(nil)
	if err != nil {
		t.Logf("Error creating iat: %s\n", err.Error())
	}
	eat, err := authIssuer.ParseAuthToken(instance.iatToken)
	if err != nil {
		t.Fatalf("Error parsing iat: %s\n", err.Error())
	}

	clientToken, err := authIssuer.IssueStreamClientToken(model.SsfClient{
		Id:            bson.NewObjectID(),
		ProjectIds:    []string{eat.ProjectId},
		AllowedScopes: []string{authSupport.ScopeStreamAdmin, authSupport.ScopeStreamMgmt},
		Email:         "test@test.com",
		Description:   "server test",
	}, eat.ProjectId, true, eat.ID)
	instance.streamMgmtToken = clientToken

	instance.projectId = eat.ProjectId

	return &instance, nil
}
