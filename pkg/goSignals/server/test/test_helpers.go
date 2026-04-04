package test

import (
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/i2-open/i2goSignals/internal/providers/dbProviders"
	"github.com/i2-open/i2goSignals/pkg/authSupport"
	ssef "github.com/i2-open/i2goSignals/pkg/goSignals/server"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/i2-open/i2goSignals/pkg/tlsSupport"
	"go.mongodb.org/mongo-driver/v2/bson"
)

var TestDbUrl = "mongodb://root:dockTest@mongo1:30001,mongo2:30002,mongo3:30003/?retryWrites=true&replicaSet=dbrs&readPreference=primary&serverSelectionTimeoutMS=5000&connectTimeoutMS=10000&authSource=admin&authMechanism=SCRAM-SHA-256"

var testLog = log.New(os.Stdout, "TEST: ", log.Ldate|log.Ltime)

type ssfInstance struct {
	ts              *httptest.Server
	host            string
	client          *http.Client
	provider        dbProviders.DbProviderInterface
	stream          model.StreamConfiguration
	app             *ssef.SignalsApplication
	streamToken     string
	streamMgmtToken string
	iatToken        string
	projectId       string
	startTime       *time.Time
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
		dbUrl = TestDbUrl
	} else {
		// When using memory provider, use a temporary directory for persistence
		// to avoid leaving files in the source tree.
		t.Setenv("MEM_DIRECTORY", t.TempDir())
	}
	// mongo, err := mongo_provider.Open(TestDbUrl, dbName)
	mongo, err := dbProviders.OpenProvider(dbUrl, dbName)
	if err != nil {
		t.Error("Mongo client error: " + err.Error())
		return nil, err
	}

	if resetDb {
		_ = mongo.ResetDb(true)
	}

	// Build application and wrap with httptest.Server
	app := ssef.NewApplication(mongo, "")
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
	instance.provider = mongo
	nowTime := time.Now()
	instance.startTime = &nowTime

	instance.iatToken, err = instance.provider.GetAuthIssuer().IssueProjectIat(nil)
	if err != nil {
		t.Logf("Error creating iat: %s\n", err.Error())
	}
	eat, err := instance.provider.GetAuthIssuer().ParseAuthToken(instance.iatToken)
	if err != nil {
		t.Logf("Error parsing iat: %s\n", err.Error())
	}

	clientToken, err := instance.provider.GetAuthIssuer().IssueStreamClientToken(model.SsfClient{
		Id:            bson.NewObjectID(),
		ProjectIds:    []string{eat.ProjectId},
		AllowedScopes: []string{authSupport.ScopeStreamAdmin, authSupport.ScopeStreamMgmt},
		Email:         "test@test.com",
		Description:   "server test",
	}, eat.ProjectId, true)
	instance.streamMgmtToken = clientToken

	instance.projectId = eat.ProjectId

	return &instance, nil
}

// TestSuiteCleanup provides a simple pattern for managing test cleanup operations
type TestSuiteCleanup struct {
	mu       sync.Mutex
	cleanups []func()
}

// NewTestSuiteCleanup creates a new cleanup manager
func NewTestSuiteCleanup() *TestSuiteCleanup {
	return &TestSuiteCleanup{
		cleanups: make([]func(), 0),
	}
}

// AddCleanup registers a cleanup function to be called during teardown
func (tc *TestSuiteCleanup) AddCleanup(fn func()) {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	tc.cleanups = append(tc.cleanups, fn)
}

// RunCleanups executes all registered cleanup functions in reverse order (LIFO)
func (tc *TestSuiteCleanup) RunCleanups() {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	// Execute in reverse order
	for i := len(tc.cleanups) - 1; i >= 0; i-- {
		tc.cleanups[i]()
	}
	tc.cleanups = nil
}

// AssertionHelper provides common assertion patterns for SSF tests
type AssertionHelper struct{}

// NewAssertionHelper creates a new assertion helper
func NewAssertionHelper() *AssertionHelper {
	return &AssertionHelper{}
}
