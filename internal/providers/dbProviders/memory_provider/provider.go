package memory_provider

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/MicahParks/keyfunc"
	"github.com/i2-open/i2goSignals/internal/authUtil"
	"github.com/i2-open/i2goSignals/internal/dao/interfaces"
	"github.com/i2-open/i2goSignals/internal/dao/memory"
	"github.com/i2-open/i2goSignals/internal/logger"
	"github.com/i2-open/i2goSignals/internal/model"
	"github.com/i2-open/i2goSignals/internal/services"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"go.mongodb.org/mongo-driver/v2/bson"
)

const CDbName = "goSignalsMem"
const CSubjectFmt = "opaque"
const CDefIssuer = "DEFAULT"
const CEnvIssuer = "I2SIG_ISSUER"
const CEnvDbName = "I2SIG_DBNAME"
const CEnvTokenIssuer = "I2SIG_TOKEN_ISSUER"
const CDefTokenIssuer = "DEFAULT"

const CEnvMemDir = "MEM_DIRECTORY"
const CEnvMemSaveRate = "MEM_SAVE_RATE"
const CDefMemSaveRate = 30

var pLog = logger.Sub("MEMORY_DB")

// MemoryProvider provides an in-memory implementation using DAOs and services
type MemoryProvider struct {
	DbUrl  string
	DbName string
	dbInit bool

	// DAOs
	streamDAO interfaces.StreamDAO
	eventDAO  interfaces.EventDAO
	keyDAO    interfaces.KeyDAO
	clientDAO interfaces.ClientDAO

	// Services
	keyService    *services.KeyService
	streamService *services.StreamService
	eventService  *services.EventService
	clientService *services.ClientService

	DefaultIssuer string
	TokenIssuer   string

	// Persistence
	memDirectory string
	saveRate     int
	stopSave     chan struct{}
	mu           sync.Mutex
	dirty        bool
}

func (m *MemoryProvider) Name() string {
	return m.DbName
}

func (m *MemoryProvider) initialize() {
	pLog.Info("Initializing new in-memory database", "dbName", m.DbName)

	// Initialize DAOs
	m.streamDAO = memory.NewStreamDAO()
	m.eventDAO = memory.NewEventDAO()
	m.keyDAO = memory.NewKeyDAO()
	m.clientDAO = memory.NewClientDAO()

	// Initialize Services
	m.keyService = services.NewKeyService(m.keyDAO, m.TokenIssuer)
	m.streamService = services.NewStreamService(m.streamDAO, m.keyService, m.DefaultIssuer)
	m.eventService = services.NewEventService(m.eventDAO)
	m.clientService = services.NewClientService(m.clientDAO, m.keyService)

	// Initialize token keys
	ctx := context.Background()
	err := m.keyService.InitializeTokenKey(ctx, m.DefaultIssuer)
	if err != nil {
		pLog.Error("Error initializing token key", "error", err)
	}

	m.dbInit = true
}

func (m *MemoryProvider) Check() error {
	// Mock provider is always available
	return nil
}

func (m *MemoryProvider) ResetDb(initialize bool) error {
	// Create new DAOs to reset all data
	m.streamDAO = memory.NewStreamDAO()
	m.eventDAO = memory.NewEventDAO()
	m.keyDAO = memory.NewKeyDAO()
	m.clientDAO = memory.NewClientDAO()

	if initialize {
		// Re-initialize services with new DAOs
		m.keyService = services.NewKeyService(m.keyDAO, m.TokenIssuer)
		m.streamService = services.NewStreamService(m.streamDAO, m.keyService, m.DefaultIssuer)
		m.eventService = services.NewEventService(m.eventDAO)
		m.clientService = services.NewClientService(m.clientDAO, m.keyService)

		ctx := context.Background()
		err := m.keyService.InitializeTokenKey(ctx, m.DefaultIssuer)
		if err != nil {
			pLog.Error("Error reinitializing token key", "error", err)
		}
	}

	m.markDirty()

	return nil
}

// Open creates and initializes a new MemoryProvider
func Open(mongoUrl string, dbName string) (*MemoryProvider, error) {
	// Check if this is a memory URL
	if !strings.HasPrefix(mongoUrl, "memorydb:") && mongoUrl != "" {
		return nil, fmt.Errorf("memory provider only supports 'memorydb:' URL prefix, got: %s", mongoUrl)
	}

	defaultIssuer, issDefined := os.LookupEnv(CEnvIssuer)
	if !issDefined {
		defaultIssuer = CDefIssuer
	}

	if dbName == "" {
		dbEnvName, dbDefined := os.LookupEnv(CEnvDbName)
		if !dbDefined {
			dbName = CDbName
		} else {
			dbName = dbEnvName
		}
	}

	tknIssuer, tknDefined := os.LookupEnv(CEnvTokenIssuer)
	if !tknDefined {
		tknIssuer = CDefTokenIssuer
	}

	if mongoUrl == "" {
		mongoUrl = "memorydb://localhost"
		pLog.Info("Defaulting Memory Database URL", "url", mongoUrl)
	}

	memDir, _ := os.LookupEnv(CEnvMemDir)
	if memDir == "" {
		memDir = filepath.Join("config", dbName)
	}

	saveRate := CDefMemSaveRate
	if rateStr, ok := os.LookupEnv(CEnvMemSaveRate); ok {
		if r, err := strconv.Atoi(rateStr); err == nil {
			saveRate = r
		}
	}

	m := &MemoryProvider{
		DbName:        dbName,
		DbUrl:         mongoUrl,
		DefaultIssuer: defaultIssuer,
		TokenIssuer:   tknIssuer,
		memDirectory:  memDir,
		saveRate:      saveRate,
	}

	err := m.Check()
	if err != nil {
		return nil, err
	}

	m.initialize()
	m.initializePersistence()

	pLog.Info("Created new memory database", "dbName", dbName)
	if m.memDirectory != "" {
		pLog.Info("Persistence ENABLED", "directory", m.memDirectory, "saveRate", m.saveRate)
	} else {
		pLog.Warn("****************************************************************")
		pLog.Warn("* WARNING: The server is running with an IN-MEMORY database.   *")
		pLog.Warn("* This is for development and testing purposes only.           *")
		pLog.Warn("* Data will NOT be persisted across restarts.                  *")
		pLog.Warn("* The server is running as a SINGLE NODE.                      *")
		pLog.Warn("****************************************************************")
	}

	return m, nil
}

func (m *MemoryProvider) Close() error {
	if m.stopSave != nil {
		close(m.stopSave)
	}
	return nil
}

// Provider Interface Implementation - delegating to services

func (m *MemoryProvider) DeleteIssuer(issuer string) error {
	err := m.keyService.DeleteIssuer(context.Background(), issuer)
	if err == nil {
		m.markDirty()
	}
	return err
}

func (m *MemoryProvider) GetPublicTransmitterJWKS(issuer string) *json.RawMessage {
	return m.keyService.GetPublicTransmitterJWKS(context.Background(), issuer)
}

func (m *MemoryProvider) GetIssuerPrivateKey(issuer string) (*rsa.PrivateKey, error) {
	return m.keyService.GetIssuerPrivateKey(context.Background(), issuer)
}

func (m *MemoryProvider) GetAuthValidatorPubKey() *keyfunc.JWKS {
	return m.keyService.GetAuthValidatorPubKey()
}

func (m *MemoryProvider) GetAuthIssuer() *authUtil.AuthIssuer {
	return m.keyService.GetAuthIssuer()
}

func (m *MemoryProvider) GetIssuerJwksForReceiver(sid string) *keyfunc.JWKS {
	return m.streamService.GetIssuerJwksForReceiver(context.Background(), sid)
}

func (m *MemoryProvider) CreateIssuerJwkKeyPair(issuer string, projectId string) (*rsa.PrivateKey, error) {
	key, err := m.keyService.CreateIssuerJwkKeyPair(context.Background(), issuer, projectId)
	if err == nil {
		m.markDirty()
	}
	return key, err
}

func (m *MemoryProvider) RotateIssuerKey(issuer string, projectId string) (*rsa.PrivateKey, string, error) {
	key, kid, err := m.keyService.RotateIssuerKey(context.Background(), issuer, projectId)
	if err == nil {
		m.markDirty()
	}
	return key, kid, err
}

func (m *MemoryProvider) GetIssuerKeyNames() []string {
	names, _ := m.keyService.GetIssuerKeyNames(context.Background())
	return names
}

func (m *MemoryProvider) GetIssuerPrivateKeyWithKid(issuer string) (*rsa.PrivateKey, string, error) {
	return m.keyService.GetIssuerPrivateKeyWithKid(context.Background(), issuer)
}

func (m *MemoryProvider) AddIssuerKey(issuer string, kid string, privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey, projectId string) error {
	err := m.keyService.AddIssuerKey(context.Background(), issuer, kid, privateKey, publicKey, projectId)
	if err == nil {
		m.markDirty()
	}
	return err
}

func (m *MemoryProvider) RegisterClient(request model.SsfClient, projectId string) *model.RegisterResponse {
	resp := m.clientService.RegisterClient(context.Background(), request, projectId)
	if resp != nil {
		m.markDirty()
	}
	return resp
}

func (m *MemoryProvider) CreateStream(request model.StreamConfiguration, projectId string) (model.StreamConfiguration, error) {
	res, err := m.streamService.CreateStream(context.Background(), request, projectId)
	if err == nil {
		m.markDirty()
	}
	return res, err
}

func (m *MemoryProvider) UpdateStream(streamId string, projectId string, configReq model.StreamConfiguration) (*model.StreamConfiguration, error) {
	res, err := m.streamService.UpdateStream(context.Background(), streamId, projectId, configReq)
	if err == nil {
		m.markDirty()
	}
	return res, err
}

func (m *MemoryProvider) DeleteStream(streamId string) error {
	err := m.streamService.DeleteStream(context.Background(), streamId)
	if err == nil {
		m.markDirty()
	}
	return err
}

func (m *MemoryProvider) GetStream(id string) (*model.StreamConfiguration, error) {
	return m.streamService.GetStream(context.Background(), id)
}

func (m *MemoryProvider) GetStreamState(id string) (*model.StreamStateRecord, error) {
	return m.streamService.GetStreamState(context.Background(), id)
}

func (m *MemoryProvider) UpdateStreamStatus(streamId string, status string, errorMsg string) {
	m.streamService.UpdateStreamStatus(context.Background(), streamId, status, errorMsg)
	m.markDirty()
}

func (m *MemoryProvider) GetStatus(streamId string) (*model.StreamStatus, error) {
	return m.streamService.GetStatus(context.Background(), streamId)
}

func (m *MemoryProvider) ListStreams() []model.StreamConfiguration {
	return m.streamService.ListStreams(context.Background())
}

func (m *MemoryProvider) GetStateMap() map[string]model.StreamStateRecord {
	return m.streamService.GetStateMap(context.Background())
}

func (m *MemoryProvider) GetEventIds(streamId string, params model.PollParameters) ([]string, bool) {
	return m.eventService.GetEventIds(context.Background(), streamId, params)
}

func (m *MemoryProvider) GetEvent(jti string) *goSet.SecurityEventToken {
	return m.eventService.GetEvent(context.Background(), jti)
}

func (m *MemoryProvider) GetEvents(jtis []string) []*goSet.SecurityEventToken {
	return m.eventService.GetEvents(context.Background(), jtis)
}

func (m *MemoryProvider) GetEventRecord(jti string) *model.EventRecord {
	return m.eventService.GetEventRecord(context.Background(), jti)
}

func (m *MemoryProvider) AckEvent(jtiString string, streamId string, fencingToken int64) error {
	err := m.eventService.AckEvent(context.Background(), jtiString, streamId, fencingToken)
	if err == nil {
		m.markDirty()
	}
	return err
}

func (m *MemoryProvider) AddEvent(event *goSet.SecurityEventToken, sid string, raw string) (*model.EventRecord, error) {
	res, err := m.eventService.AddEvent(context.Background(), event, sid, raw)
	if err == nil {
		m.markDirty()
	}
	return res, err
}

func (m *MemoryProvider) AddEventToStream(jti string, streamId bson.ObjectID) error {
	err := m.eventService.AddEventToStream(context.Background(), jti, streamId)
	if err == nil {
		m.markDirty()
	}
	return err
}

func (m *MemoryProvider) WatchPending(ctx context.Context, callback func(jti string, streamId bson.ObjectID)) {
	m.eventService.WatchPending(ctx, callback)
}

func (m *MemoryProvider) ResetEventStream(streamId string, jti string, resetDate *time.Time, isStreamEvent func(*model.EventRecord) bool) error {
	err := m.eventService.ResetEventStream(context.Background(), streamId, jti, resetDate, isStreamEvent)
	if err == nil {
		m.markDirty()
	}
	return err
}

func (m *MemoryProvider) TryAcquireOrRenewLease(_ string, _ string, _ time.Duration) (bool, int64, error) {
	return true, 1, nil
}

func (m *MemoryProvider) ReleaseLeaseIfOwned(_ string, _ string) error {
	return nil
}

func (m *MemoryProvider) RegisterNode(_ model.ClusterNode) error {
	return nil
}

func (m *MemoryProvider) GetActiveNodeCount() (int64, error) {
	return 1, nil
}

func (m *MemoryProvider) SetBaseUrl(u *url.URL) {
	m.streamService.SetBaseUrl(u)
}

func (m *MemoryProvider) markDirty() {
	m.mu.Lock()
	m.dirty = true
	m.mu.Unlock()
	if m.saveRate == 0 {
		m.saveStateToDisk()
	}
}

func (m *MemoryProvider) initializePersistence() {
	if m.memDirectory == "" {
		return
	}

	// Create directory if it doesn't exist
	err := os.MkdirAll(m.memDirectory, 0755)
	if err != nil {
		pLog.Error("Failed to create persistence directory, running in memory only", "dir", m.memDirectory, "error", err)
		m.memDirectory = ""
		return
	}

	// Set persist dir in EventDAO
	if ed, ok := m.eventDAO.(*memory.EventDAOMemory); ok {
		ed.SetPersistDir(m.memDirectory)
	}

	// Load existing state
	m.loadStateFromDisk()

	// Start save loop if saveRate > 0
	if m.saveRate > 0 {
		m.stopSave = make(chan struct{})
		go m.saveLoop()
	}
}

func (m *MemoryProvider) saveLoop() {
	ticker := time.NewTicker(time.Duration(m.saveRate) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.mu.Lock()
			isDirty := m.dirty
			m.mu.Unlock()
			if isDirty {
				m.saveStateToDisk()
			}
		case <-m.stopSave:
			return
		}
	}
}

func (m *MemoryProvider) saveStateToDisk() {
	if m.memDirectory == "" {
		return
	}

	m.mu.Lock()
	m.dirty = false
	m.mu.Unlock()

	pLog.Debug("Saving state to disk", "dir", m.memDirectory)

	// Save StreamDAO state
	if sd, ok := m.streamDAO.(*memory.StreamDAOMemory); ok {
		state := sd.GetState()
		m.saveFile("streams.json", state)
	}

	// Save KeyDAO state
	if kd, ok := m.keyDAO.(*memory.KeyDAOMemory); ok {
		state := kd.GetState()
		m.saveFile("keys.json", state)
	}

	// Save ClientDAO state
	if cd, ok := m.clientDAO.(*memory.ClientDAOMemory); ok {
		state := cd.GetState()
		m.saveFile("clients.json", state)
	}

	// Save EventDAO state (pending and delivered)
	if ed, ok := m.eventDAO.(*memory.EventDAOMemory); ok {
		_, pending, delivered := ed.GetState()
		m.saveFile("pending_events.json", pending)
		m.saveFile("delivered_events.json", delivered)
		// Individual events are already saved in Insert
	}
}

func (m *MemoryProvider) saveFile(filename string, data interface{}) {
	path := filepath.Join(m.memDirectory, filename)
	bytes, err := json.Marshal(data)
	if err != nil {
		pLog.Error("Failed to marshal state", "file", filename, "error", err)
		return
	}
	err = os.WriteFile(path, bytes, 0644)
	if err != nil {
		pLog.Error("Failed to write state file", "file", filename, "error", err)
	}
}

func (m *MemoryProvider) loadStateFromDisk() {
	if m.memDirectory == "" {
		return
	}

	// Load StreamDAO state
	var streams map[string]*model.StreamStateRecord
	if m.loadFile("streams.json", &streams) {
		if sd, ok := m.streamDAO.(*memory.StreamDAOMemory); ok {
			sd.SetState(streams)
		}
	}

	// Load KeyDAO state
	var keys map[string][]*interfaces.JwkKeyRec
	if m.loadFile("keys.json", &keys) {
		if kd, ok := m.keyDAO.(*memory.KeyDAOMemory); ok {
			kd.SetState(keys)
		}
	}

	// Load ClientDAO state
	var clients map[string]*model.SsfClient
	if m.loadFile("clients.json", &clients) {
		if cd, ok := m.clientDAO.(*memory.ClientDAOMemory); ok {
			cd.SetState(clients)
		}
	}

	// Load EventDAO state
	var pending map[string][]interfaces.DeliverableEvent
	var delivered map[string][]interfaces.DeliveredEvent
	pOk := m.loadFile("pending_events.json", &pending)
	dOk := m.loadFile("delivered_events.json", &delivered)

	// For individual events, we need to scan the events directory
	events := make(map[string]*model.EventRecord)
	eventFiles, _ := filepath.Glob(filepath.Join(m.memDirectory, "events", "*.set"))
	for _, file := range eventFiles {
		data, err := os.ReadFile(file)
		if err == nil {
			var rec model.EventRecord
			if err := json.Unmarshal(data, &rec); err == nil {
				// Memory optimization: clear Original if we are favor disk
				// Wait, if we just loaded it, we have it in memory now.
				// But Insert clears it.
				// Let's keep it cleared in memory if we are favor disk.
				rec.Original = ""
				events[rec.Jti] = &rec
			}
		}
	}

	if ed, ok := m.eventDAO.(*memory.EventDAOMemory); ok {
		ed.SetState(events, pending, delivered)
	}
	_ = pOk || dOk // use them to avoid unused var
}

func (m *MemoryProvider) loadFile(filename string, target interface{}) bool {
	path := filepath.Join(m.memDirectory, filename)
	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			pLog.Error("Failed to read state file", "file", filename, "error", err)
		}
		return false
	}
	err = json.Unmarshal(data, target)
	if err != nil {
		pLog.Error("Failed to unmarshal state", "file", filename, "error", err)
		return false
	}
	return true
}
