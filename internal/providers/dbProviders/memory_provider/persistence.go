package memory_provider

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/i2-open/i2goSignals/internal/dao/interfaces"
	"github.com/i2-open/i2goSignals/internal/dao/memory"
	"github.com/i2-open/i2goSignals/pkg/logger"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
)

var persistLog = logger.Sub("MEMORY_PERSIST")

// PersistenceManager handles saving and loading of memory provider state to/from disk
type PersistenceManager struct {
	directory string
	saveRate  int
	stopSave  chan struct{}
	mu        sync.Mutex
	dirty     bool

	// Direct references to the raw memory DAOs whose state we serialize.
	// The provider passes these in instead of a baseProvider to avoid
	// type-asserting through a wrapper-DAO layer (#44).
	streamDAO *memory.StreamDAOMemory
	eventDAO  *memory.EventDAOMemory
	keyDAO    *memory.KeyDAOMemory
	clientDAO *memory.ClientDAOMemory
	serverDAO *memory.ServerDAOMemory
}

// newPersistenceManagerForProvider builds a PersistenceManager bound to the
// raw DAOs that the given MemoryProvider holds. This is the only constructor
// — the WriteHook-coupled NewPersistenceManager(baseProvider) is gone.
func newPersistenceManagerForProvider(directory string, saveRate int, m *MemoryProvider) *PersistenceManager {
	return &PersistenceManager{
		directory: directory,
		saveRate:  saveRate,
		streamDAO: m.rawStreamDAO,
		eventDAO:  m.rawEventDAO,
		keyDAO:    m.rawKeyDAO,
		clientDAO: m.rawClientDAO,
		serverDAO: m.rawServerDAO,
	}
}

// Initialize sets up persistence: creates directory, loads existing state, starts save loop
func (pm *PersistenceManager) Initialize() error {
	if pm.directory == "" {
		return nil
	}

	// Create directory if it doesn't exist
	err := os.MkdirAll(pm.directory, 0755)
	if err != nil {
		persistLog.Error("Failed to create persistence directory, running in memory only", "dir", pm.directory, "error", err)
		pm.directory = ""
		return err
	}

	// Set persist dir on the raw EventDAO (it streams individual SETs to
	// disk on every Insert, separately from the bulk save below).
	if pm.eventDAO != nil {
		pm.eventDAO.SetPersistDir(pm.directory)
	}

	// Load existing state
	pm.LoadState()

	// Start save loop if saveRate > 0
	if pm.saveRate > 0 {
		pm.stopSave = make(chan struct{})
		go pm.saveLoop()
	}

	return nil
}

// Close stops the save loop
func (pm *PersistenceManager) Close() {
	if pm.stopSave != nil {
		close(pm.stopSave)
	}
}

// MarkDirty marks the state as dirty and triggers immediate save if saveRate is 0
func (pm *PersistenceManager) MarkDirty() {
	pm.mu.Lock()
	pm.dirty = true
	pm.mu.Unlock()
	if pm.saveRate == 0 {
		pm.SaveState()
	}
}

// saveLoop periodically saves dirty state to disk
func (pm *PersistenceManager) saveLoop() {
	ticker := time.NewTicker(time.Duration(pm.saveRate) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			pm.mu.Lock()
			isDirty := pm.dirty
			pm.mu.Unlock()
			if isDirty {
				pm.SaveState()
			}
		case <-pm.stopSave:
			return
		}
	}
}

// SaveState saves all DAO state to disk
func (pm *PersistenceManager) SaveState() {
	if pm.directory == "" {
		return
	}

	pm.mu.Lock()
	pm.dirty = false
	pm.mu.Unlock()

	persistLog.Debug("Saving state to disk", "dir", pm.directory)

	if pm.streamDAO != nil {
		pm.saveFile("streams.json", pm.streamDAO.GetState())
	}
	if pm.keyDAO != nil {
		pm.saveFile("keys.json", pm.keyDAO.GetState())
	}
	if pm.clientDAO != nil {
		pm.saveFile("clients.json", pm.clientDAO.GetState())
	}
	if pm.serverDAO != nil {
		pm.saveFile("servers.json", pm.serverDAO.GetState())
	}
	if pm.eventDAO != nil {
		_, pending, delivered := pm.eventDAO.GetState()
		pm.saveFile("pending_events.json", pending)
		pm.saveFile("delivered_events.json", delivered)
		// Individual SETs are streamed to disk in EventDAOMemory.Insert.
	}
}

// saveFile marshals data to JSON and writes to file
func (pm *PersistenceManager) saveFile(filename string, data interface{}) {
	path := filepath.Join(pm.directory, filename)
	bytes, err := json.Marshal(data)
	if err != nil {
		persistLog.Error("Failed to marshal state", "file", filename, "error", err)
		return
	}
	err = os.WriteFile(path, bytes, 0644)
	if err != nil {
		persistLog.Error("Failed to write state file", "file", filename, "error", err)
	}
}

// LoadState loads all DAO state from disk
func (pm *PersistenceManager) LoadState() {
	if pm.directory == "" {
		return
	}

	if pm.streamDAO != nil {
		var streams map[string]*model.StreamStateRecord
		if pm.loadFile("streams.json", &streams) {
			pm.streamDAO.SetState(streams)
		}
	}

	if pm.keyDAO != nil {
		var keys map[string]*interfaces.JwkKeyRec
		if pm.loadFile("keys.json", &keys) {
			pm.keyDAO.SetState(keys)
		}
	}

	if pm.clientDAO != nil {
		var clients map[string]*model.SsfClient
		if pm.loadFile("clients.json", &clients) {
			pm.clientDAO.SetState(clients)
		}
	}

	if pm.serverDAO != nil {
		var servers map[string]*model.Server
		if pm.loadFile("servers.json", &servers) {
			pm.serverDAO.SetState(servers)
		}
	}

	if pm.eventDAO != nil {
		var pending map[string][]interfaces.DeliverableEvent
		var delivered map[string][]interfaces.DeliveredEvent
		pOk := pm.loadFile("pending_events.json", &pending)
		dOk := pm.loadFile("delivered_events.json", &delivered)

		events := make(map[string]*model.AgEventRecord)
		eventFiles, _ := filepath.Glob(filepath.Join(pm.directory, "events", "*.set"))
		for _, file := range eventFiles {
			data, err := os.ReadFile(file)
			if err == nil {
				var rec model.AgEventRecord
				if err := json.Unmarshal(data, &rec); err == nil {
					rec.Original = ""
					events[rec.Jti] = &rec
				}
			}
		}

		pm.eventDAO.SetState(events, pending, delivered)
		_ = pOk || dOk
	}
}

// loadFile reads and unmarshals JSON from file
func (pm *PersistenceManager) loadFile(filename string, target interface{}) bool {
	path := filepath.Join(pm.directory, filename)
	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			persistLog.Error("Failed to read state file", "file", filename, "error", err)
		}
		return false
	}
	err = json.Unmarshal(data, target)
	if err != nil {
		persistLog.Error("Failed to unmarshal state", "file", filename, "error", err)
		return false
	}
	return true
}
