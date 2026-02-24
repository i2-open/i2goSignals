package memory_provider

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/i2-open/i2goSignals/internal/dao/interfaces"
	"github.com/i2-open/i2goSignals/internal/dao/memory"
	"github.com/i2-open/i2goSignals/internal/logger"
	"github.com/i2-open/i2goSignals/internal/model"
	"github.com/i2-open/i2goSignals/internal/providers/dbProviders/common"
)

var persistLog = logger.Sub("MEMORY_PERSIST")

// PersistenceManager handles saving and loading of memory provider state to/from disk
type PersistenceManager struct {
	directory    string
	saveRate     int
	stopSave     chan struct{}
	mu           sync.Mutex
	dirty        bool
	baseProvider *common.BaseProvider
}

// NewPersistenceManager creates a new persistence manager
func NewPersistenceManager(directory string, saveRate int, baseProvider *common.BaseProvider) *PersistenceManager {
	return &PersistenceManager{
		directory:    directory,
		saveRate:     saveRate,
		baseProvider: baseProvider,
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

	// Set persist dir in EventDAO
	if ed, ok := pm.baseProvider.GetEventDAO().(*memory.EventDAOMemory); ok {
		ed.SetPersistDir(pm.directory)
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

	// Save StreamDAO state
	if sd, ok := pm.baseProvider.GetStreamDAO().(*memory.StreamDAOMemory); ok {
		state := sd.GetState()
		pm.saveFile("streams.json", state)
	}

	// Save KeyDAO state
	if kd, ok := pm.baseProvider.GetKeyDAO().(*memory.KeyDAOMemory); ok {
		state := kd.GetState()
		pm.saveFile("keys.json", state)
	}

	// Save ClientDAO state
	if cd, ok := pm.baseProvider.GetClientDAO().(*memory.ClientDAOMemory); ok {
		state := cd.GetState()
		pm.saveFile("clients.json", state)
	}

	// Save ServerDAO state
	if sd, ok := pm.baseProvider.GetServerDAO().(*memory.ServerDAOMemory); ok {
		state := sd.GetState()
		pm.saveFile("servers.json", state)
	}

	// Save EventDAO state (pending and delivered)
	if ed, ok := pm.baseProvider.GetEventDAO().(*memory.EventDAOMemory); ok {
		_, pending, delivered := ed.GetState()
		pm.saveFile("pending_events.json", pending)
		pm.saveFile("delivered_events.json", delivered)
		// Individual events are already saved in Insert
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

	// Load StreamDAO state
	var streams map[string]*model.StreamStateRecord
	if pm.loadFile("streams.json", &streams) {
		if sd, ok := pm.baseProvider.GetStreamDAO().(*memory.StreamDAOMemory); ok {
			sd.SetState(streams)
		}
	}

	// Load KeyDAO state
	var keys map[string][]*interfaces.JwkKeyRec
	if pm.loadFile("keys.json", &keys) {
		if kd, ok := pm.baseProvider.GetKeyDAO().(*memory.KeyDAOMemory); ok {
			kd.SetState(keys)
		}
	}

	// Load ClientDAO state
	var clients map[string]*model.SsfClient
	if pm.loadFile("clients.json", &clients) {
		if cd, ok := pm.baseProvider.GetClientDAO().(*memory.ClientDAOMemory); ok {
			cd.SetState(clients)
		}
	}

	// Load ServerDAO state
	var servers map[string]*model.Server
	if pm.loadFile("servers.json", &servers) {
		if sd, ok := pm.baseProvider.GetServerDAO().(*memory.ServerDAOMemory); ok {
			sd.SetState(servers)
		}
	}

	// Load EventDAO state
	var pending map[string][]interfaces.DeliverableEvent
	var delivered map[string][]interfaces.DeliveredEvent
	pOk := pm.loadFile("pending_events.json", &pending)
	dOk := pm.loadFile("delivered_events.json", &delivered)

	// For individual events, we need to scan the events directory
	events := make(map[string]*model.EventRecord)
	eventFiles, _ := filepath.Glob(filepath.Join(pm.directory, "events", "*.set"))
	for _, file := range eventFiles {
		data, err := os.ReadFile(file)
		if err == nil {
			var rec model.EventRecord
			if err := json.Unmarshal(data, &rec); err == nil {
				// Memory optimization: clear Original if we favor disk
				rec.Original = ""
				events[rec.Jti] = &rec
			}
		}
	}

	if ed, ok := pm.baseProvider.GetEventDAO().(*memory.EventDAOMemory); ok {
		ed.SetState(events, pending, delivered)
	}
	_ = pOk || dOk // use them to avoid unused var
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
