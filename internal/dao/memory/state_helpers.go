package memory

import "sync"

// CopyFunc is a function type for creating deep copies of values
type CopyFunc[V any] func(*V) *V

// StateManager provides generic state management with mutex protection for in-memory DAOs
type StateManager[K comparable, V any] struct {
	mu       sync.RWMutex
	store    map[K]*V
	copyFunc CopyFunc[V]
}

// NewStateManager creates a new StateManager with a copy function
func NewStateManager[K comparable, V any](copyFunc CopyFunc[V]) *StateManager[K, V] {
	return &StateManager[K, V]{
		store:    make(map[K]*V),
		copyFunc: copyFunc,
	}
}

// Get retrieves a deep copy of a value by key
func (sm *StateManager[K, V]) Get(key K) (*V, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	if val, ok := sm.store[key]; ok {
		if sm.copyFunc != nil {
			return sm.copyFunc(val), true
		}
		return val, true
	}
	return nil, false
}

// Set stores a deep copy of a value
func (sm *StateManager[K, V]) Set(key K, value *V) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sm.copyFunc != nil {
		sm.store[key] = sm.copyFunc(value)
	} else {
		sm.store[key] = value
	}
}

// Delete removes a value by key
func (sm *StateManager[K, V]) Delete(key K) bool {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if _, exists := sm.store[key]; !exists {
		return false
	}
	delete(sm.store, key)
	return true
}

// Exists checks if a key exists
func (sm *StateManager[K, V]) Exists(key K) bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	_, ok := sm.store[key]
	return ok
}

// GetAll returns deep copies of all values
func (sm *StateManager[K, V]) GetAll() map[K]*V {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	result := make(map[K]*V, len(sm.store))
	for k, v := range sm.store {
		if sm.copyFunc != nil {
			result[k] = sm.copyFunc(v)
		} else {
			result[k] = v
		}
	}
	return result
}

// SetAll replaces the entire store
func (sm *StateManager[K, V]) SetAll(state map[K]*V) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.store = state
}

// ForEach iterates over all entries with read lock
func (sm *StateManager[K, V]) ForEach(fn func(key K, value *V) bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	for k, v := range sm.store {
		if !fn(k, v) {
			break
		}
	}
}

// FindFirst finds the first entry matching the predicate
func (sm *StateManager[K, V]) FindFirst(predicate func(*V) bool) (*V, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	for _, v := range sm.store {
		if predicate(v) {
			if sm.copyFunc != nil {
				return sm.copyFunc(v), true
			}
			return v, true
		}
	}
	return nil, false
}

// FindAll finds all entries matching the predicate
func (sm *StateManager[K, V]) FindAll(predicate func(*V) bool) []*V {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	var results []*V
	for _, v := range sm.store {
		if predicate(v) {
			if sm.copyFunc != nil {
				results = append(results, sm.copyFunc(v))
			} else {
				results = append(results, v)
			}
		}
	}
	return results
}

// Count returns the number of entries
func (sm *StateManager[K, V]) Count() int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	return len(sm.store)
}

// Clear removes all entries
func (sm *StateManager[K, V]) Clear() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.store = make(map[K]*V)
}
