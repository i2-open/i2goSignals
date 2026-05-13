package delivery

import (
	"context"
	"sync"
)

// MemoryAdapter is the in-memory PushDelivery used by tests. It returns a scripted
// PushOutcome — either a single Outcome on every call, or a slice consumed in order
// (the last entry repeats after exhaustion). The adapter is goroutine-safe.
//
// Use NewMemoryAdapter for the single-outcome case; NewMemoryScript for a sequence.
type MemoryAdapter struct {
	mu       sync.Mutex
	outcomes []PushOutcome
	calls    int
}

// NewMemoryAdapter returns an adapter that yields outcome on every Deliver call.
func NewMemoryAdapter(outcome PushOutcome) *MemoryAdapter {
	return &MemoryAdapter{outcomes: []PushOutcome{outcome}}
}

// NewMemoryScript returns an adapter that yields each entry of outcomes in order.
// After the script is exhausted, the final entry repeats.
func NewMemoryScript(outcomes ...PushOutcome) *MemoryAdapter {
	cp := make([]PushOutcome, len(outcomes))
	copy(cp, outcomes)
	return &MemoryAdapter{outcomes: cp}
}

// Deliver implements PushDelivery by returning the next scripted outcome. The
// request's Key/Kid carry through to the outcome unless the scripted entry sets
// its own — letting tests assert "router reuses the seam's rotated key" without
// having to populate Key on every scripted entry.
func (m *MemoryAdapter) Deliver(_ context.Context, req PushRequest) PushOutcome {
	m.mu.Lock()
	defer m.mu.Unlock()
	idx := m.calls
	if idx >= len(m.outcomes) {
		idx = len(m.outcomes) - 1
	}
	m.calls++
	out := m.outcomes[idx]
	if out.Key == nil && out.Kid == "" {
		out.Key = req.Key
		out.Kid = req.Kid
	}
	return out
}

// Calls returns the number of Deliver invocations observed so far.
func (m *MemoryAdapter) Calls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls
}
