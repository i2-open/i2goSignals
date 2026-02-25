package test

import (
	"sync"
)

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

// Common test utility functions can be added here
// For example: URL builders, token generators, stream configuration builders, etc.
