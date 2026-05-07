package memory_provider

import (
	"net/url"

	"github.com/i2-open/i2goSignals/internal/providers/storage"
)

// MemoryStorage is a narrow lifecycle wrapper exposing only the surface
// described by storage.Storage.
type MemoryStorage struct {
	p *MemoryProvider
}

func NewMemoryStorage(p *MemoryProvider) *MemoryStorage {
	return &MemoryStorage{p: p}
}

var _ storage.Storage = (*MemoryStorage)(nil)

func (s *MemoryStorage) Name() string                  { return s.p.Name() }
func (s *MemoryStorage) Check() error                  { return s.p.Check() }
func (s *MemoryStorage) Close() error                  { return s.p.Close() }
func (s *MemoryStorage) ResetDb(initialize bool) error { return s.p.ResetDb(initialize) }
func (s *MemoryStorage) SetBaseUrl(u *url.URL)         { s.p.SetBaseUrl(u) }
