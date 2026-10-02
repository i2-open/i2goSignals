package services

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/i2-open/i2goSignals/pkg/dao/memory"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// recordSpiffeEvictions replaces the pool-eviction hook with a recorder for
// the duration of the test (#326).
func recordSpiffeEvictions(t *testing.T) func() []string {
	t.Helper()
	var mu sync.Mutex
	var evicted []string
	prev := evictSpiffeClient
	evictSpiffeClient = func(server *model.Server) {
		mu.Lock()
		defer mu.Unlock()
		if server != nil {
			evicted = append(evicted, server.Id.Hex())
		}
	}
	t.Cleanup(func() { evictSpiffeClient = prev })
	return func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), evicted...)
	}
}

func seedSpiffeServer(t *testing.T, svc *ServerService, cfg *model.SpiffeConfig) *model.Server {
	t.Helper()
	token := "tok"
	srv := &model.Server{Alias: "peer", Host: "https://peer.example.com", ClientToken: &token, SpiffeConfig: cfg}
	require.NoError(t, svc.serverDAO.Create(context.Background(), srv))
	return srv
}

func TestServerService_UpdateServer_ChangedSpiffeConfigEvictsPooledClient(t *testing.T) {
	evicted := recordSpiffeEvictions(t)
	svc := NewServerService(memory.NewServerDAO())
	srv := seedSpiffeServer(t, svc, &model.SpiffeConfig{TrustDomain: "example.org"})

	token := "tok"
	updated := &model.Server{Id: srv.Id, Alias: "peer", Host: srv.Host, ClientToken: &token,
		SpiffeConfig: &model.SpiffeConfig{SpiffeID: "spiffe://example.org/peer"}}
	require.NoError(t, svc.UpdateServer(context.Background(), updated))

	assert.Equal(t, []string{srv.Id.Hex()}, evicted())
}

func TestServerService_UpdateServer_UnchangedSpiffeConfigKeepsPooledClient(t *testing.T) {
	evicted := recordSpiffeEvictions(t)
	svc := NewServerService(memory.NewServerDAO())
	srv := seedSpiffeServer(t, svc, &model.SpiffeConfig{TrustDomain: "example.org"})

	token := "tok"
	updated := &model.Server{Id: srv.Id, Alias: "peer", Host: "https://moved.example.com", ClientToken: &token,
		SpiffeConfig: &model.SpiffeConfig{TrustDomain: "example.org"}}
	require.NoError(t, svc.UpdateServer(context.Background(), updated))

	assert.Empty(t, evicted())
}

func TestServerService_DeleteServer_EvictsPooledClient(t *testing.T) {
	evicted := recordSpiffeEvictions(t)
	svc := NewServerService(memory.NewServerDAO())
	srv := seedSpiffeServer(t, svc, &model.SpiffeConfig{TrustDomain: "example.org"})

	require.NoError(t, svc.DeleteServer(context.Background(), srv.Id.Hex()))

	assert.Equal(t, []string{srv.Id.Hex()}, evicted())
}
