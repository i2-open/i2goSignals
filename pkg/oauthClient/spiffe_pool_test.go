package oauthClient

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/i2-open/i2goSignals/pkg/dao/ids"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/i2-open/i2goSignals/pkg/tlsSupport"
)

// fakeSpiffeSource stands in for the workload-API X509Source. It counts SVID
// lookups so a test can prove the TLS config consults the live source on every
// handshake rather than a snapshot taken at client construction.
type fakeSpiffeSource struct {
	svidCalls atomic.Int32
	closed    atomic.Bool
}

func (f *fakeSpiffeSource) GetX509SVID() (*x509svid.SVID, error) {
	f.svidCalls.Add(1)
	return nil, errors.New("fake: no svid")
}

func (f *fakeSpiffeSource) GetX509BundleForTrustDomain(spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	return nil, errors.New("fake: no bundle")
}

func (f *fakeSpiffeSource) Close() error {
	f.closed.Store(true)
	return nil
}

type fakeSourceLog struct {
	mu      sync.Mutex
	sources []*fakeSpiffeSource
}

func (l *fakeSourceLog) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.sources)
}

func (l *fakeSourceLog) get(i int) *fakeSpiffeSource {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.sources[i]
}

// useFakeSpiffeSources swaps the source factory for one that hands out fakes
// and records them; the pool is reset before and after the test.
func useFakeSpiffeSources(t *testing.T) *fakeSourceLog {
	t.Helper()
	t.Setenv(tlsSupport.EnvSpiffeSocket, "unix:///tmp/fake-agent.sock")
	log := &fakeSourceLog{}
	CloseSpiffeClients()
	prev := spiffeSourceFactory
	spiffeSourceFactory = func(context.Context) (spiffeSource, error) {
		log.mu.Lock()
		defer log.mu.Unlock()
		src := &fakeSpiffeSource{}
		log.sources = append(log.sources, src)
		return src, nil
	}
	t.Cleanup(func() {
		CloseSpiffeClients()
		spiffeSourceFactory = prev
	})
	return log
}

func spiffeServer(id string, cfg model.SpiffeConfig) *model.Server {
	oid, _ := bson.ObjectIDFromHex(id)
	return &model.Server{Id: oid, Alias: "peer", Host: "https://peer.example.com", SpiffeConfig: &cfg}
}

func TestSpiffeClientPool_ReusesTransportForSameServer(t *testing.T) {
	sources := useFakeSpiffeSources(t)
	srv := spiffeServer(ids.NewObjectID(), model.SpiffeConfig{TrustDomain: "example.org"})

	c1, close1, err := GetClientForServer(context.Background(), srv)
	require.NoError(t, err)
	close1()
	c2, close2, err := GetClientForServer(context.Background(), srv)
	require.NoError(t, err)
	close2()

	assert.Same(t, c1.Transport, c2.Transport, "same SPIFFE server must reuse its transport")
	assert.Equal(t, 1, sources.count(), "the X509Source must be created once, not per cycle")
	assert.False(t, sources.get(0).closed.Load(), "a caller's close must not tear down the shared source")
}

func TestSpiffeClientPool_ChangedConfigYieldsNewTransport(t *testing.T) {
	sources := useFakeSpiffeSources(t)
	id := ids.NewObjectID()

	c1, _, err := GetClientForServer(context.Background(), spiffeServer(id, model.SpiffeConfig{TrustDomain: "example.org"}))
	require.NoError(t, err)
	c2, _, err := GetClientForServer(context.Background(), spiffeServer(id, model.SpiffeConfig{SpiffeID: "spiffe://example.org/peer"}))
	require.NoError(t, err)

	assert.NotSame(t, c1.Transport, c2.Transport, "a changed SpiffeConfig must yield a new transport")
	assert.Equal(t, 1, sources.count(), "the source is process-wide and survives an authorizer change")
}

func TestSpiffeClientPool_SharesSourceAcrossServers(t *testing.T) {
	sources := useFakeSpiffeSources(t)

	c1, _, err := GetSpiffeClient(context.Background(), spiffeServer(ids.NewObjectID(), model.SpiffeConfig{TrustDomain: "a.org"}))
	require.NoError(t, err)
	c2, _, err := GetSpiffeClient(context.Background(), spiffeServer(ids.NewObjectID(), model.SpiffeConfig{TrustDomain: "b.org"}))
	require.NoError(t, err)

	assert.NotSame(t, c1.Transport, c2.Transport)
	assert.Equal(t, 1, sources.count())
}

func TestSpiffeClientPool_ConsultsLiveSourceOnEachHandshake(t *testing.T) {
	sources := useFakeSpiffeSources(t)
	c, _, err := GetSpiffeClient(context.Background(), spiffeServer(ids.NewObjectID(), model.SpiffeConfig{TrustDomain: "example.org"}))
	require.NoError(t, err)

	tlsCfg := c.Transport.(*http.Transport).TLSClientConfig
	require.NotNil(t, tlsCfg.GetClientCertificate)
	_, _ = tlsCfg.GetClientCertificate(nil)
	_, _ = tlsCfg.GetClientCertificate(nil)

	assert.EqualValues(t, 2, sources.get(0).svidCalls.Load(),
		"each handshake must read the SVID from the long-lived source so rotation takes effect")
}

func TestSpiffeClientPool_EvictDropsServerEntry(t *testing.T) {
	useFakeSpiffeSources(t)
	srv := spiffeServer(ids.NewObjectID(), model.SpiffeConfig{TrustDomain: "example.org"})

	c1, _, err := GetSpiffeClient(context.Background(), srv)
	require.NoError(t, err)
	EvictSpiffeClient(srv.Id.Hex())
	c2, _, err := GetSpiffeClient(context.Background(), srv)
	require.NoError(t, err)

	assert.NotSame(t, c1.Transport, c2.Transport, "an evicted server must get a fresh transport")
}

func TestSpiffeClientPool_CloseReleasesSource(t *testing.T) {
	sources := useFakeSpiffeSources(t)
	srv := spiffeServer(ids.NewObjectID(), model.SpiffeConfig{TrustDomain: "example.org"})

	_, _, err := GetSpiffeClient(context.Background(), srv)
	require.NoError(t, err)
	CloseSpiffeClients()
	require.True(t, sources.get(0).closed.Load(), "shutdown must close the shared source")

	// The pool is usable again after shutdown (tests run several apps per process).
	_, _, err = GetSpiffeClient(context.Background(), srv)
	require.NoError(t, err)
	assert.Equal(t, 2, sources.count())
}

func TestSpiffeClientPool_FailedSourceIsNotCached(t *testing.T) {
	useFakeSpiffeSources(t)
	calls := 0
	spiffeSourceFactory = func(context.Context) (spiffeSource, error) {
		calls++
		if calls == 1 {
			return nil, errors.New("agent down")
		}
		return &fakeSpiffeSource{}, nil
	}
	srv := spiffeServer(ids.NewObjectID(), model.SpiffeConfig{TrustDomain: "example.org"})

	_, _, err := GetSpiffeClient(context.Background(), srv)
	require.Error(t, err)
	_, _, err = GetSpiffeClient(context.Background(), srv)
	require.NoError(t, err, "a failed source creation must be retried on the next call")
}

func TestSpiffeClientPool_ConcurrentResolution(t *testing.T) {
	sources := useFakeSpiffeSources(t)
	srv := spiffeServer(ids.NewObjectID(), model.SpiffeConfig{TrustDomain: "example.org"})

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if i%8 == 7 {
				EvictSpiffeClient(srv.Id.Hex())
			}
			_, closeFn, err := GetSpiffeClient(context.Background(), srv)
			if assert.NoError(t, err) {
				closeFn()
			}
		}(i)
	}
	wg.Wait()
	assert.Equal(t, 1, sources.count())
}
