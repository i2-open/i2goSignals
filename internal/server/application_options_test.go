package server

import (
	"testing"
	"time"

	"github.com/i2-open/i2goSignals/internal/eventRouter"
	"github.com/i2-open/i2goSignals/internal/eventRouter/peer"
	"github.com/stretchr/testify/assert"
)

// With no options the application keeps production wiring: no injected
// PeerTransport (so the router builds the HTTP adapter), no router hook and
// no dialer tuning. Each option sets only its own seam.
func TestAppOptions_DefaultsAndEachSeam(t *testing.T) {
	var o appOptions
	assert.Nil(t, o.peerTransport("node-a"), "production wiring: no injected transport")
	assert.Nil(t, o.routerHook)
	assert.Nil(t, o.sstpDialerTuning)

	inproc := peer.NewInProcess()
	var hooked string
	for _, opt := range []AppOption{
		WithPeerTransport(func(nodeID string) peer.PeerTransport { return inproc.For(nodeID) }),
		WithRouterHook(func(nodeID string, _ eventRouter.EventRouter) { hooked = nodeID }),
		WithSstpDialerTuning(func(cfg *SstpDialerConfig) { cfg.LeaseDuration = 3 * time.Second }),
	} {
		opt(&o)
	}
	assert.NotNil(t, o.peerTransport("node-a"))
	o.routerHook("node-a", nil)
	assert.Equal(t, "node-a", hooked)
	var cfg SstpDialerConfig
	o.sstpDialerTuning(&cfg)
	assert.Equal(t, 3*time.Second, cfg.LeaseDuration)
}
