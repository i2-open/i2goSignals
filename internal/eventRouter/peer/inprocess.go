package peer

import (
	"context"
	"sync"
)

// InProcess is the in-process adapter: every node of a test cluster registers
// its Handler here, and the PeerTransport returned by For calls the target
// node's handler directly. A node that is not registered (never registered,
// or removed with Unregister, which is how a harness stops a node) yields
// ErrPeerUnreachable.
type InProcess struct {
	mu       sync.RWMutex
	handlers map[string]Handler
}

// NewInProcess returns an empty in-process registry.
func NewInProcess() *InProcess {
	return &InProcess{handlers: map[string]Handler{}}
}

// Register makes nodeId reachable through h.
func (p *InProcess) Register(nodeId string, h Handler) {
	p.mu.Lock()
	p.handlers[nodeId] = h
	p.mu.Unlock()
}

// Unregister makes nodeId unreachable.
func (p *InProcess) Unregister(nodeId string) {
	p.mu.Lock()
	delete(p.handlers, nodeId)
	p.mu.Unlock()
}

// For returns the PeerTransport node selfNodeId sends on.
func (p *InProcess) For(selfNodeId string) PeerTransport {
	return &inProcessTransport{reg: p, self: selfNodeId}
}

func (p *InProcess) handler(nodeId string) (Handler, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	h, ok := p.handlers[nodeId]
	return h, ok
}

// peers returns the handlers of every registered node other than self.
func (p *InProcess) peers(self string) []Handler {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]Handler, 0, len(p.handlers))
	for id, h := range p.handlers {
		if id != self {
			out = append(out, h)
		}
	}
	return out
}

type inProcessTransport struct {
	reg  *InProcess
	self string
}

func (t *inProcessTransport) Wake(_ context.Context, ownerNode string, msg WakeMessage) error {
	if ownerNode == "" {
		for _, h := range t.reg.peers(t.self) {
			h.HandleWake(msg)
		}
		return nil
	}
	h, ok := t.reg.handler(ownerNode)
	if !ok {
		return ErrPeerUnreachable
	}
	h.HandleWake(msg)
	return nil
}

func (t *inProcessTransport) Claim(ctx context.Context, ownerNode string, req ClaimRequest) (ClaimResponse, error) {
	h, ok := t.reg.handler(ownerNode)
	if !ok {
		return ClaimResponse{}, ErrPeerUnreachable
	}
	return h.HandleClaim(ctx, req), nil
}
