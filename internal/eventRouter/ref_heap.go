package eventRouter

import (
	"time"

	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// queuedRef is one held reference. It records when this node first handed
// the SET out, so the acknowledgement can report queue time and
// acknowledgement time (the per-reference timing community #352 needs).
type queuedRef struct {
	ref       interfaces.PendingRef // Jti, AckJti, EnqueuedAt
	handedOut time.Time             // first hand-out by this node; zero until then
	served    string                // the JWS served, kept while in flight
	// copyRec is the outbound copy stored with the acknowledgement when this
	// node signed and served the SET itself (nil for a forwarded SET).
	copyRec *model.EventRecord
	idx     int // position in the enqueue-time heap
}

// refHeap is a min-heap of held references by EnqueuedAt.
type refHeap []*queuedRef

func (h refHeap) Len() int { return len(h) }
func (h refHeap) Less(i, j int) bool {
	return h[i].ref.EnqueuedAt.Before(h[j].ref.EnqueuedAt)
}
func (h refHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].idx = i
	h[j].idx = j
}
func (h *refHeap) Push(x any) {
	qr := x.(*queuedRef)
	qr.idx = len(*h)
	*h = append(*h, qr)
}
func (h *refHeap) Pop() any {
	old := *h
	n := len(old)
	qr := old[n-1]
	old[n-1] = nil
	*h = old[:n-1]
	qr.idx = -1
	return qr
}
