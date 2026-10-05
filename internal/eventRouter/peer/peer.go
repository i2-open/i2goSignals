// Package peer is the seam for inter-node calls inside one community cluster
// (planning #112, community #358). A PeerTransport carries two calls: Wake, a
// fire-and-forget hint that a stream has work, and Claim, the one
// request/response call, which asks the lease owner of a stream to apply
// acknowledgements and claim the next references.
//
// A wake is advisory. Losing or truncating one is harmless: the owner finds
// the references at its next pending read (the periodic sweep), so
// correctness never depends on inter-node messaging.
//
// Two adapters implement the interface: HTTP (production, NewHTTP) and
// in-process (tests, NewInProcess). The package is internal to community
// (ADR 0049).
package peer

import (
	"context"
	"errors"

	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
)

// MaxWakeJtis caps the reference lists a wake carries. A union of more
// references is sent with the lists omitted, which the receiver treats as a
// reload.
const MaxWakeJtis = 256

// Wake modes, which are also the "mode" component of the cluster token.
const (
	ModePush       = "push"
	ModePoll       = "poll"
	ModeSstpClient = "sstp-client"
	ModeSstpServer = "sstp-server"
)

// WakeMessage is the body of a wake. Jtis, AckJtis and EnqueuedAt are
// index-aligned; when they are absent, or not of one length, the wake means
// "reload pending for the stream".
type WakeMessage struct {
	Sid        string   `json:"sid"`
	Mode       string   `json:"mode"` // "push" | "poll" | "sstp-client" | "sstp-server"
	Reason     string   `json:"reason,omitempty"`
	Jtis       []string `json:"jtis,omitempty"`       // inbound JTIs, ascending, at most MaxWakeJtis
	AckJtis    []string `json:"ackJtis,omitempty"`    // index-aligned with Jtis
	EnqueuedAt []int64  `json:"enqueuedAt,omitempty"` // Unix milliseconds, index-aligned with Jtis
}

// ClaimRequest asks the lease owner of a poll-transmitter or SSTP-acceptor
// stream to apply acknowledgements and claim the next references.
type ClaimRequest struct {
	Sid               string   `json:"sid"`                  // target (tx) stream id
	Mode              string   `json:"mode"`                 // "poll" | "sstp-server"
	MaxEvents         int32    `json:"maxEvents"`            // references to claim; 0 claims none
	WaitMs            int64    `json:"waitMs"`               // longest wait for a first reference
	ReturnImmediately bool     `json:"returnImmediately"`    // true: no wait, WaitMs ignored
	AckJtis           []string `json:"ackJtis,omitempty"`    // acknowledgement JTIs as received
	SetErrJtis        []string `json:"setErrJtis,omitempty"` // rejected JTIs to clear, as received
	ClientId          string   `json:"clientId"`             // node id of the caller
}

// ClaimResponse is the owner's answer to a ClaimRequest.
type ClaimResponse struct {
	Refs          []interfaces.PendingRef // claimed, ascending inbound JTI
	MoreAvailable bool
	NotOwner      bool // the callee does not hold the stream's lease; nothing was done
}

// ErrPeerUnreachable is returned when the target node cannot be reached.
var ErrPeerUnreachable = errors.New("peer: node unreachable")

// PeerTransport carries the inter-node calls.
type PeerTransport interface {
	// Wake delivers msg to ownerNode. An empty ownerNode means every active
	// peer other than this node.
	Wake(ctx context.Context, ownerNode string, msg WakeMessage) error
	// Claim runs req on ownerNode and returns its answer. It is the one
	// request/response peer call. ownerNode is never empty.
	Claim(ctx context.Context, ownerNode string, req ClaimRequest) (ClaimResponse, error)
}

// WakeHandler receives a wake.
type WakeHandler interface {
	HandleWake(msg WakeMessage)
}

// ClaimHandler answers a claim.
type ClaimHandler interface {
	HandleClaim(ctx context.Context, req ClaimRequest) ClaimResponse
}

// Handler is the receiving side of a PeerTransport; the event router
// implements it.
type Handler interface {
	WakeHandler
	ClaimHandler
}

// ValidClaimMode reports whether mode may be claimed.
func ValidClaimMode(mode string) bool {
	return mode == ModePoll || mode == ModeSstpServer
}
