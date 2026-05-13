// Package delivery is the push-side delivery seam of the event router.
//
// PushDelivery is one Module, one method: given a stream config, an event record, a
// signing key, and a kid, sign-or-forward the SET and push it to the receiver; return
// the goSetPush.Classification, the captured peer address (when available), and the
// (possibly-rotated) key and kid the caller should reuse on the next attempt.
//
// Scope discipline: one delivery attempt only. The HTTP adapter owns the RFC8935 §2.4
// jws_signature_failed rotate-and-retry sub-policy because that is a delivery-side
// concern (a single peer rejecting a single SET token); recovery cadence, lease
// heartbeats, backoff, backfill, and cluster wake-ups all stay in the router.
package delivery

import (
	"context"
	"crypto/rsa"

	"github.com/i2-open/i2goSignals/pkg/goSetPush"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// PushDelivery is the seam consumed by the router's push loop. One attempt per Deliver
// call. Two adapters land in the same package: HTTPAdapter (production) and MemoryAdapter
// (tests).
type PushDelivery interface {
	Deliver(ctx context.Context, req PushRequest) PushOutcome
}

// PushRequest is the input to a single delivery attempt. Stream and Event carry the
// routing context; Key and Kid carry the signing material for publish/import modes
// (ignored when the stream is in RouteModeForward, where Event.Original is forwarded
// verbatim).
type PushRequest struct {
	Stream *model.StreamStateRecord
	Event  *model.AgEventRecord
	Key    *rsa.PrivateKey
	Kid    string
}

// PushOutcome is the result of a single delivery attempt. Classification reports the
// receiver's verdict per goSetPush; RemoteAddress carries the resolved peer ("ip:port")
// when the TCP connection got far enough for httptrace.GotConn to fire (empty otherwise).
// Key and Kid may differ from the request's when the HTTP adapter rotated the signing
// material in response to jws_signature_failed — the caller reuses them on subsequent
// attempts.
type PushOutcome struct {
	Classification goSetPush.Classification
	RemoteAddress  string
	Key            *rsa.PrivateKey
	Kid            string
}

// KeyReloader is the seam the HTTP adapter uses on the jws_signature_failed retry path.
// The router implements this against its issuer-key cache (invalidate + reload from
// KeyService). MemoryAdapter does not need it.
type KeyReloader interface {
	// InvalidateAndReload flushes any cached private key for issuer and fetches a fresh
	// one from the underlying provider. Returns (nil, "") when reload is unavailable;
	// the HTTP adapter then skips the retry.
	InvalidateAndReload(streamID, issuer string) (*rsa.PrivateKey, string)
}
