package delivery

import (
	"context"
	"fmt"
	"net/http/httptrace"
	"net/url"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/goSetPush"
	"github.com/i2-open/i2goSignals/pkg/services"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// HTTPAdapter is the production PushDelivery. It signs (or forwards) the SET,
// pushes once via goSetPush.PushSET, classifies the receiver's response, and on
// RFC8935 jws_signature_failed flushes the cached signing key, reloads, and
// retries exactly once. Successful connections capture the resolved peer
// address via httptrace and update the stream's persisted RemoteAddress.
//
// streamService may be nil — in that case the peer-address capture is
// reported in the outcome but not persisted (tests). keyReloader may be nil —
// in that case the jws_signature_failed retry is skipped.
//
// Deliver is called concurrently for one stream (the router's push worker pool
// shares one *StreamStateRecord), so the compare-and-persist of RemoteAddress
// runs under a per-stream mutex (issue #346). The lock lives in the adapter,
// not the router's batch loop, so it holds however deliveries are scheduled.
type HTTPAdapter struct {
	addressStore remoteAddressStore
	keyReloader  KeyReloader

	// addrLocks maps stream id -> *sync.Mutex guarding that stream's
	// RemoteAddress read, persist and in-memory write.
	addrLocks sync.Map
}

// remoteAddressStore is the one StreamService method the adapter needs;
// *services.StreamService satisfies it.
type remoteAddressStore interface {
	UpdateRemoteAddress(ctx context.Context, streamID string, addr *model.RemoteIP)
}

// NewHTTPAdapter wires the adapter for production.
func NewHTTPAdapter(streamService *services.StreamService, keyReloader KeyReloader) *HTTPAdapter {
	a := &HTTPAdapter{keyReloader: keyReloader}
	if streamService != nil {
		a.addressStore = streamService
	}
	return a
}

// SetKeyReloader supplies the KeyReloader after construction. Used by the
// composition root to break the chicken-and-egg between the adapter (which
// needs a KeyReloader) and the router (which implements KeyReloader but
// is constructed after the adapter, since it consumes the adapter).
func (a *HTTPAdapter) SetKeyReloader(r KeyReloader) {
	a.keyReloader = r
}

// Deliver signs-or-forwards the SET and pushes it. See package docs for scope. A SET
// that cannot be signed is not sent: the outcome carries SignErr.
func (a *HTTPAdapter) Deliver(ctx context.Context, req PushRequest) PushOutcome {
	out := a.attempt(ctx, req)
	if out.SignErr != nil {
		return out
	}

	if a.shouldRotateAndRetry(req, out.Classification) {
		newKey, newKid := a.keyReloader.InvalidateAndReload(
			req.Stream.StreamConfiguration.Id,
			req.Stream.StreamConfiguration.Iss,
			req.Stream.StreamConfiguration.SigningAlg,
		)
		if newKey != nil {
			retryReq := req
			retryReq.Key = newKey
			retryReq.Kid = newKid
			out = a.attempt(ctx, retryReq)
			out.Key = newKey
			out.Kid = newKid
			return out
		}
	}

	out.Key = req.Key
	out.Kid = req.Kid
	return out
}

func (a *HTTPAdapter) shouldRotateAndRetry(req PushRequest, cls goSetPush.Classification) bool {
	if a.keyReloader == nil {
		return false
	}
	if cls.Class != goSetPush.ClassRFC8935Error {
		return false
	}
	if cls.RFC8935ErrCode != goSetPush.ErrJwsSignatureFailed {
		return false
	}
	return req.Stream.GetRouteMode() != model.RouteModeForward
}

// attempt performs a single sign-or-forward + push + classify cycle.
func (a *HTTPAdapter) attempt(ctx context.Context, req PushRequest) PushOutcome {
	cfg := req.Stream.StreamConfiguration
	pushCfg := cfg.Delivery.PushTransmitMethod

	tokenString, err := a.tokenString(req)
	if err != nil {
		return PushOutcome{SignErr: err, Key: req.Key, Kid: req.Kid}
	}

	var capturedAddr string
	trace := &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			capturedAddr = info.Conn.RemoteAddr().String()
		},
	}
	traceCtx := httptrace.WithClientTrace(ctx, trace)

	result := goSetPush.PushSET(traceCtx, tokenString, goSetPush.TransmitterConfig{
		EndpointURL:        pushCfg.EndpointUrl,
		Authorization:      pushCfg.AuthorizationHeader,
		InsecureSkipVerify: cfg.TxTLSSkipVerify,
		// Business-stream TLS floor (#322): http:// receivers are refused inside
		// PushSET unless the stream carries the tx_allow_plaintext opt-out.
		AllowPlaintext: cfg.TxAllowPlaintext,
	})

	cls := goSetPush.ClassifyResult(result)
	a.persistRemoteAddress(ctx, req.Stream, pushCfg.EndpointUrl, capturedAddr)

	return PushOutcome{
		Classification: cls,
		RemoteAddress:  capturedAddr,
	}
}

// tokenString is the SET to push: the original token as is in Forward mode, the
// event re-signed under the stream's iss and signing_alg otherwise (an empty route
// mode re-signs). A re-sign that fails returns the error, never an empty token.
func (a *HTTPAdapter) tokenString(req PushRequest) (string, error) {
	cfg := req.Stream.StreamConfiguration
	if cfg.RouteMode == model.RouteModeForward {
		return req.Event.Original, nil
	}
	// PB/IM re-sign: copy the stored event token before mutating iss/aud/iat/kid so
	// concurrent multi-stream fan-out cannot race on or corrupt the shared in-memory
	// event (PRD #196 #200). The copy is a value copy of the SecurityEventToken: every
	// field touched below is reassigned (slice/pointer headers replaced, not mutated
	// through shared backing storage), so the source event's iss/aud/iat/kid stay
	// pristine. jti (RegisteredClaims.ID) and txn (TransactionId) are carried over by
	// the copy and never touched, so they are preserved verbatim across the hop
	// (ADR 0017 — jti is the dedup key).
	token := req.Event.Event
	token.Issuer = cfg.Iss
	token.Audience = cfg.Aud
	token.IssuedAt = jwt.NewNumericDate(time.Now())
	token.Kid = req.Kid
	signed, err := token.JWS(goSet.SigningMethodOrRS256(cfg.SigningAlg), req.Key)
	if err != nil {
		return "", fmt.Errorf("signing SET for issuer %s: %w", cfg.Iss, err)
	}
	return signed, nil
}

// persistRemoteAddress updates the stream's RemoteAddress field both in memory
// and via streamService when the captured address differs from what was last
// recorded. Mirrors the existing only-when-changed guard that previously lived
// in router.pushEvent. Honors the caller's ctx so the write fails fast on
// router shutdown rather than racing against a closing storage.
//
// Concurrent deliveries on one stream share the record, so the read, persist
// and write run under the stream's mutex: each change is persisted once, and
// the in-memory and stored values converge on the last address observed.
func (a *HTTPAdapter) persistRemoteAddress(ctx context.Context, stream *model.StreamStateRecord, endpointURL, captured string) {
	if captured == "" || a.addressStore == nil {
		return
	}
	endpoint, _ := url.Parse(endpointURL)
	scheme := "http"
	if endpoint != nil && endpoint.Scheme != "" {
		scheme = endpoint.Scheme
	}
	remoteIP := model.BuildOutboundRemoteIP(scheme, captured)

	sid := stream.StreamConfiguration.Id
	lock := a.addressLock(sid)
	lock.Lock()
	defer lock.Unlock()
	if remoteIP.Equals(stream.RemoteAddress) {
		return
	}
	a.addressStore.UpdateRemoteAddress(ctx, sid, remoteIP)
	stream.RemoteAddress = remoteIP
}

// addressLock returns the mutex guarding RemoteAddress for stream sid.
func (a *HTTPAdapter) addressLock(sid string) *sync.Mutex {
	if m, ok := a.addrLocks.Load(sid); ok {
		return m.(*sync.Mutex)
	}
	m, _ := a.addrLocks.LoadOrStore(sid, &sync.Mutex{})
	return m.(*sync.Mutex)
}
