package delivery

import (
	"context"
	"net/http/httptrace"
	"net/url"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/i2-open/i2goSignals/pkg/services"
	"github.com/i2-open/i2goSignals/pkg/goSetPush"
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
type HTTPAdapter struct {
	streamService *services.StreamService
	keyReloader   KeyReloader
}

// NewHTTPAdapter wires the adapter for production.
func NewHTTPAdapter(streamService *services.StreamService, keyReloader KeyReloader) *HTTPAdapter {
	return &HTTPAdapter{
		streamService: streamService,
		keyReloader:   keyReloader,
	}
}

// SetKeyReloader supplies the KeyReloader after construction. Used by the
// composition root to break the chicken-and-egg between the adapter (which
// needs a KeyReloader) and the router (which implements KeyReloader but
// is constructed after the adapter, since it consumes the adapter).
func (a *HTTPAdapter) SetKeyReloader(r KeyReloader) {
	a.keyReloader = r
}

// Deliver signs-or-forwards the SET and pushes it. See package docs for scope.
func (a *HTTPAdapter) Deliver(ctx context.Context, req PushRequest) PushOutcome {
	out := a.attempt(ctx, req)

	if a.shouldRotateAndRetry(req, out.Classification) {
		newKey, newKid := a.keyReloader.InvalidateAndReload(
			req.Stream.StreamConfiguration.Id,
			req.Stream.StreamConfiguration.Iss,
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

	tokenString := a.tokenString(req)

	var capturedAddr string
	trace := &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			capturedAddr = info.Conn.RemoteAddr().String()
		},
	}
	traceCtx := httptrace.WithClientTrace(ctx, trace)

	result := goSetPush.PushSET(traceCtx, tokenString, goSetPush.TransmitterConfig{
		EndpointURL:   pushCfg.EndpointUrl,
		Authorization: pushCfg.AuthorizationHeader,
	})

	cls := goSetPush.ClassifyResult(result)
	a.persistRemoteAddress(ctx, req.Stream, pushCfg.EndpointUrl, capturedAddr)

	return PushOutcome{
		Classification: cls,
		RemoteAddress:  capturedAddr,
	}
}

func (a *HTTPAdapter) tokenString(req PushRequest) string {
	cfg := req.Stream.StreamConfiguration
	if cfg.RouteMode == model.RouteModeForward {
		return req.Event.Original
	}
	token := &req.Event.Event
	token.Issuer = cfg.Iss
	token.Audience = cfg.Aud
	token.IssuedAt = jwt.NewNumericDate(time.Now())
	token.Kid = req.Kid
	signed, err := token.JWS(jwt.SigningMethodRS256, req.Key)
	if err != nil {
		// Match the prior router behavior: log and return an empty token string so
		// the receiver responds with an error that ClassifyResult will surface.
		return ""
	}
	return signed
}

// persistRemoteAddress updates the stream's RemoteAddress field both in memory
// and via streamService when the captured address differs from what was last
// recorded. Mirrors the existing only-when-changed guard that previously lived
// in router.pushEvent. Honors the caller's ctx so the write fails fast on
// router shutdown rather than racing against a closing storage.
func (a *HTTPAdapter) persistRemoteAddress(ctx context.Context, stream *model.StreamStateRecord, endpointURL, captured string) {
	if captured == "" || a.streamService == nil {
		return
	}
	endpoint, _ := url.Parse(endpointURL)
	scheme := "http"
	if endpoint != nil && endpoint.Scheme != "" {
		scheme = endpoint.Scheme
	}
	remoteIP := model.BuildOutboundRemoteIP(scheme, captured)
	if remoteIP.Equals(stream.RemoteAddress) {
		return
	}
	a.streamService.UpdateRemoteAddress(ctx, stream.StreamConfiguration.Id, remoteIP)
	stream.RemoteAddress = remoteIP
}
