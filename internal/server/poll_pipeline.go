package server

import (
	"context"
	"net/http"
	"net/http/httptrace"
	"sync"

	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/goSetPoll"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/prometheus/client_golang/prometheus"
)

// pollOutstandingGauge counts the polls a receiver stream has sent to its
// upstream transmitter and not yet finished processing (#338). It is bounded by
// I2SIG_POLL_PIPELINE_DEPTH.
var pollOutstandingGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Namespace: "goSignals",
	Subsystem: "router",
	Name:      "poll_receiver_outstanding",
	Help:      "RFC 8936 polls a poll receiver stream has sent upstream and not yet finished processing (#338).",
}, []string{"stream_id"})

// pollOutcome is the result of one pipelined poll: the transport outcome, and on
// success the acks and setErrs the response earned for a later poll.
type pollOutcome struct {
	seq        uint64
	httpStatus int
	err        error
	// sentAcks and sentErrs are what this poll carried. A failed poll hands
	// them back so they ride the next poll, as the one-at-a-time loop resent
	// them.
	sentAcks []string
	sentErrs map[string]goSetPoll.SetErrType
	// acks and setErrs are what the response earned. A SET whose ingest failed
	// is absent from acks, so the transmitter sends it again (ADR 0038).
	acks       []string
	setErrs    map[string]goSetPoll.SetErrType
	setCnt     int
	more       bool
	remoteAddr string
}

// pollIssue is everything one poll needs, captured when the dispatcher sends it
// so a later client refresh or stream patch cannot change a poll mid-flight.
type pollIssue struct {
	seq           uint64
	sid           string
	stream        *model.StreamStateRecord
	eventUrl      string
	receiveMethod *model.PollReceiveMethod
	client        *http.Client
	auth          string
	acks          []string
	setErrs       map[string]goSetPoll.SetErrType
	// started is closed when a 200 response begins to arrive, or when the
	// poll's bodies have been read, whichever is first. It is never closed for
	// a failed poll. The dispatcher sends the next poll on it.
	started chan struct{}
}

// executePoll sends one poll and ingests its response. It runs on its own
// goroutine so up to I2SIG_POLL_PIPELINE_DEPTH of them overlap; the dispatcher
// in runPollLoop owns every piece of loop state and applies the outcome.
func (ps *ClientPollStream) executePoll(ctx context.Context, in pollIssue) pollOutcome {
	var once sync.Once
	markStarted := func() { once.Do(func() { close(in.started) }) }

	out := pollOutcome{seq: in.seq, sentAcks: in.acks, sentErrs: in.setErrs}
	stream := in.stream
	sid := in.sid

	pollReq := goSetPoll.PollRequest{
		Acks:    in.acks,
		SetErrs: in.setErrs,
	}
	if in.receiveMethod.PollConfig != nil {
		pollReq.MaxEvents = in.receiveMethod.PollConfig.MaxEvents
		pollReq.ReturnImmediately = in.receiveMethod.PollConfig.ReturnImmediately
		pollReq.TimeoutSecs = in.receiveMethod.PollConfig.TimeoutSecs
	}

	serverLog.Debug("POLL-RCV Initiating POLL request", "sid", sid, "url", in.eventUrl, "acks", len(in.acks), "setErrs", len(in.setErrs))
	var capturedPollAddr string
	pollTrace := &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			capturedPollAddr = info.Conn.RemoteAddr().String()
		},
	}
	tracedCtx := httptrace.WithClientTrace(ctx, pollTrace)
	// A 200 response has begun to stream: the pipeline may send the next poll
	// now rather than after this body is read and ingested (#338). Any other
	// status is left to the dispatcher's retry policy, so a 401 or 503 is never
	// answered by a second poll already on its way.
	client := startOnOK(in.client, markStarted)

	// Resolve this receiver's event_validation mode and engage the matching
	// validators (spec #247 #251). Re-resolved every poll so an operator
	// changing the mode on a live stream takes effect on the next poll; under
	// NONE the validator set is nil and Poll takes exactly the pre-#247 path.
	validationMode := resolveReceiveValidationMode(ps.sa.StreamService, stream)
	validators := buildReceiveValidatorSet(stream, validationMode)
	// The verification material is resolved per poll for the same reason: an
	// iss / issuerJWKSUrl patch (#306) replaces the receiver cache entry, and a
	// JWKS captured once before the loop would keep verifying against the old
	// key set for the life of this goroutine. The lookup is a cache read unless
	// the entry is due for retry.
	jwks := ps.sa.StreamService.GetIssuerJwksForReceiver(context.Background(), stream.StreamConfiguration.Id)

	parsed, httpStatus, err := goSetPoll.Poll(tracedCtx, pollReq, goSetPoll.ReceiverConfig{
		EndpointURL:       in.eventUrl,
		Authorization:     in.auth,
		HTTPClient:        client,
		JWKS:              jwks,
		ExpectedIssuer:    stream.Iss,
		ExpectedAudiences: stream.Aud,
		// Signing-only (#184): make verification of pulled SETs mandatory so a
		// nil JWKS rejects rather than silently accepting unsigned events.
		RequireSignature: stream.SigningOnly,
		Validators:       validators,
		// Business-stream TLS floor (#322): an http:// transmitter is refused
		// inside Poll unless the stream carries the tx_allow_plaintext opt-out.
		AllowPlaintext: stream.TxAllowPlaintext,
	})
	out.httpStatus = httpStatus
	out.err = err
	if err != nil {
		return out
	}
	// Bodies are read; the poll no longer holds a connection open.
	markStarted()

	setErrs := make(map[string]goSetPoll.SetErrType)
	acks := []string{}

	out.setCnt = len(parsed.Sets)
	out.more = parsed.MoreAvailable
	serverLog.Debug("POLL-RCV: Response received", "sid", sid, "setCnt", out.setCnt, "hasMore", parsed.MoreAvailable)

	// Carry over the parse / iss / aud errors goSetPoll reported, to be sent
	// back in a later poll's setErrs. Merged rather than assigned so the
	// event_validation rejections added below are not clobbered.
	for jti, setErr := range parsed.Errors {
		setErrs[jti] = setErr
	}

	// Process successfully parsed and validated SETs. Rejections are decided
	// per JTI below; what survives is ingested as one batch (one bulk insert,
	// one pending-list write per matching outbound stream) via HandleEventsCtx.
	batchJtis := make([]string, 0, len(parsed.ParsedSETs))
	batchTokens := make([]*goSet.SecurityEventToken, 0, len(parsed.ParsedSETs))
	batchRaws := make([]string, 0, len(parsed.ParsedSETs))
	for jti, token := range parsed.ParsedSETs {
		// Apply the stream's event_validation mode to the dispositions
		// goSetPoll computed (spec #247 #251). A rejected jti is reported in
		// setErrs with invalid_request and is never routed; other jtis in the
		// same batch still ack normally, because the decision is per-jti even
		// though it is whole-SET within a jti.
		//
		// It is ALSO acked. RFC8936 §2.4 keeps ack and setErrs separate and
		// leaves a transmitter free to keep an un-acked SET pending, so
		// reporting the error alone means a transmitter that does not read
		// setErrs as an acknowledgement re-delivers the same SET on every poll
		// forever — and with a bounded maxEvents or JTI-ordered service, the
		// poison SET occupies the batch every cycle and nothing behind it is
		// ever delivered. The stream livelocks while still reporting enabled.
		//
		// Acking it says "do not send this again", which is true: a payload
		// that fails validation fails identically on resend. The setErr is
		// what carries WHY, so the transmitter still learns the SET was
		// rejected rather than processed. This is the disposition the other
		// two transports already take — push clears a corroborated rejection,
		// SSTP maps invalid_request to Clear.
		if decision := applyEventValidation(validationMode, validationTransportPoll,
			sid, jti, parsed.Validations[jti], ps.sa.Stats); decision.Reject {
			setErrs[jti] = goSetPoll.SetErrType{
				Error:       decision.ErrCode,
				Description: decision.Description,
			}
			acks = append(acks, jti)
			continue
		}

		serverLog.Debug("POLL-RCV: Handling Event", "sid", sid, "jti", jti)
		batchJtis = append(batchJtis, jti)
		batchTokens = append(batchTokens, token)
		batchRaws = append(batchRaws, parsed.Sets[jti])
	}
	var ingestErrs []error
	if len(batchTokens) > 0 {
		// A response already received is stored even if the receiver is
		// stopping: only its acks are lost, and the transmitter redelivers
		// those SETs to the next owner, where JTI dedup absorbs them.
		ingestErrs = ps.sa.EventRouter.HandleEventsCtx(context.WithoutCancel(ctx), batchTokens, batchRaws, sid)
	}
	for i, ingestErr := range ingestErrs {
		if ingestErr != nil {
			serverLog.Error("POLL-RCV: Error handling event", "sid", sid, "jti", batchJtis[i], "error", ingestErr)
			// We don't acknowledge if we couldn't handle it (ADR 0038).
			continue
		}
		acks = append(acks, batchJtis[i])
	}

	out.acks = acks
	out.setErrs = setErrs
	out.remoteAddr = capturedPollAddr
	return out
}

// startOnOK returns a copy of client whose transport calls onOK when a
// response with status 200 arrives, before its body is read.
func startOnOK(client *http.Client, onOK func()) *http.Client {
	c := &http.Client{}
	if client != nil {
		*c = *client
	}
	base := c.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	c.Transport = startOnOKTransport{base: base, onOK: onOK}
	return c
}

type startOnOKTransport struct {
	base http.RoundTripper
	onOK func()
}

func (t startOnOKTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err == nil && resp.StatusCode == http.StatusOK {
		t.onOK()
	}
	return resp, err
}

// mergeSetErrs adds src into dst, allocating dst when needed.
func mergeSetErrs(dst, src map[string]goSetPoll.SetErrType) map[string]goSetPoll.SetErrType {
	if len(src) == 0 {
		return dst
	}
	if dst == nil {
		dst = make(map[string]goSetPoll.SetErrType, len(src))
	}
	for jti, e := range src {
		dst[jti] = e
	}
	return dst
}
