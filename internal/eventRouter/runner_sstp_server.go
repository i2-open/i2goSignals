package eventRouter

import (
	"context"
	"crypto/rsa"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/i2-open/i2goSignals/internal/eventRouter/buffer"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/goSetSstp"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// SSTP-server side runner (PRD #154 slice 8, issue #165).
//
// The SSTP-server (responder) side answers POST /sstp/{id} and long-polls
// outbound for the duration of the request. It takes NO cluster lease — every
// node can serve the endpoint, so the receiver side scales horizontally (Q11.1).
// It is parallel to PollEventsHandler/PollStreamHandler but drives both the
// inbound (ingest) and outbound (long-poll drain) halves of one SSTP HTTP cycle.

// SstpInboundSet is one already-parsed inbound SET handed to the SSTP-server
// runner. The HTTP handler parses each Sets[jti] entry with goSetPush.ParseReceivedSET
// (each SET is byte-identical to an RFC8935 SET, Q5.1) and forwards the verified
// token + raw string here; the runner persists it through the normal ingest path.
type SstpInboundSet struct {
	Jti   string
	Token *goSet.SecurityEventToken
	Raw   string
}

// SstpServerHandler runs one SSTP-server cycle for the pair named by pairId: it
// ingests the already-parsed inbound SETs (persist-then-route through HandleEvent,
// counting eventsIn with tfr=SSTP, stream_id=rxSid), then long-polls the outbound
// EventPollBuffer and returns the resulting SSTP response message. Returns the
// response and an HTTP status: 200 for a served (or paused) pair, 404 for a
// deleted/unknown pair.
func (r *router) SstpServerHandler(ctx context.Context, pairId string, inbound goSetSstp.Message, parsedIn []SstpInboundSet) (goSetSstp.Message, int) {
	rec, err := r.streamService.GetStreamStateByPairId(r.ctx, pairId)
	if err != nil || rec == nil {
		return goSetSstp.Message{}, http.StatusNotFound
	}

	resp := goSetSstp.Message{}

	// Outbound ack consumption (Finding #5): the peer's request carries, in
	// Message.Ack, the JTIs of outbound SETs it received on a previous cycle. Ack
	// them on the pair's outbound buffer AND via eventService so they are removed
	// from the pending list and never re-delivered. This mirrors the RFC8936 poll
	// transmitter's params.Acks handling (PollStreamHandler): a SET delivered in
	// cycle N is acked by the peer in cycle N+1's request. drainSstpOutbound's
	// GetEvents only COPIES; only AckEvents removes — so without this, every
	// delivered SET would be re-sent forever.
	txSid := rec.StreamConfiguration.Id
	if len(inbound.Ack) > 0 {
		// Finding #3: gate the peer's ack to JTIs THIS node actually delivered to it
		// on a prior cycle (recorded in sstpServerDelivered). A buggy/replaying peer
		// that acks a JTI never delivered to it must not prematurely remove a
		// still-undelivered outbound SET — mirrors the client handleSstpAcks sent-set
		// gate. Scoped per-pair (keyed on txSid).
		gated := r.gateSstpServerAck(txSid, inbound.Ack)
		if len(gated) > 0 {
			buf := r.sstpServerBufferFor(txSid)
			buf.AckEvents(gated)
			for _, jti := range gated {
				_ = r.eventService.AckEvent(r.ctx, jti, txSid, 0)
			}
		}
	}

	// Inbound ingest: persist-then-process each parsed SET via HandleEvent, keyed
	// on the rx-side SID so the inbound counter carries stream_id=rxSid (Q46). A
	// duplicate JTI is swallowed silently by HandleEvent's #153 short-circuit; we
	// still ack it so the sender stops resending.
	rxSid := ""
	if rec.SstpInbound != nil {
		rxSid = rec.SstpInbound.Id
	}
	// Inbound ingest is governed by the inbound direction's status. When inbound is
	// paused/disabled we decline to ingest (the sender's SETs stay un-acked and are
	// resent on a later cycle once the direction resumes).
	if rec.InboundStatus == model.StreamStateEnabled {
		for _, in := range parsedIn {
			if in.Token == nil {
				continue
			}
			if ingestErr := r.HandleEvent(in.Token, in.Raw, rxSid); ingestErr != nil {
				resp.SetErrs = appendSstpSetErr(resp.SetErrs, in.Jti, ingestErr)
				continue
			}
			resp.Ack = append(resp.Ack, in.Jti)
		}
	}

	// Outbound long-poll drain is governed by the outbound direction's status. A
	// paused (or disabled) outbound returns 200 with returnEvents=false so the
	// long-poll cycle keeps running and resumes draining on unpause — 4xx is
	// reserved for the deleted-pair case (PRD #154 Q20, Q7.3).
	if rec.Status != model.StreamStateEnabled {
		resp.ReturnEvents = goSetSstp.BoolPtr(false)
		return resp, http.StatusOK
	}

	// Outbound long-poll drain: wait on the pair's EventPollBuffer for the duration
	// of the request and return whatever SETs are available (Q7.1, Q15, Q19, Q20).
	sets := r.drainSstpOutbound(ctx, rec, inbound)
	if len(sets) > 0 {
		resp.Sets = sets
		// Finding #3: record the JTIs delivered this cycle as delivered-but-unacked so
		// the NEXT cycle's inbound Ack is gated to them.
		delivered := make([]string, 0, len(sets))
		for jti := range sets {
			delivered = append(delivered, jti)
		}
		r.recordSstpServerDelivered(txSid, delivered)
	}

	return resp, http.StatusOK
}

// recordSstpServerDelivered marks the given JTIs as delivered-but-unacked for the
// pair's tx SID, so a later inbound Ack for one of them is honored (Finding #3).
func (r *router) recordSstpServerDelivered(txSid string, jtis []string) {
	if len(jtis) == 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	set := r.sstpServerDelivered[txSid]
	if set == nil {
		set = map[string]bool{}
		r.sstpServerDelivered[txSid] = set
	}
	for _, jti := range jtis {
		set[jti] = true
	}
}

// gateSstpServerAck returns the subset of acked JTIs that this node actually
// delivered to the peer (present in sstpServerDelivered for txSid), and clears
// them from the delivered set. A JTI never delivered by this node is dropped, so a
// buggy/replaying peer cannot prematurely remove an undelivered outbound SET
// (Finding #3). Scoped per-pair.
func (r *router) gateSstpServerAck(txSid string, acked []string) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	set := r.sstpServerDelivered[txSid]
	if len(set) == 0 {
		return nil
	}
	gated := make([]string, 0, len(acked))
	for _, jti := range acked {
		if set[jti] {
			gated = append(gated, jti)
			delete(set, jti)
		}
	}
	if len(set) == 0 {
		delete(r.sstpServerDelivered, txSid)
	}
	return gated
}

// drainSstpOutbound long-polls the pair's outbound EventPollBuffer and returns the
// SETs to send back this cycle (signed for publish mode, forwarded verbatim for
// RouteModeForward). The wait reuses the I2SIG_POLL_DEFAULT_TIMEOUT /
// I2SIG_POLL_MAX_TIMEOUT knobs (no SSTP-specific knob) and — per Q15 — does NOT
// honor request-context cancellation: it waits the full buffer timeout even if the
// client aborts, symmetric with the RFC8936 poll-transmitter handler.
func (r *router) drainSstpOutbound(_ context.Context, rec *model.StreamStateRecord, inbound goSetSstp.Message) map[string]string {
	if !inbound.ReturnEventsResolved() {
		return nil
	}

	txSid := rec.StreamConfiguration.Id
	buf := r.sstpServerBufferFor(txSid)

	// Opportunistically prefetch pending JTIs when the buffer is empty (recovery
	// after takeover relies on persisted outbound events, Q13).
	if buf.Cnt() == 0 {
		jtis, _ := r.eventService.GetEventIds(r.ctx, txSid, model.PollParameters{
			MaxEvents:         int32(r.backfillBatch),
			ReturnImmediately: true,
		})
		if len(jtis) > 0 {
			buf.SubmitEvents(jtis)
		}
	}

	// Long-poll wait on the buffer. ReturnImmediately mirrors the wire field: a
	// peer that sets returnImmediately=true declines long-polling and gets whatever
	// is already queued (§2.1). Otherwise the buffer applies its resolved default
	// timeout. The buffer's own select on its notifier is the wait; it intentionally
	// does not observe the request context (Q15).
	jtiSlice, _ := buf.GetEvents(model.PollParameters{
		MaxEvents:         int32(r.backfillBatch),
		ReturnImmediately: inbound.ReturnImmediatelyResolved(),
	})
	if jtiSlice == nil || len(*jtiSlice) == 0 {
		return nil
	}

	return r.buildSstpOutboundSets(rec, *jtiSlice)
}

// sstpServerBufferFor returns the outbound long-poll buffer for the pair's tx
// SID, creating it (with the router's resolved poll timeouts) on first use.
func (r *router) sstpServerBufferFor(txSid string) *buffer.EventPollBuffer {
	r.mu.Lock()
	defer r.mu.Unlock()
	if buf, ok := r.sstpServerBuffers[txSid]; ok {
		return buf
	}
	buf := buffer.CreateEventPollBuffer(nil, r.pollDefaultTimeoutSecs, r.pollMaxTimeoutSecs)
	r.sstpServerBuffers[txSid] = buf
	return buf
}

// buildSstpOutboundSets renders each outbound JTI to its on-wire SET string:
// forwarded verbatim in RouteModeForward, or signed with the pair's issuer key
// otherwise. Mirrors the poll-transmitter's signing path (PollStreamHandler).
func (r *router) buildSstpOutboundSets(rec *model.StreamStateRecord, jtis []string) map[string]string {
	forward := rec.GetRouteMode() == model.RouteModeForward
	var key *rsa.PrivateKey
	var kid string
	if !forward {
		key, kid = r.checkAndLoadKey(rec.StreamConfiguration.Id, rec.StreamConfiguration.Iss)
	}

	sets := make(map[string]string, len(jtis))
	for _, jti := range jtis {
		eventRecord := r.eventService.GetEventRecord(r.ctx, jti)
		if eventRecord == nil {
			continue
		}
		if forward {
			sets[jti] = eventRecord.Original
			continue
		}
		token := &eventRecord.Event
		token.Issuer = rec.StreamConfiguration.Iss
		token.Audience = rec.StreamConfiguration.Aud
		token.IssuedAt = jwt.NewNumericDate(time.Now())
		token.Kid = kid
		signed, err := token.JWS(jwt.SigningMethodRS256, key)
		if err != nil {
			eventLogger.Error("SSTP-SRV: error signing outbound SET", "sid", rec.StreamConfiguration.Id, "jti", jti, "error", err)
			continue
		}
		sets[jti] = signed
	}
	return sets
}

// sstpInboundCounterRecord returns a view of the SSTP pair record whose
// StreamConfiguration carries the rx-side SID and rx-side issuer, so the inbound
// eventsIn counter labels stream_id with the receive-side SID (Q46). The pair's
// SstpMethod is preserved so GetType still reports DeliverySstpPair (tfr=SSTP).
func sstpInboundCounterRecord(pair *model.StreamStateRecord, rxSid string) *model.StreamStateRecord {
	view := *pair
	if pair.SstpInbound != nil {
		view.StreamConfiguration = *pair.SstpInbound
	}
	view.StreamConfiguration.Id = rxSid
	return &view
}

// appendSstpSetErr records a per-JTI ingest error in the SSTP setErrs map,
// allocating the map on first use.
func appendSstpSetErr(m map[string]goSetSstp.SetErr, jti string, err error) map[string]goSetSstp.SetErr {
	if m == nil {
		m = map[string]goSetSstp.SetErr{}
	}
	m[jti] = goSetSstp.SetErr{Err: string(goSetSstp.ErrSetData), Description: err.Error()}
	return m
}
