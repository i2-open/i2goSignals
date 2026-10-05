package eventRouter

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/i2-open/i2goSignals/internal/eventRouter/peer"
	"github.com/i2-open/i2goSignals/internal/providers/cluster"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/goSetSstp"
	"github.com/i2-open/i2goSignals/pkg/services"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// SSTP-server side runner (PRD #154 slice 8, issue #165).
//
// The SSTP-server (responder) side answers POST /sstp/{id} and long-polls
// outbound for the duration of the request. Every node can serve the endpoint,
// so the receiver side scales horizontally (Q11.1); the outbound queue lives
// only on the holder of the pair's sstp-server lease, and a non-owner serves
// the outbound half through one Claim to it (#365).
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

// SstpServerHandler runs one SSTP-server cycle for the pair already resolved by
// the HTTP handler (PRD #49 slice 3, AC 2: single pair resolution). The handler
// owns pair-404 — it looks the record up once, applies its 4xx gates in order
// (Check → pair-404 → bearer → Parse), and threads the resolved record here. The
// runner therefore performs NO second GetStreamStateByPairId — a rec==nil is a
// caller contract violation and yields an empty response so a misuse cannot
// silently re-deliver on stale state.
//
// It ingests the already-parsed inbound SETs (persist-then-route via HandleEvent,
// counting eventsIn with tfr=SSTP, stream_id=rxSid), then long-polls the outbound
// EventPollBuffer and returns the resulting SSTP response message.
func (r *router) SstpServerHandler(ctx context.Context, rec *model.StreamStateRecord, inbound goSetSstp.Message, parsedIn []SstpInboundSet) (goSetSstp.Message, error) {
	resp := goSetSstp.Message{}
	if rec == nil {
		// Defensive: the handler must resolve the pair before calling. If a
		// caller nonetheless passes nil, refuse to fabricate state — return
		// an empty response rather than panicking or re-looking-up.
		return resp, nil
	}
	if err := r.startGate(); err != nil {
		// Delivery waits for the legacy deliveries migration (#361): refuse
		// the whole exchange before the owner is resolved, a queue is seeded
		// or the peer's acks are applied; the peer resends on 503.
		eventLogger.Debug("SSTP-SRV: delivery not started yet; exchange refused", "sid", rec.StreamConfiguration.Id)
		return resp, err
	}

	// Seed the request memo with the pair the HTTP handler already resolved
	// (issue #287). Without it resolveIngressStream re-derives the very same
	// record from the rx-side SID at a cost of three stream-store round trips:
	// FindByID(rxSid) misses, GetStreamStateBySID probes FindByID(rxSid) a second
	// time, and only FindByInboundSID(rxSid) hits. Seeded, all three are served
	// from memory for the life of this request, and nothing is asserted about a
	// SID this record does not carry.
	ctx = services.WithRequestStreamCache(ctx)
	services.SeedRequestStream(ctx, rec)

	// Outbound ack consumption (Finding #5): the peer's request carries, in
	// Message.Ack, the JTIs of outbound SETs it received on a previous cycle. Ack
	// them on the pair's outbound buffer AND via eventService so they are removed
	// from the pending list and never re-delivered. This mirrors the RFC8936 poll
	// transmitter's params.Acks handling (PollStreamHandler): a SET delivered in
	// cycle N is acked by the peer in cycle N+1's request. drainSstpOutbound's
	// GetEvents only COPIES; only AckEvents removes — so without this, every
	// delivered SET would be re-sent forever.
	txSid := rec.StreamConfiguration.Id
	var wireAcks, wireClears []string
	if len(inbound.Ack) > 0 {
		// Ack unconditionally, mirroring the RFC8936 poll transmitter
		// (PollStreamHandler): the per-pair buffer's AckEvents is a no-op for any JTI
		// not pending, and a peer can only ever ack JTIs from its own pair's outbound
		// stream — so an ack for a not-yet-delivered JTI at worst drops that peer's own
		// event, never another stream's. Crucially any node serves this endpoint,
		// so the ack MUST be honored regardless of which node
		// delivered the SET; per-node delivery tracking would silently drop a legitimate
		// cross-node ack and redeliver forever. Since #365 a non-owner hands the
		// ack to the acceptor lease owner in its Claim.
		//
		// The peer acks the acknowledgement JTIs it received (#363): they go to the
		// store as received, in one Ack with any cleared setErrs below.
		wireAcks = inbound.Ack
	}

	// Outbound setErr consumption: the peer's request also carries, in
	// Message.SetErrs, the JTIs of outbound SETs it REJECTED — notably a SET whose
	// payload failed the peer's event_validation. A DETERMINISTIC rejection must
	// clear exactly like an ack, or drainSstpOutbound re-claims it every cycle and
	// the pair's outbound buffer never drains that JTI: claim, sign, POST, reject,
	// release, repeat.
	//
	// Clearing is permanent, so it is not applied to every code. goSetSstp.
	// PartitionSetErrs applies the ADR-0040 verdicts: a retryable rejection
	// (ProblemSignatureInvalid / ProblemUnknownKID / jwtCrypto — what a peer emits
	// while our signing key rotates or its JWKS cache is briefly stale) stays
	// pending so the very same SET is re-sent once the key material settles, and a
	// stream-fatal one (binding-revoked) pauses the pair instead of
	// draining the queue into a stream the peer says is dead. Every rejection is
	// logged so the operator sees what the peer refused and why.
	if len(inbound.SetErrs) > 0 {
		disposition := goSetSstp.PartitionSetErrs(inbound.SetErrs)
		for _, jti := range disposition.Retry {
			se := inbound.SetErrs[jti]
			eventLogger.Warn("SSTP-SRV: peer rejected outbound SET with a retryable code, holding it for resend",
				"sid", txSid, "jti", jti, "err", se.Err, "description", se.Description)
		}
		for _, jti := range disposition.Unrecognized {
			se := inbound.SetErrs[jti]
			eventLogger.Warn("SSTP-SRV: peer rejected outbound SET with an unrecognized code, holding it rather than discarding it",
				"sid", txSid, "jti", jti, "err", se.Err, "description", se.Description)
		}
		for _, jti := range disposition.Clear {
			se := inbound.SetErrs[jti]
			eventLogger.Warn("SSTP-SRV: peer rejected outbound SET, clearing it",
				"sid", txSid, "jti", jti, "err", se.Err, "description", se.Description)
		}
		wireClears = disposition.Clear
		if len(disposition.Fatal) > 0 {
			eventLogger.Error("SSTP-SRV: peer reports the stream is dead, pausing pair",
				"sid", txSid, "jti", disposition.Fatal[0],
				"err", disposition.FatalErr.Err, "description", disposition.FatalErr.Description)
			r.pauseSstpPair(rec, fmt.Sprintf("SSTP-SRV: peer reports stream dead on pair=%s: %s: %s",
				rec.PairId, disposition.FatalErr.Err, disposition.FatalErr.Description))
		}
	}

	// The acceptor side is leased (#365): its owner holds the pair's one
	// outbound queue and applies acks and cleared setErrs in its one write. A
	// request that acks, clears or asks for events resolves the owner here; a
	// non-owner sends all of it to the owner in one Claim after the inbound
	// ingest below. A request with none of these (the second-push cycles of a
	// dialing peer) makes no Claim.
	resource := cluster.SstpServerResource(txSid)
	hasAcks := len(wireAcks) > 0 || len(wireClears) > 0
	wantsEvents := rec.Status == model.StreamStateEnabled && inbound.ReturnEventsResolved()
	var owner string
	var self bool
	if hasAcks || wantsEvents {
		owner, self = r.resolveOwner(resource)
	}
	claim := peer.ClaimRequest{Sid: txSid, Mode: peer.ModeSstpServer, AckJtis: wireAcks, SetErrJtis: wireClears}
	if hasAcks && self {
		// One acknowledgement write, through the pair's DeliveryQueue (#363).
		r.claimLocal(ctx, claim, false)
		claim.AckJtis, claim.SetErrJtis = nil, nil
		hasAcks = false
	}

	// Inbound ingest: persist-then-process the parsed SETs as one batch via
	// HandleEvents, keyed on the rx-side SID so the inbound counter carries
	// stream_id=rxSid (Q46). A duplicate JTI is swallowed silently by the #153
	// short-circuit; we still ack it so the sender stops resending.
	rxSid := ""
	if rec.SstpInbound != nil {
		rxSid = rec.SstpInbound.Id
	}
	// Inbound ingest is governed by the inbound direction's status. When inbound is
	// paused/disabled we decline to ingest (the sender's SETs stay un-acked and are
	// resent on a later cycle once the direction resumes).
	if rec.InboundStatus == model.StreamStateEnabled {
		batch := make([]SstpInboundSet, 0, len(parsedIn))
		for _, in := range parsedIn {
			if in.Token != nil {
				batch = append(batch, in)
			}
		}
		tokens := make([]*goSet.SecurityEventToken, len(batch))
		raws := make([]string, len(batch))
		for i, in := range batch {
			tokens[i], raws[i] = in.Token, in.Raw
		}
		var storeErr error
		for i, ingestErr := range r.HandleEventsCtx(ctx, tokens, raws, rxSid) {
			if errors.Is(ingestErr, ErrStoreUnavailable) {
				storeErr = ingestErr
				continue
			}
			if ingestErr != nil {
				resp.SetErrs = appendSstpSetErr(resp.SetErrs, batch[i].Jti, ingestErr)
				continue
			}
			resp.Ack = append(resp.Ack, batch[i].Jti)
		}
		if storeErr != nil {
			// A SET the peer sent could not be durably stored (#333). Refuse the
			// whole exchange so the peer resends it: the SETs that were stored
			// come back as duplicate JTIs and are acked then, and nothing is
			// drained outbound into a response that will not be sent.
			// WARN, not ERROR: the peer resends on 503 and the store layer
			// already logs the underlying failure (CONTEXT.md log-level policy).
			eventLogger.Warn("SSTP-SRV: inbound SET could not be stored, refusing exchange",
				"sid", txSid, "error", storeErr)
			return goSetSstp.Message{}, storeErr
		}
	}

	// Outbound long-poll drain is governed by the outbound direction's status. A
	// paused (or disabled) outbound returns 200 with returnEvents=false so the
	// long-poll cycle keeps running and resumes draining on unpause — 4xx is
	// reserved for the deleted-pair case (PRD #154 Q20, Q7.3), handled at the
	// HTTP handler.
	if !wantsEvents {
		if hasAcks {
			// MaxEvents 0: the owner applies the acks and claims nothing.
			r.claimFor(ctx, resource, owner, self, claim)
		}
		if rec.Status != model.StreamStateEnabled {
			resp.ReturnEvents = goSetSstp.BoolPtr(false)
		}
		return resp, nil
	}

	// Outbound long-poll drain: one claim on the pair's queue, on the owner,
	// for the duration of the request (Q7.1, Q19, Q20), carrying any acks
	// not yet applied.
	sets, signErr := r.drainSstpOutbound(ctx, rec, inbound, resource, owner, self, claim)
	if signErr != nil {
		// The key was checked when the exchange began (CheckSstpSigningKey) but
		// could not sign this batch: send none of it, rather than a message that
		// leaves SETs out, and take the key-unavailable pause (#312). The inbound
		// half is already applied, so the exchange still answers 200 with its acks.
		r.takeKeyUnavailablePause(rec, "SSTP-SRV", signErr)
		resp.ReturnEvents = goSetSstp.BoolPtr(false)
		return resp, nil
	}
	if len(sets) > 0 {
		resp.Sets = sets
	}

	return resp, nil
}

// drainSstpOutbound claims the pair's next outbound SETs and returns them for
// this cycle (signed for publish mode, forwarded verbatim for
// RouteModeForward). The claim runs on the acceptor lease owner: here, or
// through one Claim when another node owns it (#365). The wait reuses the
// I2SIG_POLL_DEFAULT_TIMEOUT / I2SIG_POLL_MAX_TIMEOUT knobs (no SSTP-specific
// knob) and ends when the request context is cancelled, so a peer that
// disconnects cancels the Claim on the owner.
func (r *router) drainSstpOutbound(ctx context.Context, rec *model.StreamStateRecord, inbound goSetSstp.Message, resource, owner string, self bool, claim peer.ClaimRequest) (map[string]string, error) {
	// ReturnImmediately mirrors the wire field: a peer that sets
	// returnImmediately=true declines long-polling and gets whatever is
	// already queued (§2.1).
	ri := inbound.ReturnImmediatelyResolved()
	claim.MaxEvents = int32(r.backfillBatch)
	claim.ReturnImmediately = ri
	claim.WaitMs = r.claimWaitMs(0, ri)
	if self && !ri {
		claim.WaitMs = r.resolvedWait(0).Milliseconds()
	}
	resp, token, local := r.claimFor(ctx, resource, owner, self, claim)
	if len(resp.Refs) == 0 {
		return nil, nil
	}
	if !local {
		forward := rec.GetRouteMode() == model.RouteModeForward
		var key crypto.Signer
		var kid string
		if !forward {
			key, kid = r.checkAndLoadKey(rec.StreamConfiguration.Id, rec.StreamConfiguration.Iss, rec.StreamConfiguration.SigningAlg)
			if key == nil {
				return nil, errNoActiveSigningKey(rec.StreamConfiguration)
			}
		}
		return r.signClaimedRefs(rec, resp.Refs, forward, key, kid)
	}
	sets, err := r.buildSstpOutboundSets(rec, r.resolveOutboundSets(resp.Refs))
	if err != nil {
		if buf, _ := r.heldBuffer(peer.ModeSstpServer, rec.StreamConfiguration.Id); buf != nil {
			r.queueFor(rec.StreamConfiguration.Id).ReleaseClaim(token)
		}
	}
	return sets, err
}

// buildSstpOutboundSets renders each outbound set to its on-wire SET string:
// forwarded verbatim in RouteModeForward, or signed with the pair's issuer key
// under the set's Ref.AckJti otherwise. The records come resolved in one read
// (resolveOutboundSets), then the re-signing fans out across the
// signConcurrency pool (ADR 0036). A reference whose record is gone was
// dropped by that read and stays in the buffer. With no active key, or when any SET fails to sign, it
// returns no sets and the error, so the caller sends none of them rather than
// a message that leaves one out (#312); every SET stays pending.
func (r *router) buildSstpOutboundSets(rec *model.StreamStateRecord, outbound []OutboundSet) (map[string]string, error) {
	forward := rec.GetRouteMode() == model.RouteModeForward
	var key crypto.Signer
	var kid string
	if !forward {
		key, kid = r.checkAndLoadKey(rec.StreamConfiguration.Id, rec.StreamConfiguration.Iss, rec.StreamConfiguration.SigningAlg)
		if key == nil {
			return nil, errNoActiveSigningKey(rec.StreamConfiguration)
		}
	}

	q := r.queueFor(rec.StreamConfiguration.Id)
	sets := make(map[string]string, len(outbound))
	work := make([]*model.EventRecord, 0, len(outbound))
	ackJtiOf := make(map[*model.EventRecord]string, len(outbound))
	for _, set := range outbound {
		if set.Record == nil {
			continue
		}
		if forward {
			sets[set.Ref.Jti] = set.Record.Original
			continue
		}
		work = append(work, set.Record)
		ackJtiOf[set.Record] = set.Ref.AckJti
	}
	if len(work) == 0 {
		q.MarkHandedOut(mapKeys(sets), time.Now())
		return sets, nil
	}

	// Each re-signed SET is a value copy of the stored token carrying the
	// reference's acknowledgement JTI (#363); the message keys it by that
	// JTI, which is what the peer acks.
	cfg := rec.StreamConfiguration
	method := goSet.SigningMethodOrRS256(cfg.SigningAlg)
	// A reference claimed without its acknowledgement JTI (a bare buffer
	// submit) takes its stored row's one, all in one Resolve; one with none
	// is not sent and its claim is released.
	var bare []string
	for _, eventRecord := range work {
		if ackJtiOf[eventRecord] == "" {
			bare = append(bare, eventRecord.Jti)
		}
	}
	if len(bare) > 0 {
		refs, _ := q.Resolve(bare)
		found := make(map[string]string, len(refs))
		for _, ref := range refs {
			found[ref.Jti] = ref.AckJti
		}
		resolved := work[:0]
		for _, eventRecord := range work {
			if ackJtiOf[eventRecord] == "" {
				ackJti, ok := found[eventRecord.Jti]
				if !ok {
					continue
				}
				ackJtiOf[eventRecord] = ackJti
			}
			resolved = append(resolved, eventRecord)
		}
		work = resolved
	}
	if len(work) == 0 {
		q.MarkHandedOut(mapKeys(sets), time.Now())
		return sets, nil
	}
	idx := make(map[*model.EventRecord]int, len(work))
	tokens := make([]goSet.SecurityEventToken, len(work))
	for i, eventRecord := range work {
		idx[eventRecord] = i
		tokens[i] = eventRecord.Event
		tokens[i].ID = ackJtiOf[eventRecord]
	}
	signed := SignSets(work, r.signConcurrency, func(eventRecord *model.EventRecord) (string, error) {
		token := &tokens[idx[eventRecord]]
		token.Issuer = cfg.Iss
		token.Audience = cfg.Aud
		token.IssuedAt = jwt.NewNumericDate(time.Now())
		token.Kid = kid
		return token.JWS(method, key)
	})
	for i, eventRecord := range work {
		if signed[i].Err != nil {
			return nil, fmt.Errorf("signing outbound JTI %s: %w", eventRecord.Jti, signed[i].Err)
		}
	}
	for i, eventRecord := range work {
		sets[tokens[i].ID] = signed[i].JWS
		q.Served(eventRecord, &tokens[i], signed[i].JWS)
	}
	q.MarkHandedOut(mapKeys(sets), time.Now())
	return sets, nil
}

// mapKeys returns m's keys in no particular order.
func mapKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
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
