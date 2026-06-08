package eventRouter

import (
	"context"
	"testing"
	"time"

	"github.com/i2-open/i2goSignals/internal/eventRouter/delivery"
	"github.com/i2-open/i2goSignals/pkg/goSetSstp"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// SSTP-server side runner (PRD #154 slice 8, issue #165). These tests exercise
// the router method that backs POST /sstp/{id}: it ingests inbound SETs through
// HandleEvent (counting eventsIn with tfr=SSTP, stream_id=rxSid), long-polls the
// outbound EventPollBuffer, and shapes the paused-pair response. The HTTP parse
// of each inbound SET (goSetPush.ParseReceivedSET) is tested at the handler layer.

// sstpServerPairState builds a persisted bidirectional SSTP pair record for the
// server-side runner tests. txSid is the outbound (primary) SID; rxSid is the
// inbound (SstpInbound) SID; pairId is the on-wire SSF stream_id (== document
// _id). Both directions start enabled.
func sstpServerPairState(txSid, rxSid, pairId string) *model.StreamStateRecord {
	return &model.StreamStateRecord{
		StreamConfiguration: model.StreamConfiguration{
			Id:        txSid,
			Iss:       dupTestIssuer,
			Aud:       []string{"https://peer.example.com"},
			RouteMode: model.RouteModeForward,
		},
		Status:        model.StreamStateEnabled,
		InboundStatus: model.StreamStateEnabled,
		PairId:        pairId,
		SstpInbound: &model.StreamConfiguration{
			Id:        rxSid,
			Iss:       "https://peer.example.com",
			Aud:       []string{dupTestIssuer},
			RouteMode: model.RouteModeImport,
		},
		SstpMethod: &model.SstpMethod{
			Role:        model.SstpRoleResponder,
			EndpointUrl: "https://local.example.com/sstp/" + pairId,
		},
	}
}

func inCounterValueSstp(t *testing.T, vec *prometheus.CounterVec, sid string) float64 {
	t.Helper()
	return testutil.ToFloat64(vec.With(prometheus.Labels{
		"type":      typeAcctDisabled,
		"iss":       "https://peer.example.com",
		"tfr":       "SSTP",
		"stream_id": sid,
	}))
}

// TestSstpServer_IngestsInboundAndCountsRxMetric is the tracer bullet: an inbound
// SET delivered to the SSTP-server side is persisted and counted in eventsIn with
// tfr=SSTP and stream_id=rxSid (Q46, Q5.1).
func TestSstpServer_IngestsInboundAndCountsRxMetric(t *testing.T) {
	adapter := delivery.NewSstpMemoryAdapter(delivery.SstpOutcome{})
	h := newSstpRunnerHarness(t, adapter)

	txSid, rxSid, pairId := "sstp-tx-in", "sstp-rx-in", "pair-in"
	rec := sstpServerPairState(txSid, rxSid, pairId)
	require.NoError(t, h.router.streamService.PersistStreamStateRecord(context.Background(), rec))

	jti := "sstp-in-1"
	token := newRiscToken(jti, "https://peer.example.com", dupTestIssuer)
	inbound := []SstpInboundSet{{Jti: jti, Token: token, Raw: `{"raw":"in1"}`}}

	// returnImmediately declines the outbound long-poll; this test exercises the
	// inbound ingest + metric, not the outbound wait.
	resp, status := h.router.SstpServerHandler(context.Background(), pairId,
		goSetSstp.Message{ReturnImmediately: goSetSstp.BoolPtr(true)}, inbound)

	assert.Equal(t, 200, status, "enabled pair ingest must return 200")
	assert.Contains(t, resp.Ack, jti, "ingested SET must be acked back to the sender")
	assert.InDelta(t, 1.0, inCounterValueSstp(t, h.inCounter, rxSid), 0.0001,
		"inbound SET must increment eventsIn with tfr=SSTP and stream_id=rxSid")
}

// TestSstpServer_DuplicateInboundJtiSwallowed: re-delivering the same inbound JTI
// is swallowed silently by HandleEvent's #153 dedup short-circuit — the second
// arrival does NOT increment eventsIn a second time, yet is still acked so the
// sender stops resending (PRD #154 Q13 takeover window).
func TestSstpServer_DuplicateInboundJtiSwallowed(t *testing.T) {
	adapter := delivery.NewSstpMemoryAdapter(delivery.SstpOutcome{})
	h := newSstpRunnerHarness(t, adapter)

	txSid, rxSid, pairId := "sstp-tx-dup", "sstp-rx-dup", "pair-dup"
	rec := sstpServerPairState(txSid, rxSid, pairId)
	require.NoError(t, h.router.streamService.PersistStreamStateRecord(context.Background(), rec))

	jti := "sstp-dup-1"
	token := newRiscToken(jti, "https://peer.example.com", dupTestIssuer)
	inbound := []SstpInboundSet{{Jti: jti, Token: token, Raw: `{"raw":"dup"}`}}

	immediate := goSetSstp.Message{ReturnImmediately: goSetSstp.BoolPtr(true)}
	resp1, status1 := h.router.SstpServerHandler(context.Background(), pairId, immediate, inbound)
	require.Equal(t, 200, status1)
	require.Contains(t, resp1.Ack, jti)
	require.InDelta(t, 1.0, inCounterValueSstp(t, h.inCounter, rxSid), 0.0001,
		"first inbound increments eventsIn once")

	// Second delivery of the same JTI.
	resp2, status2 := h.router.SstpServerHandler(context.Background(), pairId, immediate, inbound)
	assert.Equal(t, 200, status2)
	assert.Contains(t, resp2.Ack, jti, "duplicate must still be acked so the sender stops resending")
	assert.InDelta(t, 1.0, inCounterValueSstp(t, h.inCounter, rxSid), 0.0001,
		"duplicate JTI must NOT increment eventsIn a second time")
}

// TestSstpServer_DrainsOutboundReturnsSets: a pending outbound event on the
// pair's tx side is returned in the SSTP response "sets" (forward mode returns
// the original SET verbatim). This is the outbound half of the single cycle.
func TestSstpServer_DrainsOutboundReturnsSets(t *testing.T) {
	adapter := delivery.NewSstpMemoryAdapter(delivery.SstpOutcome{})
	h := newSstpRunnerHarness(t, adapter)

	txSid, rxSid, pairId := "sstp-tx-out", "sstp-rx-out", "pair-out"
	rec := sstpServerPairState(txSid, rxSid, pairId)
	require.NoError(t, h.router.streamService.PersistStreamStateRecord(context.Background(), rec))

	jti := "sstp-out-1"
	h.persistOutboundEvent(t, txSid, jti)

	resp, status := h.router.SstpServerHandler(context.Background(), pairId, goSetSstp.Message{}, nil)

	assert.Equal(t, 200, status)
	require.Contains(t, resp.Sets, jti, "pending outbound SET must be returned in the response sets")
	assert.NotEmpty(t, resp.Sets[jti], "returned SET must carry the encoded SET string")
}

// TestSstpServer_PausedPairReturnsReturnEventsFalse: when either direction of the
// pair is paused, the server returns 200 with returnEvents=false and NO outbound
// sets — the long-poll cycle keeps running and resumes draining on unpause. 4xx is
// reserved for the deleted-pair case (PRD #154 Q20, Q7.3).
func TestSstpServer_PausedPairReturnsReturnEventsFalse(t *testing.T) {
	adapter := delivery.NewSstpMemoryAdapter(delivery.SstpOutcome{})
	h := newSstpRunnerHarness(t, adapter)

	txSid, rxSid, pairId := "sstp-tx-pause", "sstp-rx-pause", "pair-pause"
	rec := sstpServerPairState(txSid, rxSid, pairId)
	rec.Status = model.StreamStatePause // outbound paused
	require.NoError(t, h.router.streamService.PersistStreamStateRecord(context.Background(), rec))

	// A pending outbound event exists, but the paused state must suppress it.
	h.persistOutboundEvent(t, txSid, "sstp-pause-out")

	resp, status := h.router.SstpServerHandler(context.Background(), pairId, goSetSstp.Message{}, nil)

	assert.Equal(t, 200, status, "paused pair returns 200, not 4xx")
	require.NotNil(t, resp.ReturnEvents, "paused pair must set returnEvents explicitly")
	assert.False(t, *resp.ReturnEvents, "paused pair must return returnEvents=false")
	assert.Empty(t, resp.Sets, "paused pair must not drain outbound sets")
}

// TestSstpServer_DeletedPairReturns4xx: an unknown/deleted PairId returns a 4xx
// status (HTTP status is the primary error signal end-to-end).
func TestSstpServer_DeletedPairReturns4xx(t *testing.T) {
	adapter := delivery.NewSstpMemoryAdapter(delivery.SstpOutcome{})
	h := newSstpRunnerHarness(t, adapter)

	_, status := h.router.SstpServerHandler(context.Background(), "pair-does-not-exist", goSetSstp.Message{}, nil)
	assert.GreaterOrEqual(t, status, 400, "deleted/unknown pair must return 4xx")
	assert.Less(t, status, 500, "deleted/unknown pair must return a 4xx, not 5xx")
}

// TestSstpServer_PreInitializeCounter_RxSide: pre-initializing the counter for an
// SSTP pair primes BOTH directions' eventsIn series — the rx side (stream_id=rxSid)
// in addition to the tx side primed in slice #164 — so the inbound metric is
// visible from process start (Q46).
func TestSstpServer_PreInitializeCounter_RxSide(t *testing.T) {
	adapter := delivery.NewSstpMemoryAdapter(delivery.SstpOutcome{})
	h := newSstpRunnerHarness(t, adapter)

	// No series exist before pre-initialization (avoid the With() side effect of
	// auto-creating the series, which would make a label-value read pass trivially).
	require.Equal(t, 0, testutil.CollectAndCount(h.inCounter), "no eventsIn series before PreInitialize")

	rec := sstpServerPairState("sstp-tx-pre2", "sstp-rx-pre2", "pair-pre2")
	h.router.PreInitializeCounter(rec)

	// Both directions must now be primed on eventsIn: the tx side (#164) AND the rx
	// side (#165). Two distinct stream_id series proves the rx side was added.
	assert.Equal(t, 2, testutil.CollectAndCount(h.inCounter),
		"PreInitialize must prime eventsIn for BOTH the tx and rx sides of an SSTP pair")

	rxV := testutil.ToFloat64(h.inCounter.With(prometheus.Labels{
		"type":      "NONE",
		"iss":       "https://peer.example.com",
		"tfr":       "SSTP",
		"stream_id": "sstp-rx-pre2",
	}))
	assert.Equal(t, 0.0, rxV, "rx-side eventsIn series must be primed at zero with tfr=SSTP")
}

// TestSstpServer_LongPollIgnoresContextCancel: the outbound long-poll wait does
// NOT honor request-context cancellation — an aborted client does not make the
// handler return early; it waits out the buffer timeout (PRD #154 Q15, distinct
// from the SSTP-client side which DOES cancel on lease loss).
func TestSstpServer_LongPollIgnoresContextCancel(t *testing.T) {
	adapter := delivery.NewSstpMemoryAdapter(delivery.SstpOutcome{})
	h := newSstpRunnerHarness(t, adapter)
	// Shrink the buffer long-poll timeout so the test waits ~1s, not 30s.
	h.router.pollDefaultTimeoutSecs = 1

	txSid, rxSid, pairId := "sstp-tx-ctx", "sstp-rx-ctx", "pair-ctx"
	rec := sstpServerPairState(txSid, rxSid, pairId)
	require.NoError(t, h.router.streamService.PersistStreamStateRecord(context.Background(), rec))

	// Pre-cancelled context: a non-SSTP-aware wait would return immediately.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	resp, status := h.router.SstpServerHandler(ctx, pairId, goSetSstp.Message{}, nil)
	elapsed := time.Since(start)

	assert.Equal(t, 200, status)
	assert.Empty(t, resp.Sets, "no outbound events were queued")
	assert.GreaterOrEqual(t, elapsed, 800*time.Millisecond,
		"long-poll must wait out the buffer timeout despite the cancelled context (Q15)")
}
