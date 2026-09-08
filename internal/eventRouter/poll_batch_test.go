package eventRouter

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// concurrencyProbe is a SignSets sign func that holds each call for
// `hold` and records the peak number of overlapping calls (ADR 0036).
type concurrencyProbe struct {
	mu       sync.Mutex
	inflight int
	peak     int
	hold     time.Duration
	failJti  string
}

func (p *concurrencyProbe) sign(rec *model.EventRecord) (string, error) {
	p.mu.Lock()
	p.inflight++
	if p.inflight > p.peak {
		p.peak = p.inflight
	}
	p.mu.Unlock()

	time.Sleep(p.hold)

	p.mu.Lock()
	p.inflight--
	p.mu.Unlock()
	if rec.Jti == p.failJti {
		return "", errors.New("boom")
	}
	return "jws:" + rec.Jti, nil
}

func probeRecords(n int) []*model.EventRecord {
	recs := make([]*model.EventRecord, n)
	for i := range recs {
		recs[i] = &model.EventRecord{Jti: fmt.Sprintf("jti-%d", i)}
	}
	return recs
}

// TestSignSets_FansOutInInputOrder: a pool of four signs more than one
// SET at a time, never more than four, and the results line up with the input.
func TestSignSets_FansOutInInputOrder(t *testing.T) {
	recs := probeRecords(12)
	probe := &concurrencyProbe{hold: 20 * time.Millisecond}

	out := SignSets(recs, 4, probe.sign)

	require.Len(t, out, len(recs))
	for i, rec := range recs {
		require.NoError(t, out[i].Err)
		require.Equal(t, "jws:"+rec.Jti, out[i].JWS)
	}
	require.LessOrEqual(t, probe.peak, 4, "pool never exceeds the configured concurrency")
	require.GreaterOrEqual(t, probe.peak, 2, "pool actually signs side by side (peak %d)", probe.peak)
}

// TestSignSets_ConcurrencyOneIsSerial: I2SIG_SIGN_CONCURRENCY=1 never
// overlaps two signatures, and a failed signature is reported in its slot
// without disturbing the others.
func TestSignSets_ConcurrencyOneIsSerial(t *testing.T) {
	recs := probeRecords(5)
	probe := &concurrencyProbe{hold: 2 * time.Millisecond, failJti: "jti-2"}

	out := SignSets(recs, 1, probe.sign)

	require.Equal(t, 1, probe.peak)
	require.Error(t, out[2].Err)
	require.Empty(t, out[2].JWS)
	for _, i := range []int{0, 1, 3, 4} {
		require.NoError(t, out[i].Err)
		require.Equal(t, "jws:"+recs[i].Jti, out[i].JWS)
	}
}

// TestPollBatch_ResignsWholeBatch: a PUBLISH-mode poll stream serves a whole
// buffered batch from one poll, every SET re-signed under the stream's
// iss/aud, and a JTI whose record no longer exists is skipped rather than
// breaking the batch.
func TestPollBatch_ResignsWholeBatch(t *testing.T) {
	h := newFilterPushRouter(t)
	require.Positive(t, h.router.signConcurrency)

	stream := h.createPollStream(t, model.DefaultSubjectsAll)
	stream.StreamConfiguration.RouteMode = model.RouteModePublish
	h.router.UpdateStreamState(stream)
	sid := stream.StreamConfiguration.Id

	jtis := h.addPendingEvents(t, sid, 12)
	h.loadPollBuffer(t, sid, append(jtis, "ghost-jti")...)

	sets, status := h.pollImmediate(sid)
	require.Equal(t, 200, status)
	require.Len(t, sets, 12, "every real SET is served in one poll; the ghost is skipped")
	require.NotContains(t, sets, "ghost-jti")

	for _, jti := range jtis {
		raw, ok := sets[jti]
		require.True(t, ok, "jti %s missing from the response", jti)
		require.Equal(t, 3, len(strings.Split(raw, ".")), "each SET is a compact JWS")
		claims := jwt.MapClaims{}
		_, _, err := jwt.NewParser().ParseUnverified(raw, claims)
		require.NoError(t, err)
		require.Equal(t, jti, claims["jti"])
		require.Equal(t, stream.StreamConfiguration.Iss, claims["iss"])
	}
}
