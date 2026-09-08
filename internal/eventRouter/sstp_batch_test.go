package eventRouter

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	"github.com/i2-open/i2goSignals/pkg/goSetSstp"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// TestSstpServer_PublishModeSignsWholeBatch: the responder's outbound half
// serves a whole buffered batch in one SSTP response, every SET re-signed
// under the pair's iss/aud through the shared signing pool, and a JTI whose
// record no longer exists is skipped rather than breaking the batch (ADR 0036).
func TestSstpServer_PublishModeSignsWholeBatch(t *testing.T) {
	h := newSstpRunnerHarness(t)
	require.Positive(t, h.router.signConcurrency)

	txSid, rxSid, pairId := "sstp-tx-batch", "sstp-rx-batch", "pair-batch"
	rec := sstpServerPairState(txSid, rxSid, pairId)
	rec.StreamConfiguration.RouteMode = model.RouteModePublish
	rec.StreamConfiguration.Iss = "DEFAULT" // the memory provider's pre-provisioned signing issuer
	require.NoError(t, h.router.streamService.PersistStreamStateRecord(context.Background(), rec))

	jtis := make([]string, 0, 12)
	for i := 0; i < 12; i++ {
		jti := "sstp-batch-" + strings.Repeat("x", i+1)
		h.persistOutboundEvent(t, txSid, jti)
		jtis = append(jtis, jti)
	}
	// Load the outbound buffer directly (like a live wake would) so the drain
	// serves this exact batch, ghost included, without the pending prefetch.
	buf := h.router.sstpServerBufferFor(txSid)
	buf.SubmitEvents(append(append([]string{}, jtis...), "ghost-jti"))
	require.Eventually(t, func() bool { return buf.Cnt() == len(jtis)+1 }, 2*time.Second, 5*time.Millisecond,
		"submitted JTIs must drain into the outbound buffer")

	resolved, err := h.router.streamService.GetStreamStateByPairId(context.Background(), pairId)
	require.NoError(t, err)
	resp := h.router.SstpServerHandler(context.Background(), resolved, goSetSstp.Message{}, nil)

	require.Len(t, resp.Sets, 12, "every real SET is served in one response; the ghost is skipped")
	require.NotContains(t, resp.Sets, "ghost-jti")
	for _, jti := range jtis {
		raw, ok := resp.Sets[jti]
		require.True(t, ok, "jti %s missing from the response", jti)
		require.Equal(t, 3, len(strings.Split(raw, ".")), "each SET is a compact JWS")
		claims := jwt.MapClaims{}
		_, _, err := jwt.NewParser().ParseUnverified(raw, claims)
		require.NoError(t, err)
		require.Equal(t, jti, claims["jti"])
		require.Equal(t, rec.StreamConfiguration.Iss, claims["iss"])
	}
}

// TestResolveSstpEventsByJti_KeepsClaimOrderSkipsMissing: the initiator's
// resolve step reads the claimed batch in one query but hands the records
// back in claim order, dropping a JTI whose record is gone.
func TestResolveSstpEventsByJti_KeepsClaimOrderSkipsMissing(t *testing.T) {
	h := newSstpRunnerHarness(t)
	for _, jti := range []string{"a", "b", "c"} {
		h.persistOutboundEvent(t, "sstp-tx-resolve", jti)
	}

	got := h.router.resolveSstpEventsByJti([]string{"c", "ghost", "a"})

	require.Len(t, got, 2)
	require.Equal(t, "c", got[0].Jti)
	require.Equal(t, "a", got[1].Jti)
	require.Nil(t, h.router.resolveSstpEventsByJti(nil))
}
