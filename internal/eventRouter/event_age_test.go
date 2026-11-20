package eventRouter

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ageSample reads the event-age histogram's count and sum for one transfer type.
func ageSample(t *testing.T, h *prometheus.HistogramVec, tfr string) (uint64, float64) {
	t.Helper()
	var m dto.Metric
	require.NoError(t, h.WithLabelValues(tfr).(prometheus.Histogram).Write(&m))
	return m.GetHistogram().GetSampleCount(), m.GetHistogram().GetSampleSum()
}

// TestIncrementCounter_ObservesEventAgeAtReceipt: an inbound SET carrying a toe
// is observed into the event-age histogram under the receiving stream's
// transfer type, so the bench can read per-leg delivery latency (#325).
func TestIncrementCounter_ObservesEventAgeAtReceipt(t *testing.T) {
	h := newTestRouter(t)
	labels := []string{"type", "iss", "tfr", "stream_id"}
	h.router.SetEventCounter(
		prometheus.NewCounterVec(prometheus.CounterOpts{Name: "test_age_in_total", Help: "test"}, labels),
		prometheus.NewCounterVec(prometheus.CounterOpts{Name: "test_age_out_total", Help: "test"}, labels),
	)
	age := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "test_event_age_at_receipt_seconds",
		Help:    "test",
		Buckets: prometheus.ExponentialBucketsRange(0.001, 30, 16),
	}, []string{"tfr"})
	h.router.SetEventAgeHistogram(age)

	streams := map[string]*model.StreamStateRecord{
		"PUSH": {StreamConfiguration: model.StreamConfiguration{Id: "push-rx", Delivery: &model.OneOfStreamConfigurationDelivery{
			PushReceiveMethod: &model.PushReceiveMethod{Method: model.ReceivePush}}}},
		"POLL": {StreamConfiguration: model.StreamConfiguration{Id: "poll-rx", Delivery: &model.OneOfStreamConfigurationDelivery{
			PollReceiveMethod: &model.PollReceiveMethod{Method: model.ReceivePoll}}}},
		"SSTP": {SstpMethod: &model.SstpMethod{Role: model.SstpRoleResponder},
			StreamConfiguration: model.StreamConfiguration{Id: "sstp-pair"}},
	}
	for tfr, stream := range streams {
		token := &goSet.SecurityEventToken{
			RegisteredClaims: jwt.RegisteredClaims{Issuer: "https://bench.example", ID: tfr},
			TimeOfEvent:      &jwt.NumericDate{Time: time.Now().Add(-50 * time.Millisecond)},
		}
		h.router.IncrementCounter(stream, token, true)

		count, sum := ageSample(t, age, tfr)
		assert.Equal(t, uint64(1), count, "%s leg observed once", tfr)
		assert.GreaterOrEqual(t, sum, 0.05, "%s age covers the 50ms since toe", tfr)
		assert.Less(t, sum, 5.0, "%s age is not wildly off", tfr)
	}

	// A SET with no toe, and an outbound SET, are not observed.
	h.router.IncrementCounter(streams["PUSH"], &goSet.SecurityEventToken{}, true)
	h.router.IncrementCounter(streams["PUSH"], &goSet.SecurityEventToken{
		TimeOfEvent: &jwt.NumericDate{Time: time.Now()}}, false)
	count, _ := ageSample(t, age, "PUSH")
	assert.Equal(t, uint64(1), count, "no-toe and outbound SETs are skipped")
}
