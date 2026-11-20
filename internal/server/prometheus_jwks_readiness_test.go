package server

import (
	"context"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/i2-open/i2goSignals/pkg/dao/memory"
	"github.com/i2-open/i2goSignals/pkg/services"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// collectStreamMetrics runs the streamCollector and returns every emitted
// metric, so a test can assert on the series an operator would scrape.
func collectStreamMetrics(t *testing.T, sa *SignalsApplication) []*dto.Metric {
	t.Helper()
	ch := make(chan prometheus.Metric, 128)
	newStreamCollector(sa).Collect(ch)
	close(ch)

	var out []*dto.Metric
	for m := range ch {
		d := &dto.Metric{}
		if err := m.Write(d); err != nil {
			t.Fatalf("write metric: %v", err)
		}
		d.Label = append(d.Label, &dto.LabelPair{
			Name:  metricNamePtr("__name__"),
			Value: metricNamePtr(m.Desc().String()),
		})
		out = append(out, d)
	}
	return out
}

func metricNamePtr(s string) *string { return &s }

// labelValue returns the value of the named label on a metric, or "".
func labelValue(m *dto.Metric, name string) string {
	for _, l := range m.Label {
		if l.GetName() == name {
			return l.GetValue()
		}
	}
	return ""
}

// jwksReadinessSeries filters the collected metrics down to the readiness gauge.
func jwksReadinessSeries(metrics []*dto.Metric) []*dto.Metric {
	var out []*dto.Metric
	for _, m := range metrics {
		if strings.Contains(labelValue(m, "__name__"), "goSignals_router_stream_jwks_readiness_info") {
			out = append(out, m)
		}
	}
	return out
}

// newMetricsApplication builds an admin-shaped application over in-memory DAOs —
// enough for the stream collector, which only reads StreamService.
func newMetricsApplication(t *testing.T) (*SignalsApplication, *services.StreamService) {
	t.Helper()
	keyService := services.NewKeyService(memory.NewKeyDAO(), "DEFAULT", nil, nil)
	if err := keyService.InitializeTokenKey(context.Background(), "DEFAULT"); err != nil {
		t.Fatalf("InitializeTokenKey: %v", err)
	}
	streamService := services.NewStreamService(memory.NewStreamDAO(), keyService, "DEFAULT", services.StreamServiceConfig{})
	sa := NewAdminApplication(AdminAppDeps{
		StreamService: streamService,
		KeyService:    keyService,
		Auth:          keyService.GetAuthIssuer(),
		DefIssuer:     "DEFAULT",
	})
	return sa, streamService
}

// TestStreamCollector_ExportsJwksReadinessGauge: ADR 0033 puts readiness on a
// per-stream Prometheus gauge beside the existing error gauge, because stream
// Status deliberately keeps reporting "enabled" for a stream that cannot verify
// anything. Without the gauge the only signal an unresolvable receiver produces
// is a single startup log line.
func TestStreamCollector_ExportsJwksReadinessGauge(t *testing.T) {
	sa, streamService := newMetricsApplication(t)
	ctx := context.Background()

	id := model.NewRecordId()
	rec := &model.StreamStateRecord{
		Id:        id,
		ProjectId: "proj-metrics",
		StreamConfiguration: model.StreamConfiguration{
			Id:            id.Hex(),
			Iss:           "https://tx.example",
			IssuerJWKSUrl: "http://127.0.0.1:1/jwks.json", // refuses connections
			Delivery: &model.OneOfStreamConfigurationDelivery{
				PushReceiveMethod: &model.PushReceiveMethod{Method: model.ReceivePush},
			},
		},
		Status: model.StreamStateEnabled,
	}
	if err := streamService.PersistStreamStateRecord(ctx, rec); err != nil {
		t.Fatalf("persist: %v", err)
	}
	streamService.LoadReceiverStreams(ctx)

	series := jwksReadinessSeries(collectStreamMetrics(t, sa))
	if len(series) != 1 {
		t.Fatalf("got %d readiness series, want exactly 1 for one receiver stream", len(series))
	}
	m := series[0]
	if got := labelValue(m, "stream_id"); got != id.Hex() {
		t.Errorf("stream_id = %q, want %q", got, id.Hex())
	}
	if got := labelValue(m, "readiness"); got != model.JwksReadinessUnresolved {
		t.Errorf("readiness = %q, want %q", got, model.JwksReadinessUnresolved)
	}
	if got := labelValue(m, "direction"); got != "receive" {
		t.Errorf("direction = %q, want %q", got, "receive")
	}
	if m.GetGauge().GetValue() != 1 {
		t.Errorf("gauge value = %v, want 1 (info-gauge idiom, matching the existing error gauge)",
			m.GetGauge().GetValue())
	}
}

// TestStreamCollector_NoReadinessSeriesForTransmitOnlyStreams: readiness
// describes a RECEIVE direction's verification material. A transmit-only stream
// has none, so emitting a series for it would be noise an operator could
// mistake for a fault.
func TestStreamCollector_NoReadinessSeriesForTransmitOnlyStreams(t *testing.T) {
	sa, streamService := newMetricsApplication(t)
	ctx := context.Background()

	id := model.NewRecordId()
	rec := &model.StreamStateRecord{
		Id:        id,
		ProjectId: "proj-metrics",
		StreamConfiguration: model.StreamConfiguration{
			Id:  id.Hex(),
			Iss: "DEFAULT",
			Delivery: &model.OneOfStreamConfigurationDelivery{
				PushTransmitMethod: &model.PushTransmitMethod{Method: model.DeliveryPush},
			},
		},
		Status: model.StreamStateEnabled,
	}
	if err := streamService.PersistStreamStateRecord(ctx, rec); err != nil {
		t.Fatalf("persist: %v", err)
	}

	if series := jwksReadinessSeries(collectStreamMetrics(t, sa)); len(series) != 0 {
		t.Errorf("got %d readiness series for a transmit-only stream, want 0", len(series))
	}
}
