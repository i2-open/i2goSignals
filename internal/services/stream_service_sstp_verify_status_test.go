package services

import (
	"context"
	"testing"

	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGetStatus_SstpTxSideReturnsOutboundStatus: GET /status?stream_id=<txSid>
// returns Status+ErrorMsg for an SSTP record. (Q41)
func TestGetStatus_SstpTxSideReturnsOutboundStatus(t *testing.T) {
	svc, rec := createdPair(t)
	svc.UpdateStreamStatus(context.Background(), rec.StreamConfiguration.Id, model.StreamStatePause, "tx throttled")

	got, err := svc.GetStatus(context.Background(), rec.StreamConfiguration.Id)
	require.NoError(t, err)
	assert.Equal(t, model.StreamStatePause, got.Status)
	assert.Equal(t, "tx throttled", got.Reason)
}

// TestGetStatus_SstpRxSideReturnsInboundStatus: GET /status?stream_id=<rxSid>
// returns InboundStatus+InboundErrorMsg for the same record. (Q41)
func TestGetStatus_SstpRxSideReturnsInboundStatus(t *testing.T) {
	svc, rec := createdPair(t)
	svc.UpdateStreamStatus(context.Background(), rec.SstpInbound.Id, model.StreamStatePause, "rx throttled")

	got, err := svc.GetStatus(context.Background(), rec.SstpInbound.Id)
	require.NoError(t, err)
	assert.Equal(t, model.StreamStatePause, got.Status)
	assert.Equal(t, "rx throttled", got.Reason)
}

// TestGetStatus_SstpRxSideDistinctFromTxSide: the two directions report
// independently — naming the rx SID must not leak the tx Status. (Q41)
func TestGetStatus_SstpRxSideDistinctFromTxSide(t *testing.T) {
	svc, rec := createdPair(t)
	svc.UpdateStreamStatus(context.Background(), rec.StreamConfiguration.Id, model.StreamStatePause, "tx throttled")

	// rx side untouched -> still enabled, no reason
	got, err := svc.GetStatus(context.Background(), rec.SstpInbound.Id)
	require.NoError(t, err)
	assert.Equal(t, model.StreamStateEnabled, got.Status)
	assert.Empty(t, got.Reason)
}

// TestGetStreamConfigBySID_SstpTxSide: verify (Q40) resolves the outbound side
// of the named direction. Naming the tx SID returns the primary direction's
// StreamConfiguration (its iss/aud scope the generated verify SET).
func TestGetStreamConfigBySID_SstpTxSide(t *testing.T) {
	svc, rec := createdPair(t)

	cfg, err := svc.GetStreamConfigBySID(context.Background(), rec.StreamConfiguration.Id)
	require.NoError(t, err)
	require.NotNil(t, cfg)
	assert.Equal(t, rec.StreamConfiguration.Id, cfg.Id)
	assert.Equal(t, rec.StreamConfiguration.Iss, cfg.Iss)
	assert.Equal(t, rec.StreamConfiguration.Aud, cfg.Aud)
}

// TestGetStreamConfigBySID_SstpRxSide: naming the rx SID resolves the inbound
// direction's StreamConfiguration so a verify against the rx side scopes to the
// inbound iss/aud rather than 404ing. (Q40)
func TestGetStreamConfigBySID_SstpRxSide(t *testing.T) {
	svc, rec := createdPair(t)

	cfg, err := svc.GetStreamConfigBySID(context.Background(), rec.SstpInbound.Id)
	require.NoError(t, err)
	require.NotNil(t, cfg)
	assert.Equal(t, rec.SstpInbound.Id, cfg.Id)
	assert.Equal(t, rec.SstpInbound.Iss, cfg.Iss)
	assert.Equal(t, rec.SstpInbound.Aud, cfg.Aud)
}

// TestStateListing_SstpPairCarriesPairIdAndBothDirections: the flat /states
// listing source (GetStateMap) surfaces an SSTP pair as a single record that
// carries PairId plus both the outbound (StreamConfiguration) and inbound
// (SstpInbound) directions, so goSignalsAdmin / cmd/goSignals can expand it into
// two rows and group by PairId client-side — no new /pairs endpoint. (Q36)
func TestStateListing_SstpPairCarriesPairIdAndBothDirections(t *testing.T) {
	svc, rec := createdPair(t)

	stateMap := svc.GetStateMap(context.Background())
	got, ok := stateMap[rec.StreamConfiguration.Id]
	require.True(t, ok, "SSTP pair must appear in the flat state listing keyed by its tx SID")

	assert.Equal(t, rec.PairId, got.PairId, "listing row must carry PairId for client-side grouping")
	assert.NotEmpty(t, got.PairId)
	// Outbound (tx) direction.
	assert.Equal(t, rec.StreamConfiguration.Id, got.StreamConfiguration.Id)
	// Inbound (rx) direction is present on the same record so the client can
	// render the rxSid as a second row.
	require.NotNil(t, got.SstpInbound, "listing row must carry the inbound direction")
	assert.Equal(t, rec.SstpInbound.Id, got.SstpInbound.Id)
	assert.NotEqual(t, got.StreamConfiguration.Id, got.SstpInbound.Id, "tx and rx SIDs must be distinct rows")
}

// TestGetStreamConfigBySID_NonSstp: a plain (non-SSTP) stream resolves through
// the same helper unchanged.
func TestGetStreamConfigBySID_NonSstp(t *testing.T) {
	svc, _ := sstpFixture(t)
	plain := &model.StreamStateRecord{
		StreamConfiguration: model.StreamConfiguration{
			Id:  "plain-sid-1",
			Iss: "http://transmitter.example",
			Aud: []string{"http://receiver.example"},
		},
		Status: model.StreamStateEnabled,
	}
	require.NoError(t, svc.PersistStreamStateRecord(context.Background(), plain))

	cfg, err := svc.GetStreamConfigBySID(context.Background(), plain.StreamConfiguration.Id)
	require.NoError(t, err)
	require.NotNil(t, cfg)
	assert.Equal(t, plain.StreamConfiguration.Id, cfg.Id)
}
