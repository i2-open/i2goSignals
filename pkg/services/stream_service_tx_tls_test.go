package services

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestStreamService_TxTLSSkipVerifyFromRequest verifies an explicit
// tx_tls_skip_verify on the create request is persisted onto the stream — the
// field is assembled field-by-field in CreateStream, so without the copy the
// request value would be silently dropped (the original dead-field regression).
func TestStreamService_TxTLSSkipVerifyFromRequest(t *testing.T) {
	svc := newSubjectFilterTestService()
	ctx := context.Background()

	req := pushTransmitterRequest()
	req.StreamConfiguration.TxTLSSkipVerify = true

	created, err := svc.CreateStream(ctx, req, "test-project", nil)
	require.NoError(t, err)

	state, err := svc.GetStreamState(ctx, created.Id)
	require.NoError(t, err)
	assert.True(t, state.StreamConfiguration.TxTLSSkipVerify,
		"an explicit tx_tls_skip_verify on the request must persist onto the stream")
}

// TestStreamService_TxTLSSkipVerifyFromEnv verifies the deployment-wide default:
// with I2SIG_TX_TLS_SKIP_VERIFY truthy, a stream created without the field set
// defaults to skipping receiver TLS verification (dev / conformance receivers).
func TestStreamService_TxTLSSkipVerifyFromEnv(t *testing.T) {
	t.Setenv("I2SIG_TX_TLS_SKIP_VERIFY", "true")
	svc := newSubjectFilterTestService()
	ctx := context.Background()

	created, err := svc.CreateStream(ctx, pushTransmitterRequest(), "test-project", nil)
	require.NoError(t, err)

	state, err := svc.GetStreamState(ctx, created.Id)
	require.NoError(t, err)
	assert.True(t, state.StreamConfiguration.TxTLSSkipVerify,
		"I2SIG_TX_TLS_SKIP_VERIFY must default new streams to skip receiver TLS verification")
}

// TestStreamService_TxTLSSkipVerifyDefaultsOff verifies the safe default: with
// no env and no request value, verification stays on (flag false).
func TestStreamService_TxTLSSkipVerifyDefaultsOff(t *testing.T) {
	svc := newSubjectFilterTestService()
	ctx := context.Background()

	created, err := svc.CreateStream(ctx, pushTransmitterRequest(), "test-project", nil)
	require.NoError(t, err)

	state, err := svc.GetStreamState(ctx, created.Id)
	require.NoError(t, err)
	assert.False(t, state.StreamConfiguration.TxTLSSkipVerify,
		"tx_tls_skip_verify must default to false (verify) absent an env or request value")
}
