package eventRouter

import (
	"context"
	"testing"

	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/services"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHandleEventCtxResolvesIngressFromRequestMemo proves the plumbing issue
// #287 added, not just the memo it plumbs: HandleEventCtx must resolve the
// ingress stream on the CALLER's context, so the record the push handler (or
// the SSTP-server handler) already resolved is the one the router uses.
//
// The proof is a record that exists ONLY in the memo. If the router honoured
// the caller's context, ingest resolves it and succeeds; if it fell back to its
// own lifetime context, the stream store has never heard of the SID and every
// SET in the batch comes back as an error. The non-ctx entry point is asserted
// alongside it to pin the difference on the context and nothing else.
func TestHandleEventCtxResolvesIngressFromRequestMemo(t *testing.T) {
	h := newTestRouter(t)
	const sid = "memo-only-stream"

	phantom := &model.StreamStateRecord{
		Id:     model.NewRecordId(),
		Status: model.StreamStateEnabled,
		StreamConfiguration: model.StreamConfiguration{
			Id:  sid,
			Iss: "https://issuer.example.com",
			Aud: []string{"https://receiver.example.com"},
		},
	}

	// Baseline: with no memo the SID does not resolve.
	err := h.router.HandleEvent(newRiscToken("memo-baseline", "https://issuer.example.com", "https://receiver.example.com"), `{"raw":0}`, sid)
	require.Error(t, err, "an unknown SID must not resolve without a memo")

	ctx := services.WithRequestStreamCache(context.Background())
	services.SeedRequestStream(ctx, phantom)

	err = h.router.HandleEventCtx(ctx, newRiscToken("memo-ctx", "https://issuer.example.com", "https://receiver.example.com"), `{"raw":1}`, sid)
	assert.NoError(t, err, "HandleEventCtx must resolve the ingress stream on the caller's context")
	assert.NotNil(t, h.router.eventService.GetEventRecord(context.Background(), "memo-ctx"),
		"the SET must have been ingested once the stream resolved")
}

// TestHandleEventsCtxWritesOnTheRouterContext pins the other half of the
// contract: the caller's context resolves the stream and NOTHING else. Ingest
// writes stay on the router's own lifetime context, so a client that hangs up
// mid-request cannot cancel a majority-acked write already in flight.
func TestHandleEventsCtxWritesOnTheRouterContext(t *testing.T) {
	h := newTestRouter(t)
	const sid = "cancelled-request-stream"

	phantom := &model.StreamStateRecord{
		Id:     model.NewRecordId(),
		Status: model.StreamStateEnabled,
		StreamConfiguration: model.StreamConfiguration{
			Id:  sid,
			Iss: "https://issuer.example.com",
			Aud: []string{"https://receiver.example.com"},
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	ctx = services.WithRequestStreamCache(ctx)
	services.SeedRequestStream(ctx, phantom)
	// The request is already gone by the time ingest runs — the shape of a
	// receiver that dropped the connection after sending its SET.
	cancel()

	errs := h.router.HandleEventsCtx(ctx,
		[]*goSet.SecurityEventToken{newRiscToken("cancelled-1", "https://issuer.example.com", "https://receiver.example.com")},
		[]string{`{"raw":0}`}, sid)
	require.Len(t, errs, 1)
	assert.NoError(t, errs[0], "a cancelled request context must not fail the ingest write")
	assert.NotNil(t, h.router.eventService.GetEventRecord(context.Background(), "cancelled-1"),
		"the SET must be durable even though the request context was cancelled")
}
