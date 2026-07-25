package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/i2-open/i2goSignals/pkg/goSetSstp"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A peer may ship queued outbound SETs on ANY 200, including the response to a
// returnEvents=false second push. pushWhilePollHeld ingests those, but it runs
// in its own goroutine while the pair loop holds its pending feedback as a value
// it cannot touch — so the feedback used to be computed and thrown away. The
// peer therefore never learned we had taken the SETs, its outbound never cleared
// them, and it resent them every cycle forever: exactly the infinite-resend loop
// the setErr/ack carriage exists to break (code-review finding on spec #247).
func TestPushWhilePollHeld_DefersInboundFeedbackForTheNextRequest(t *testing.T) {
	const (
		pairId       = "pair-second-push-feedback"
		txSid        = "tx-second-push-feedback"
		peerIssuer   = "https://peer.issuer.example"
		peerAudience = "https://us.example"
		responseKid  = "peer-kid-second-push"
		responseJti  = "sstp-second-push-response-1"
	)

	peerKey, err := rsaTestKey()
	require.NoError(t, err)
	jwks := makeGivenJwks(t, responseKid, &peerKey.PublicKey)
	responseToken := signResponseSet(t, peerKey, responseKid, peerIssuer, peerAudience, responseJti)

	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var msg goSetSstp.Message
		require.NoError(t, json.Unmarshal(raw, &msg))
		// The second push declines long-polling but the peer answers with a
		// queued SET anyway — permitted by §2.1 and the case this test pins.
		resp := goSetSstp.Message{
			Ack:  []string{"sstp-outbound-second-push"},
			Sets: map[string]string{responseJti: responseToken},
		}
		w.Header().Set("Content-Type", goSetSstp.ContentType)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer peer.Close()

	pair := model.StreamStateRecord{
		StreamConfiguration: model.StreamConfiguration{
			Id:        txSid,
			Iss:       "https://us.example",
			Aud:       []string{peerIssuer},
			RouteMode: model.RouteModeForward,
		},
		SstpInbound: &model.StreamConfiguration{
			Id:  "rx-sid-second-push",
			Iss: peerIssuer,
			Aud: []string{peerAudience},
		},
		Status: model.StreamStateEnabled,
		PairId: pairId,
		SstpMethod: &model.SstpMethod{
			Role:                model.SstpRoleInitiator,
			EndpointUrl:         peer.URL,
			AuthorizationHeader: "Bearer test-token",
		},
	}
	ev := &model.EventRecord{
		Jti:      "sstp-outbound-second-push",
		Original: `{"jti":"sstp-outbound-second-push","raw":true}`,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fake := newFakeSstpOutbound(ctx, pair, ev)
	fake.verifyCfg = goSetSstp.VerifyConfig{
		JWKS:              jwks,
		ExpectedIssuer:    peerIssuer,
		ExpectedAudiences: []string{peerAudience},
		RequireSignature:  true,
	}

	dialer := NewSstpDialer(&oneShotCoordinator{}, "node-second-push", nil, SstpDialerConfig{
		BaseDelay:     5 * time.Millisecond,
		MaxDelay:      50 * time.Millisecond,
		BackoffFactor: 2.0,
		Jitter:        func() time.Duration { return 0 },
		HTTPClient:    &http.Client{Timeout: 2 * time.Second},
		BackfillBatch: 10,
	})
	dialer.Bind(fake)

	// Drive the second push directly: the wake-driven spawn is the pair loop's
	// concern, and this is the goroutine whose feedback was being dropped.
	cls := dialer.pushWhilePollHeld(ctx, &pair, 1)
	require.Equal(t, goSetSstp.ClassOK, cls.Class)

	require.Len(t, fake.ingestedCopy(), 1, "the response SET must still be ingested")

	deferred := dialer.takeDeferredFeedback(pairId)
	assert.Equal(t, []string{responseJti}, deferred.Acks,
		"the second push's ack must be deferred for the pair loop's next request")

	assert.True(t, dialer.takeDeferredFeedback(pairId).empty(),
		"taking the deferred feedback must hand it over exactly once")
}

// The store must survive several second pushes before the pair loop drains it,
// and must not accumulate duplicates.
func TestDeferredFeedback_AccumulatesUntilTaken(t *testing.T) {
	d := NewSstpDialer(&oneShotCoordinator{}, "node-defer", nil, SstpDialerConfig{})

	d.deferFeedback("pair-a", sstpPendingFeedback{Acks: []string{"jti-1"}})
	d.deferFeedback("pair-a", sstpPendingFeedback{Acks: []string{"jti-1", "jti-2"}})
	d.deferFeedback("pair-a", sstpPendingFeedback{
		SetErrs: map[string]goSetSstp.SetErr{"jti-3": {Err: goSetSstp.ErrCodeInvalidRequest}},
	})
	d.deferFeedback("pair-b", sstpPendingFeedback{Acks: []string{"other-pair"}})

	got := d.takeDeferredFeedback("pair-a")
	assert.Equal(t, []string{"jti-1", "jti-2"}, got.Acks, "a repeated ack must not be carried twice")
	assert.Len(t, got.SetErrs, 1)
	assert.Contains(t, got.SetErrs, "jti-3")

	assert.Equal(t, []string{"other-pair"}, d.takeDeferredFeedback("pair-b").Acks,
		"the store is per-pair")
}

// Empty feedback must not create an entry — the common case is a second push
// whose response carried no SETs at all.
func TestDeferredFeedback_EmptyIsNotStored(t *testing.T) {
	d := NewSstpDialer(&oneShotCoordinator{}, "node-defer-empty", nil, SstpDialerConfig{})

	d.deferFeedback("pair-a", sstpPendingFeedback{})

	d.deferredMu.Lock()
	defer d.deferredMu.Unlock()
	assert.Empty(t, d.deferred, "empty feedback must not allocate a per-pair entry")
}

// A removed pair's feedback has nobody left to carry it and must not leak.
func TestDeferredFeedback_DroppedOnUnregister(t *testing.T) {
	d := NewSstpDialer(&oneShotCoordinator{}, "node-defer-drop", nil, SstpDialerConfig{})

	d.deferFeedback("pair-gone", sstpPendingFeedback{Acks: []string{"jti-1"}})
	d.UnregisterPair("pair-gone")

	assert.True(t, d.takeDeferredFeedback("pair-gone").empty(),
		"UnregisterPair must drop the pair's deferred feedback")
}

// merge is what folds the deferred value into the loop's carried one; acks
// de-duplicate and setErrs union.
func TestPendingFeedback_Merge(t *testing.T) {
	carried := sstpPendingFeedback{
		Acks:    []string{"jti-1", "jti-2"},
		SetErrs: map[string]goSetSstp.SetErr{"jti-bad": {Err: goSetSstp.ErrCodeInvalidRequest}},
	}

	carried.merge(sstpPendingFeedback{
		Acks:    []string{"jti-2", "jti-3"},
		SetErrs: map[string]goSetSstp.SetErr{"jti-worse": {Err: goSetSstp.ErrSetParse}},
	})

	assert.Equal(t, []string{"jti-1", "jti-2", "jti-3"}, carried.Acks,
		"acks must de-duplicate and keep order")
	assert.Len(t, carried.SetErrs, 2)
	assert.Contains(t, carried.SetErrs, "jti-bad")
	assert.Contains(t, carried.SetErrs, "jti-worse")
}

// Merging into a zero value must allocate rather than panic on the nil map.
func TestPendingFeedback_MergeIntoZeroValue(t *testing.T) {
	var carried sstpPendingFeedback

	carried.merge(sstpPendingFeedback{
		Acks:    []string{"jti-1"},
		SetErrs: map[string]goSetSstp.SetErr{"jti-bad": {Err: goSetSstp.ErrCodeInvalidRequest}},
	})

	assert.Equal(t, []string{"jti-1"}, carried.Acks)
	assert.Contains(t, carried.SetErrs, "jti-bad")
	assert.False(t, carried.empty())
}
