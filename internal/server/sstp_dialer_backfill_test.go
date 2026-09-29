package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/i2-open/i2goSignals/pkg/goSetSstp"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// #347: the cross-node wake is edge-triggered. A wake that lands while every
// second-push slot is held used to be dropped by the slot fast-reject, and the
// outbound SET it announced then waited for the primary long-poll to return
// (the responder's poll timeout, 30 s by default). With the fix, the dropped
// wake is remembered and the dialer's backfill ticker claims the SET within
// one backfill interval of a slot coming free, while the primary is still held.
func TestSstpDialer_DroppedWakeWhileSlotsHeldIsBackfilled(t *testing.T) {
	const (
		pairId   = "pair-dropped-wake"
		txSid    = "tx-dropped-wake"
		interval = 100 * time.Millisecond
	)

	// The peer parks the primary long-poll (returnEvents=true) until the test
	// ends, and acks every second push (returnEvents=false) at once.
	releasePrimary := make(chan struct{})
	var primaryOpen atomic.Int64
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var msg goSetSstp.Message
		if err := json.Unmarshal(raw, &msg); err != nil {
			t.Errorf("bad request body: %v", err)
		}
		acks := make([]string, 0, len(msg.Sets))
		for jti := range msg.Sets {
			acks = append(acks, jti)
		}
		if msg.ReturnEvents == nil || *msg.ReturnEvents {
			primaryOpen.Add(1)
			select {
			case <-releasePrimary:
			case <-r.Context().Done():
			}
			primaryOpen.Add(-1)
		}
		w.Header().Set("Content-Type", goSetSstp.ContentType)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(goSetSstp.Message{Ack: acks})
	}))
	defer peer.Close()

	pair := model.StreamStateRecord{
		StreamConfiguration: model.StreamConfiguration{
			Id:               txSid,
			Iss:              "https://us.example",
			Aud:              []string{"https://peer.example"},
			RouteMode:        model.RouteModeForward,
			TxAllowPlaintext: true, // loopback httptest peer (#322)
		},
		Status: model.StreamStateEnabled,
		PairId: pairId,
		SstpMethod: &model.SstpMethod{
			Role:                model.SstpRoleInitiator,
			EndpointUrl:         peer.URL,
			AuthorizationHeader: "Bearer test-token",
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fake := newFakeSstpOutbound(ctx, pair)
	fake.slotMax = 1

	dialer := NewSstpDialer(&oneShotCoordinator{}, "node-dropped-wake", nil, SstpDialerConfig{
		BaseDelay:        5 * time.Millisecond,
		MaxDelay:         50 * time.Millisecond,
		BackoffFactor:    2.0,
		Jitter:           func() time.Duration { return 0 },
		HTTPClient:       &http.Client{Timeout: 10 * time.Second},
		BackfillInterval: interval,
	})
	dialer.Bind(fake)

	cycleDone := make(chan struct{})
	go func() {
		defer close(cycleDone)
		delay := 5 * time.Millisecond
		dialer.runPrimaryCycleWithSecondPush(ctx, &pair, 1, &delay, sstpPendingFeedback{})
	}()
	defer func() {
		close(releasePrimary)
		<-cycleDone
	}()
	require.Eventually(t, func() bool { return primaryOpen.Load() == 1 }, 5*time.Second, 5*time.Millisecond,
		"the primary long-poll is held by the peer")

	// Every second-push slot is held elsewhere (another push in flight).
	require.True(t, fake.AcquireSecondPushSlot(pairId))

	const jti = "sstp-dropped-wake-1"
	fake.mu.Lock()
	fake.events[jti] = &model.EventRecord{Jti: jti, Original: `{"jti":"` + jti + `","raw":true}`}
	fake.mu.Unlock()
	fake.wake <- struct{}{}

	// The wake is consumed and turned away by the slot guard.
	require.Eventually(t, func() bool { return len(fake.wake) == 0 }, time.Second, time.Millisecond)
	time.Sleep(2 * interval)
	assert.Empty(t, fake.ackedCopy(), "nothing can be pushed while the slot is held")

	fake.ReleaseSecondPushSlot(pairId)
	released := time.Now()

	require.Eventually(t, func() bool { return len(fake.ackedCopy()) == 1 }, 3*interval, 5*time.Millisecond,
		"the SET announced by the dropped wake is claimed within the backfill interval")
	assert.Less(t, time.Since(released), 3*interval)
	assert.Equal(t, int64(1), primaryOpen.Load(), "delivered while the primary long-poll is still held")
}
