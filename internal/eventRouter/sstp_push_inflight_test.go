package eventRouter

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// #339 (ADR 0044): I2SIG_SSTP_PUSH_INFLIGHT is K, the push-while-poll-held
// batches one SSTP-client pair keeps in flight.
func TestSstpPushInFlight_DefaultAndOverride(t *testing.T) {
	t.Setenv("I2SIG_SSTP_PUSH_INFLIGHT", "")
	assert.Equal(t, 2, sstpPushInFlight(256, 100), "default: 256 / 100")
	assert.Equal(t, 1, sstpPushInFlight(64, 100), "never below one slot")
	assert.Equal(t, maxSstpPushInFlight, sstpPushInFlight(4096, 100), "capped")

	t.Setenv("I2SIG_SSTP_PUSH_INFLIGHT", "1")
	assert.Equal(t, 1, sstpPushInFlight(256, 100), "K=1 is the Q7.2 single slot")
	t.Setenv("I2SIG_SSTP_PUSH_INFLIGHT", "8")
	assert.Equal(t, 8, sstpPushInFlight(256, 100))
	t.Setenv("I2SIG_SSTP_PUSH_INFLIGHT", "zero")
	assert.Equal(t, 2, sstpPushInFlight(256, 100), "an invalid value falls back to the default")
}

func TestSstpSecondPushSlots_BoundedByK(t *testing.T) {
	for _, k := range []int{1, 3} {
		r := &router{sstpSecondPushInFlight: map[string]int{}, sstpPushInFlightMax: k}
		for i := 0; i < k; i++ {
			assert.True(t, r.acquireSstpSecondPushSlot("pair"), "K=%d slot %d", k, i+1)
		}
		assert.False(t, r.acquireSstpSecondPushSlot("pair"), "K=%d: all slots held", k)
		assert.True(t, r.acquireSstpSecondPushSlot("other"), "slots are per pair")

		r.releaseSstpSecondPushSlot("pair")
		assert.True(t, r.acquireSstpSecondPushSlot("pair"), "a released slot is reusable")
		for i := 0; i < k; i++ {
			r.releaseSstpSecondPushSlot("pair")
		}
		_, present := r.sstpSecondPushInFlight["pair"]
		assert.False(t, present, "an idle pair leaves no entry behind")
	}
}
