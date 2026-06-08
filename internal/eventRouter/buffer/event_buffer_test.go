package buffer

import (
	"fmt"
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/i2-open/i2goSignals/pkg/dao/ids"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"

	"github.com/stretchr/testify/assert"
)

func TestCreateEventPushBuffer(t *testing.T) {
	testSize := 100
	testVals := make([]string, testSize)
	receiveVals := make([]string, testSize)
	for i := 0; i < testSize; i++ {
		testVals[i] = ids.NewObjectID()
	}
	buffer := CreateEventPushBuffer(testVals[:2])

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		i := -1
		for v := range buffer.Out {
			i++
			jti := v.(string)
			fmt.Println(fmt.Sprintf("Jti received: %s", jti))
			if jti != testVals[i] {
				t.Errorf("Unexpected value; expected %s, got %s", testVals[i], jti)
			}
			receiveVals[i] = jti
		}
		wg.Done()
		fmt.Println("Finished reading")
	}()

	for i := 2; i < 100; i++ {
		fmt.Println("Writing: ", i)
		buffer.SubmitEvent(testVals[i])
	}
	buffer.Close()
	fmt.Println("Finished writing")
	wg.Wait()
	for i := 0; i < testSize; i++ {
		if testVals[i] != receiveVals[i] {
			t.Errorf("Didn't match values. %s <-> %s", testVals[i], receiveVals[i])
			break
		}
	}
}

func TestCreateEventPollBuffer(t *testing.T) {
	buffer := CreateEventPollBuffer([]string{}, 30, 300)
	lastVal := "EMPTY"
	var wg sync.WaitGroup

	testVals := make([]string, 100)
	for i := 0; i < 100; i++ {
		testVals[i] = ids.NewObjectID()
	}
	receiveVals := make([]string, 100)
	wg.Add(1)
	go func() {
		i := 0
		for i < 100 {
			jtis, _ := buffer.GetEvents(model.PollParameters{ReturnImmediately: true})
			if jtis != nil {
				buffer.AckEvents(*jtis)
				for _, v := range *jtis {
					if i < 100 {
						lastVal = v
						receiveVals[i] = v
						fmt.Println(fmt.Sprintf("Received multi-event %d jti: %s", i, lastVal))
						i++
					}
				}
			}
			if i >= 100 {
				break
			}
			if buffer.IsClosed() {
				// If closed, wait a bit to ensure all events are moved from 'in' channel to 'events'
				time.Sleep(10 * time.Millisecond)
				// Check one last time
				jtis, _ = buffer.GetEvents(model.PollParameters{ReturnImmediately: true})
				if jtis == nil {
					break
				}
			} else {
				time.Sleep(time.Duration(rand.Intn(5)) * time.Millisecond)
			}
		}
		wg.Done()
		fmt.Println("Finished reading")
	}()

	for i := 0; i < 100; i++ {
		fmt.Println(fmt.Sprintf("Writing event #%d: %s", i, testVals[i]))
		buffer.in <- testVals[i]
	}
	buffer.Close()
	fmt.Println("Finished writing")
	wg.Wait()
	assert.True(t, buffer.IsClosed(), "Buffer should be closed")
	if testVals[99] != receiveVals[99] {
		t.Errorf("Didn't get all values. Last received was %s", lastVal)
	}
}

func TestCreateEventPollBufferAdvanced(t *testing.T) {
	buffer := CreateEventPollBuffer([]string{}, 30, 300)

	var wg sync.WaitGroup
	testSize := 100

	testVals := make([]string, testSize)
	for i := 0; i < 100; i++ {
		testVals[i] = ids.NewObjectID()
	}
	receiveVals := make([]string, testSize)
	noVals := false
	oneVal := false
	manyVals := false
	wg.Add(1)
	go func() {
		i := 0
		for !buffer.IsClosed() && i < testSize {
			// Introduce random time element in to allow for multi-events
			time.Sleep(time.Duration(rand.Intn(100)) * time.Millisecond)
			jtis, _ := buffer.GetEvents(model.PollParameters{ReturnImmediately: false, TimeoutSecs: 1})
			if jtis == nil {
				fmt.Println("No events available!")
				noVals = true
				continue
			} else {
				buffer.AckEvents(*jtis)
				cnt := len(*jtis)
				fmt.Printf("%d events returned\n", cnt)
				if cnt == 1 {
					oneVal = true
				} else if cnt > 1 {
					manyVals = true
				}
			}
			for _, v := range *jtis {
				if i < testSize {
					receiveVals[i] = v
					i++
				}
			}
		}
		assert.Equal(t, testSize, i, "Expected result size matches")
		assert.True(t, oneVal, "At least one result had a single value")
		assert.True(t, noVals, "At least one result had no values (timeout)")
		assert.True(t, manyVals, "At least one result returned multiple values")
		fmt.Println("Finished reading")
		wg.Done()

	}()

	for i := 0; i < testSize; i++ {
		fmt.Println(fmt.Sprintf("Writing event #%d: %s", i, testVals[i]))
		switch i {
		case 25:
			fmt.Println("No DELAY")
			// no delay
		case 50:
			fmt.Println("LONG DELAY")
			// long wait
			time.Sleep(2000 * time.Millisecond)
		default:
			time.Sleep(time.Duration(rand.Intn(100)) * time.Millisecond)
		}

		buffer.in <- testVals[i]
	}

	wg.Wait()
	buffer.Close()
	fmt.Println("Finished writing")

	for i := 0; i < testSize; i++ {
		if testVals[i] != receiveVals[i] {
			t.Errorf("Didn't match values. %s <-> %s", testVals[i], receiveVals[i])
			break
		}
	}
}

func TestCreateEventPollBufferOptions(t *testing.T) {
	testSize := 10

	testVals := make([]string, testSize)
	for i := 0; i < testSize; i++ {
		testVals[i] = ids.NewObjectID()
	}

	initialJtis := testVals[0:4]

	buffer := CreateEventPollBuffer(initialJtis, 30, 300)

	jtis, more := buffer.GetEvents(model.PollParameters{
		ReturnImmediately: false,
		MaxEvents:         2,
		TimeoutSecs:       0})
	assert.Equal(t, 2, len(*jtis), "Should be 2 results")
	assert.Equal(t, true, more, "should be more results")
	buffer.AckEvents(*jtis)

	jtis, more = buffer.GetEvents(model.PollParameters{
		ReturnImmediately: true,
		MaxEvents:         0,
		TimeoutSecs:       5})
	assert.Equal(t, 2, len(*jtis), "Should be 2 results")
	assert.Equal(t, false, more, "should be NO more results")
	buffer.AckEvents(*jtis)

	jtis, more = buffer.GetEvents(model.PollParameters{
		ReturnImmediately: true,
		MaxEvents:         0,
		TimeoutSecs:       5})
	assert.Nil(t, jtis, "Should be NIL results")
	assert.Equal(t, false, more, "should be NO more results")

	for i := 4; i < 10; i++ {
		buffer.SubmitEvent(testVals[i])
	}
	time.Sleep(100 * time.Millisecond) // Wait for async processing
	jtis, more = buffer.GetEvents(model.PollParameters{
		ReturnImmediately: true,
		MaxEvents:         1000,
		TimeoutSecs:       5})
	assert.Greater(t, len(*jtis), 2, "Should be several results")
	assert.Equal(t, false, more, "should be NO more results")
	buffer.AckEvents(*jtis)

	go func() {
		time.Sleep(time.Second)
		buffer.SubmitEvent(testVals[0])
		buffer.SubmitEvent(testVals[1])
	}()

	jtis, more = buffer.GetEvents(model.PollParameters{
		ReturnImmediately: false,
		MaxEvents:         0,
		TimeoutSecs:       0})
	assert.NotNil(t, jtis)
	assert.True(t, len(*jtis) > 0, "Should be a results")

	assert.False(t, buffer.IsClosed())
	buffer.Close()
	assert.True(t, buffer.IsClosed())
}

func TestCreateEventPollBufferFast(t *testing.T) {
	buffer := CreateEventPollBuffer([]string{}, 30, 300)

	var wg sync.WaitGroup
	testSize := 1000

	testVals := make([]string, testSize)
	for i := 0; i < testSize; i++ {
		testVals[i] = ids.NewObjectID()
	}
	receiveVals := make([]string, testSize)
	// noVals := false
	oneVal := false
	manyVals := false
	wg.Add(1)
	go func() {
		i := 0
		for !buffer.IsClosed() && i < testSize {
			// Introduce random time element in to allow for multi-events
			if rand.Intn(10) == 1 {
				fmt.Println("READ DELAY")
				time.Sleep(time.Duration(rand.Intn(100)) * time.Millisecond)
			}
			jtis, _ := buffer.GetEvents(model.PollParameters{ReturnImmediately: false, TimeoutSecs: 1})
			if jtis == nil {
				fmt.Println("Received NO events")
				// noVals = true
				continue
			} else {
				buffer.AckEvents(*jtis)
				cnt := len(*jtis)
				fmt.Printf("Received %d events\n", cnt)
				if cnt > 1 {
					manyVals = true
				} else if cnt == 1 {
					oneVal = true
				}
			}
			for _, v := range *jtis {
				if i < testSize {
					receiveVals[i] = v
					i++
				}
			}

		}
		assert.Equal(t, testSize, i, "Expected result size matches")
		assert.True(t, oneVal, "At least one result had a single value")
		// assert.True(t, noVals, "At least one result had no values (timeout)")
		assert.True(t, manyVals, "At least one result returned multiple values")
		fmt.Println("Finished reading")
		wg.Done()

	}()

	for i := 0; i < testSize; i++ {
		// fmt.Println(fmt.Sprintf("Writing event #%d: %s", i, testVals[i]))
		switch {
		case i > 50 && i < 100:
			// no delay

		case i == 150:
			fmt.Println("WRITE LONG DELAY")
			// long wait
			time.Sleep(200 * time.Millisecond)
		default:
			time.Sleep(time.Duration(rand.Intn(5)) * time.Millisecond)
			// random delay
		}
		buffer.SubmitEvent(testVals[i])
	}
	fmt.Println("Finished writing")

	wg.Wait()
	buffer.Close()

	for i := 0; i < testSize; i++ {
		if testVals[i] != receiveVals[i] {
			t.Errorf("Didn't match values. %s <-> %s", testVals[i], receiveVals[i])
			break
		}
	}

}

func TestEventPollBuffer_Wakeup(t *testing.T) {
	buffer := CreateEventPollBuffer([]string{}, 30, 300)

	start := time.Now()

	// Start a goroutine that will wake up the buffer after 500ms
	go func() {
		time.Sleep(500 * time.Millisecond)
		buffer.Wakeup()
	}()

	jtis, more := buffer.GetEvents(model.PollParameters{
		ReturnImmediately: false,
		TimeoutSecs:       5, // 5 seconds timeout
	})

	elapsed := time.Since(start)

	assert.Nil(t, jtis)
	assert.False(t, more)
	assert.True(t, elapsed < 1*time.Second, "GetEvents should have returned early, took %v", elapsed)
}

// TestEventPollBuffer_DefaultTimeoutSecsAppliedWhenZero verifies that when a
// receiver omits timeoutSecs (sends 0), the buffer uses the per-buffer
// configured default rather than a package-internal constant.
func TestEventPollBuffer_DefaultTimeoutSecsAppliedWhenZero(t *testing.T) {
	// Configure a 1-second default. If the configured default is NOT being
	// applied and the old 30s hard-coded fallback is still in force, the
	// elapsed time will be ~30s rather than ~1s (test would also fail to
	// compile against the old 1-arg signature, which is the point of the
	// tracer bullet).
	buffer := CreateEventPollBuffer([]string{}, 1, 300)
	defer buffer.Close()

	start := time.Now()
	jtis, more := buffer.GetEvents(model.PollParameters{
		ReturnImmediately: false,
		TimeoutSecs:       0, // receiver omitted timeoutSecs
	})
	elapsed := time.Since(start)

	assert.Nil(t, jtis, "no events in buffer, should return nil")
	assert.False(t, more)
	assert.GreaterOrEqual(t, elapsed, 900*time.Millisecond,
		"buffer should have waited approximately the configured default (1s), got %v", elapsed)
	assert.Less(t, elapsed, 2*time.Second,
		"buffer should not have waited longer than the configured default + slack, got %v", elapsed)
}

// TestEventPollBuffer_ReceiverTimeoutSecsInRangeHonouredExactly verifies that a
// receiver-supplied timeoutSecs > 0 and <= max is honoured unchanged. The
// configured default and max should not interfere.
func TestEventPollBuffer_ReceiverTimeoutSecsInRangeHonouredExactly(t *testing.T) {
	// default=30 (would be obviously visible if it leaked in), max=300.
	buffer := CreateEventPollBuffer([]string{}, 30, 300)
	defer buffer.Close()

	start := time.Now()
	jtis, more := buffer.GetEvents(model.PollParameters{
		ReturnImmediately: false,
		TimeoutSecs:       1, // receiver-supplied, in-range
	})
	elapsed := time.Since(start)

	assert.Nil(t, jtis)
	assert.False(t, more)
	assert.GreaterOrEqual(t, elapsed, 900*time.Millisecond,
		"buffer should have waited approximately the receiver-supplied 1s, got %v", elapsed)
	assert.Less(t, elapsed, 2*time.Second,
		"buffer should not have waited the 30s default; receiver value was supplied, got %v", elapsed)
}

// TestEventPollBuffer_ReceiverTimeoutSecsExceedingMaxClampedSilently verifies
// that a receiver-supplied timeoutSecs greater than the configured max is
// silently clamped to max. RFC8936 §2.4 makes timeoutSecs a SHOULD, so the
// clamp is spec-compliant; no error is returned, no per-request log emitted.
func TestEventPollBuffer_ReceiverTimeoutSecsExceedingMaxClampedSilently(t *testing.T) {
	// max=1 makes the clamped wait observable in a second-scale test.
	buffer := CreateEventPollBuffer([]string{}, 30, 1)
	defer buffer.Close()

	start := time.Now()
	jtis, more := buffer.GetEvents(model.PollParameters{
		ReturnImmediately: false,
		TimeoutSecs:       60, // receiver-supplied, exceeds max
	})
	elapsed := time.Since(start)

	assert.Nil(t, jtis)
	assert.False(t, more)
	assert.GreaterOrEqual(t, elapsed, 900*time.Millisecond,
		"buffer should have waited approximately the clamped max (1s), got %v", elapsed)
	assert.Less(t, elapsed, 2*time.Second,
		"buffer should not have waited the un-clamped 60s, got %v", elapsed)
}

// TestEventPollBuffer_NotifierPreemptsClampedDeadline verifies that even when
// timeoutSecs is clamped, an event arriving before the clamped deadline is
// delivered. Confirms the clamp does not suppress wake-up notifications.
func TestEventPollBuffer_NotifierPreemptsClampedDeadline(t *testing.T) {
	buffer := CreateEventPollBuffer([]string{}, 30, 2) // clamp to 2s
	defer buffer.Close()

	jti := ids.NewObjectID()
	go func() {
		time.Sleep(150 * time.Millisecond)
		buffer.SubmitEvent(jti)
	}()

	start := time.Now()
	jtis, _ := buffer.GetEvents(model.PollParameters{
		ReturnImmediately: false,
		TimeoutSecs:       60, // will be clamped to 2
	})
	elapsed := time.Since(start)

	assert.NotNil(t, jtis, "event submitted before clamped deadline should be delivered")
	if jtis != nil {
		assert.Equal(t, 1, len(*jtis))
		assert.Equal(t, jti, (*jtis)[0])
	}
	assert.Less(t, elapsed, 1500*time.Millisecond,
		"buffer should have returned on notifier well before the 2s clamped deadline, got %v", elapsed)
}

// TestEventPollBuffer_MaxTimeoutZeroDisablesClamp verifies that a max of 0
// disables clamping entirely — the operator escape hatch documented in
// POLL_MAX_TIMEOUT=0. Receiver-supplied timeoutSecs is honoured as given.
func TestEventPollBuffer_MaxTimeoutZeroDisablesClamp(t *testing.T) {
	buffer := CreateEventPollBuffer([]string{}, 30, 0) // cap disabled
	defer buffer.Close()

	// We don't want to actually wait 100s. Submit a Wakeup after 150ms and
	// observe that no premature clamp fired in the meantime — the call
	// returns on the Wakeup rather than on a clamp-imposed timer.
	go func() {
		time.Sleep(150 * time.Millisecond)
		buffer.Wakeup()
	}()

	start := time.Now()
	jtis, _ := buffer.GetEvents(model.PollParameters{
		ReturnImmediately: false,
		TimeoutSecs:       100, // way above any plausible clamp
	})
	elapsed := time.Since(start)

	assert.Nil(t, jtis, "no events submitted, expected nil")
	assert.GreaterOrEqual(t, elapsed, 100*time.Millisecond,
		"buffer must have actually waited (not clamped to 0), got %v", elapsed)
	assert.Less(t, elapsed, 1*time.Second,
		"buffer returned on Wakeup well before any clamped deadline, got %v", elapsed)
}

// TestEventPollBuffer_DefaultZeroPlusReceiverZeroReturnsImmediately verifies
// the operator escape hatch POLL_DEFAULT_TIMEOUT=0: when both the configured
// default and the receiver-supplied timeoutSecs are zero, GetEvents returns
// immediately even with ReturnImmediately=false (i.e. no implicit long-poll).
func TestEventPollBuffer_DefaultZeroPlusReceiverZeroReturnsImmediately(t *testing.T) {
	buffer := CreateEventPollBuffer([]string{}, 0, 300) // default disabled
	defer buffer.Close()

	start := time.Now()
	jtis, more := buffer.GetEvents(model.PollParameters{
		ReturnImmediately: false,
		TimeoutSecs:       0,
	})
	elapsed := time.Since(start)

	assert.Nil(t, jtis)
	assert.False(t, more)
	assert.Less(t, elapsed, 100*time.Millisecond,
		"buffer should have returned immediately, got %v", elapsed)
}
