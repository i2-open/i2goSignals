package buffer

import (
	"fmt"
	"github.com/independentid/i2goSignals/internal/model"
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

func TestCreateEventPushBuffer(t *testing.T) {
	testSize := 100
	testVals := make([]string, testSize)
	receiveVals := make([]string, testSize)
	for i := 0; i < testSize; i++ {
		testVals[i] = primitive.NewObjectID().Hex()
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
	buffer := CreateEventPollBuffer([]string{})
	lastVal := "EMPTY"
	var wg sync.WaitGroup

	testVals := make([]string, 100)
	for i := 0; i < 100; i++ {
		testVals[i] = primitive.NewObjectID().Hex()
	}
	receiveVals := make([]string, 100)
	wg.Add(1)
	go func() {
		i := 0
		for !buffer.IsClosed() {
			// Introduce random time element in to allow for multi-events
			time.Sleep(time.Duration(rand.Intn(5)) * time.Millisecond)
			jtis, _ := buffer.GetEvents(model.PollParameters{ReturnImmediately: true})
			for _, v := range *jtis {
				lastVal = v
				receiveVals[i] = v
				fmt.Println(fmt.Sprintf("Received multi-event %d jti: %s", i, lastVal))
				i++
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
	assert.True(t, buffer.IsClosed(), "Buffer should be closed")
	fmt.Println("Finished writing")
	wg.Wait()
	if testVals[99] != receiveVals[99] {
		t.Errorf("Didn't get all values. Last received was %s", lastVal)
	}
}

func TestCreateEventPollBufferAdvanced(t *testing.T) {
	buffer := CreateEventPollBuffer([]string{})

	var wg sync.WaitGroup
	testSize := 100

	testVals := make([]string, testSize)
	for i := 0; i < 100; i++ {
		testVals[i] = primitive.NewObjectID().Hex()
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
				cnt := len(*jtis)
				fmt.Printf("%d events returned\n", cnt)
				if cnt == 1 {
					oneVal = true
				} else if cnt > 1 {
					manyVals = true
				}
			}
			for _, v := range *jtis {

				receiveVals[i] = v
				// fmt.Println(fmt.Sprintf("Received #%d: jti: %s", i, lastVal))
				i++
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
		testVals[i] = primitive.NewObjectID().Hex()
	}

	initialJtis := testVals[0:4]

	buffer := CreateEventPollBuffer(initialJtis)

	jtis, more := buffer.GetEvents(model.PollParameters{
		ReturnImmediately: false,
		MaxEvents:         2,
		TimeoutSecs:       0})
	assert.Equal(t, 2, len(*jtis), "Should be 2 results")
	assert.Equal(t, true, more, "should be more results")

	jtis, more = buffer.GetEvents(model.PollParameters{
		ReturnImmediately: true,
		MaxEvents:         0,
		TimeoutSecs:       5})
	assert.Equal(t, 2, len(*jtis), "Should be 2 results")
	assert.Equal(t, false, more, "should be NO more results")

	jtis, more = buffer.GetEvents(model.PollParameters{
		ReturnImmediately: true,
		MaxEvents:         0,
		TimeoutSecs:       5})
	assert.Nil(t, jtis, "Should be NIL results")
	assert.Equal(t, false, more, "should be NO more results")

	for i := 4; i < 10; i++ {
		buffer.SubmitEvent(testVals[i])
	}
	jtis, more = buffer.GetEvents(model.PollParameters{
		ReturnImmediately: true,
		MaxEvents:         1000,
		TimeoutSecs:       5})
	assert.Greater(t, len(*jtis), 2, "Should be several results")
	assert.Equal(t, false, more, "should be NO more results")

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
	buffer := CreateEventPollBuffer([]string{})

	var wg sync.WaitGroup
	testSize := 1000

	testVals := make([]string, testSize)
	for i := 0; i < 100; i++ {
		testVals[i] = primitive.NewObjectID().Hex()
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
				cnt := len(*jtis)
				fmt.Printf("Received %d events\n", cnt)
				if cnt > 1 {
					manyVals = true
				} else if cnt == 1 {
					oneVal = true
				}
			}
			for _, v := range *jtis {
				receiveVals[i] = v
				// fmt.Println(fmt.Sprintf("Received #%d: jti: %s", i, lastVal))
				i++
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
