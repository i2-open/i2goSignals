package buffer

import (
	"fmt"
	"i2goSignals/internal/model"
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

func TestCreateEventPushBuffer(t *testing.T) {
	buffer := CreateEventPushBuffer([]string{})
	lastVal := -1
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		for v := range buffer.Out {
			vi := v.(int)
			fmt.Println(fmt.Sprintf("Jti received: %d", vi))
			if lastVal+1 != vi {
				t.Errorf("Unexpected value; expeded %d, got %d", lastVal+1, vi)
			}
			lastVal = vi
		}
		wg.Done()
		fmt.Println("Finished reading")
	}()

	for i := 0; i < 100; i++ {
		fmt.Println("Writing: ", i)
		buffer.In <- i
	}
	close(buffer.In)
	fmt.Println("Finished writing")
	wg.Wait()
	if lastVal != 99 {
		t.Errorf("Didn't get all values. Last received was %d", lastVal)
	}
}

func TestCreateEventPollBuffer(t *testing.T) {
	buffer := CreateEventPollBuffer()
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
		buffer.In <- testVals[i]
	}
	buffer.Close()
	fmt.Println("Finished writing")
	wg.Wait()
	if testVals[99] != receiveVals[99] {
		t.Errorf("Didn't get all values. Last received was %s", lastVal)
	}
}

func TestCreateEventPollBufferAdvanced(t *testing.T) {
	buffer := CreateEventPollBuffer()

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

		buffer.In <- testVals[i]
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

func TestCreateEventPollBufferFast(t *testing.T) {
	buffer := CreateEventPollBuffer()

	var wg sync.WaitGroup
	testSize := 10000

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

		buffer.In <- testVals[i]
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
