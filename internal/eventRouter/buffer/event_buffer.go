package buffer

import (
	"i2goSignals/internal/model"
	"log"
	"sync"
	"time"
)

type EventBuf interface {
	SubmitEvent(jti string)
	IsClosed() bool
	Close()
	Cnt() int
}

type EventPollBuffer struct {
	in               chan string
	events           []string
	mutex            sync.Mutex
	closed           bool
	triggerCondition *sync.Cond
	pollReady        bool
}

// CreateEventPollBuffer is intended to queue up events via an in channel. Events can be subsequently retrieved
// from the buffer using EventPollBuffer.GetEvents()
func CreateEventPollBuffer(initialJtis []string) *EventPollBuffer {

	buffer := &EventPollBuffer{
		in: make(chan string),
		// Out:    make(chan interface{}),
		events:           []string{},
		mutex:            sync.Mutex{},
		pollReady:        false,
		closed:           false,
		triggerCondition: sync.NewCond(new(sync.Mutex)),
	}
	if len(initialJtis) > 0 {
		buffer.addEvents(initialJtis)
	}

	go func() {
		for len(buffer.events) > 0 || buffer.in != nil {
			select {
			case v, ok := <-buffer.in:
				if !ok {
					buffer.in = nil
				} else {
					// log.Println("DEBUG: incoming JTI: " + v)
					buffer.mutex.Lock()
					buffer.events = append(buffer.events, v)
					buffer.mutex.Unlock()

					buffer.triggerCondition.L.Lock()
					// log.Println("\t\t\tADDING NEW EVENT AND BROADCASTING")
					buffer.triggerCondition.Broadcast()
					buffer.triggerCondition.L.Unlock()
					// log.Println("\t\t\tDONE")
				}
				/*
				   case outCh() <- nextEvent():
				       buffer.events = buffer.events[1:]
				*/
			}
		}

		if len(buffer.events) > 0 {
			log.Printf("WARNING: The following JTIs were not read:\n%v", buffer.events)
		}
	}()

	return buffer
}

func (b *EventPollBuffer) Cnt() float64 {
	return float64(len(b.events))
}

func (b *EventPollBuffer) addEvents(jtis []string) {
	defer b.mutex.Unlock()
	b.mutex.Lock()
	for _, jti := range jtis {
		b.events = append(b.events, jti)
	}
}

func (b *EventPollBuffer) SubmitEvent(jti string) {
	// This avoids a panic. The submitted event will be recovered on restart
	if b.IsClosed() {
		return
	}
	b.in <- jti
}

func (b *EventPollBuffer) IsClosed() bool {
	return b.closed
}

func (b *EventPollBuffer) Close() {
	if b.IsClosed() {
		return
	}
	b.closed = true
	close(b.in)
	b.in = nil
}

func (b *EventPollBuffer) waitForEventTrigger(result chan string) {
	b.triggerCondition.L.Lock()
	// log.Println("\t\t\tWaiting for trigger")
	b.triggerCondition.Wait()
	b.triggerCondition.L.Unlock()
	// log.Println("\t\t\tReceived trigger!!")
	result <- "done"
}

func (b *EventPollBuffer) waitForEventWithTimeout(waitTime time.Duration) {
	result := make(chan string, 1)
	go b.waitForEventTrigger(result)
	select {
	case <-time.After(waitTime):
		// log.Println("\t\t\tEvent wait timed out")
	case <-result:
		// log.Println("\t\t\tReceived event trigger: " + val)
	}
}

// GetEvents returns all events in the buffer and resets the buffer to empty
func (b *EventPollBuffer) GetEvents(params model.PollParameters) (*[]string, bool) {
	if len(b.events) == 0 {
		if params.ReturnImmediately == false {
			timeout := time.Duration(params.TimeoutSecs) * time.Second
			if timeout == 0 {
				timeout = 900 * time.Second
			}
			b.waitForEventWithTimeout(timeout)
		}
	}
	more := false
	var values []string
	defer b.mutex.Unlock()
	b.mutex.Lock()
	eventsAvailable := len(b.events)
	if eventsAvailable == 0 {
		return nil, false
	} else {
		if params.MaxEvents > 0 {
			if eventsAvailable <= int(params.MaxEvents) {
				values = b.events
				b.events = []string{}
			} else {
				more = true
				values = b.events[:params.MaxEvents]
				b.events = b.events[params.MaxEvents:]
			}
		} else {
			values = b.events
			b.events = []string{}
		}
	}

	return &values, more
}

type EventPushBuffer struct {
	in          chan interface{}
	Out         chan interface{}
	events      []interface{}
	eventsMutex sync.Mutex
}

// CreateEventPushBuffer creates an input and output channel that allows events to be queued up (using in channel) for a reader
// that is sending events one at a time using the Out channel
func CreateEventPushBuffer(initialJtis []string) *EventPushBuffer {

	buffer := &EventPushBuffer{
		in:          make(chan interface{}),
		Out:         make(chan interface{}),
		events:      []interface{}{},
		eventsMutex: sync.Mutex{},
	}

	if len(initialJtis) > 0 {
		buffer.addEvents(initialJtis)
	}

	go func() {
		outCh := func() chan interface{} {
			if len(buffer.events) == 0 {
				return nil
			}
			return buffer.Out
		}
		nextEvent := func() interface{} {
			if len(buffer.events) == 0 {
				return nil
			}
			return buffer.events[0]
		}
		for len(buffer.events) > 0 || buffer.in != nil {
			select {
			case v, ok := <-buffer.in:
				// log.Printf("DEBUG: incoming JTI: %s", v)
				if !ok {
					buffer.in = nil
				} else {
					buffer.events = append(buffer.events, v)
				}
			case outCh() <- nextEvent():
				buffer.events = buffer.events[1:]
			}
		}
		close(buffer.Out)
		log.Println("Stream buffer closing")
		if len(buffer.events) > 0 {
			log.Printf("WARNING: The following JTIs were not read:\n%v", buffer.events)
		}
	}()
	return buffer
}

func (b *EventPushBuffer) Cnt() float64 {
	return float64(len(b.events))
}

func (b *EventPushBuffer) addEvents(jtis []string) {
	defer b.eventsMutex.Unlock()
	b.eventsMutex.Lock()
	for _, jti := range jtis {
		b.events = append(b.events, jti)
	}
}

func (b *EventPushBuffer) SubmitEvent(jti string) {
	// To avoid a panic just return. This will be recovered on restart
	if b.IsClosed() {
		return
	}
	b.in <- jti
}

func (b *EventPushBuffer) IsClosed() bool {
	return b.in == nil
}

func (b *EventPushBuffer) Close() {
	if b.IsClosed() {
		return
	}
	close(b.in)
	b.in = nil
}
