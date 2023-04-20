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
}

type EventPollBuffer struct {
	In     chan string
	events []string
	mutex  sync.Mutex

	triggerCondition *sync.Cond
	pollReady        bool
}

// CreateEventPollBuffer is intended to queue up events via an In channel. Events can be subsequently retrieved
// from the buffer using EventPollBuffer.GetEvents()
func CreateEventPollBuffer() *EventPollBuffer {

	buffer := &EventPollBuffer{
		In: make(chan string),
		// Out:    make(chan interface{}),
		events:           []string{},
		mutex:            sync.Mutex{},
		pollReady:        false,
		triggerCondition: sync.NewCond(new(sync.Mutex)),
	}

	go func() {
		for len(buffer.events) > 0 || buffer.In != nil {
			select {
			case v, ok := <-buffer.In:
				if !ok {
					buffer.In = nil
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
		log.Println("Stream buffer closing")
		if len(buffer.events) > 0 {
			log.Printf("WARNING: The following JTIs were not read:\n%v", buffer.events)
		}
	}()

	return buffer
}

func (b *EventPollBuffer) AddEvents(jtis []string) {
	defer b.mutex.Unlock()
	b.mutex.Lock()
	for _, jti := range jtis {
		b.events = append(b.events, jti)
	}
}

func (b *EventPollBuffer) SubmitEvent(jti string) {
	b.In <- jti
}

func (b *EventPollBuffer) IsClosed() bool {
	return b.In == nil
}

func (b *EventPollBuffer) Close() {
	if b.IsClosed() {
		return
	}
	close(b.In)
	b.In = nil
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
				timeout = time.Duration(900)
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
				values = b.events[0 : params.MaxEvents-1]
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
	In          chan interface{}
	Out         chan interface{}
	events      []interface{}
	eventsMutex sync.Mutex
}

// CreateEventPushBuffer creates an input and output channel that allows events to be queued up (using In channel) for a reader
// that is sending events one at a time using the Out channel
func CreateEventPushBuffer(jtis []string) *EventPushBuffer {

	buffer := &EventPushBuffer{
		In:          make(chan interface{}),
		Out:         make(chan interface{}),
		events:      []interface{}{},
		eventsMutex: sync.Mutex{},
	}

	if len(jtis) > 0 {
		buffer.addEvents(jtis)
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
		for len(buffer.events) > 0 || buffer.In != nil {
			select {
			case v, ok := <-buffer.In:
				// log.Printf("DEBUG: incoming JTI: %s", v)
				if !ok {
					buffer.In = nil
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

func (b *EventPushBuffer) addEvents(jtis []string) {
	defer b.eventsMutex.Unlock()
	b.eventsMutex.Lock()
	for _, jti := range jtis {
		b.events = append(b.events, jti)
	}
}

func (b *EventPushBuffer) SubmitEvent(jti string) {
	b.In <- jti
}

func (b *EventPushBuffer) IsClosed() bool {
	return b.In == nil
}

func (b *EventPushBuffer) Close() {
	if b.IsClosed() {
		return
	}
	close(b.In)
	b.In = nil
}