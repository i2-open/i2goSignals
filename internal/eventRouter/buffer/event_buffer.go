package buffer

import (
	"sync"
	"time"

	"github.com/i2-open/i2goSignals/pkg/logger"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
)

var bLog = logger.Sub("BUFFER")

type EventBuf interface {
	SubmitEvent(jti string)
	IsClosed() bool
	Close()
	Cnt() int
	Wakeup()
}

type EventPollBuffer struct {
	in        chan string
	events    []string
	mutex     sync.Mutex
	closed    bool
	notifier  chan struct{}
	pollReady bool
}

// CreateEventPollBuffer is intended to queue up events via an in channel. Events can be subsequently retrieved
// from the buffer using EventPollBuffer.GetEvents()
func CreateEventPollBuffer(initialJtis []string) *EventPollBuffer {

	buffer := &EventPollBuffer{
		in:        make(chan string, 100),
		events:    []string{},
		pollReady: false,
		closed:    false,
		notifier:  make(chan struct{}),
	}

	if len(initialJtis) > 0 {
		buffer.addEvents(initialJtis)
	}

	go func() {
		inCh := buffer.in
		for {
			buffer.mutex.Lock()
			if inCh == nil && len(buffer.events) == 0 {
				buffer.mutex.Unlock()
				break
			}
			buffer.mutex.Unlock()

			select {
			case v, ok := <-inCh:
				buffer.mutex.Lock()
				if !ok {
					inCh = nil
				} else {
					buffer.events = append(buffer.events, v)
					if !buffer.closed {
						close(buffer.notifier)
						buffer.notifier = make(chan struct{})
					}
				}
				buffer.mutex.Unlock()
			}
		}

		buffer.mutex.Lock()
		if len(buffer.events) > 0 {
			bLog.Warn("The following JTIs were not read", "jtis", buffer.events)
		}
		buffer.mutex.Unlock()
	}()

	return buffer
}

func (b *EventPollBuffer) Cnt() int {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	return len(b.events)
}

func (b *EventPollBuffer) addEvents(jtis []string) {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	for _, jti := range jtis {
		b.events = append(b.events, jti)
	}
}

func (b *EventPollBuffer) SubmitEvent(jti string) {
	b.mutex.Lock()
	if b.closed {
		b.mutex.Unlock()
		return
	}
	in := b.in
	b.mutex.Unlock()

	defer func() {
		recover()
	}()
	in <- jti
}

func (b *EventPollBuffer) IsClosed() bool {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	return b.closed
}

func (b *EventPollBuffer) Close() {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	if b.closed {
		return
	}
	b.closed = true
	close(b.in)
	close(b.notifier)
}

// Wakeup sends a notification to the buffer to wake up Poller to end the current long poll session (e.g., because of stream state change)
func (b *EventPollBuffer) Wakeup() {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	if b.closed {
		return
	}
	close(b.notifier)
	b.notifier = make(chan struct{})
}

func (b *EventPollBuffer) AckEvents(jtis []string) {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	for _, jti := range jtis {
		for i, e := range b.events {
			if e == jti {
				b.events = append(b.events[:i], b.events[i+1:]...)
				break
			}
		}
	}
}

func (b *EventPollBuffer) Clear() {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	b.events = []string{}
}

// GetEvents returns all events in the buffer. Events remain in buffer until acknowledged.
func (b *EventPollBuffer) GetEvents(params model.PollParameters) (*[]string, bool) {
	b.mutex.Lock()
	if len(b.events) == 0 {
		if params.ReturnImmediately == false {
			timeoutSecs := params.TimeoutSecs
			if timeoutSecs == 0 {
				timeoutSecs = 30
			}
			timeout := time.Duration(timeoutSecs) * time.Second
			notifier := b.notifier
			b.mutex.Unlock()
			select {
			case <-notifier:
			case <-time.After(timeout):
			}
			b.mutex.Lock()
		}
	}

	more := false
	var values []string
	defer b.mutex.Unlock()
	eventsAvailable := len(b.events)
	if eventsAvailable == 0 {
		return nil, false
	}

	if params.MaxEvents > 0 && eventsAvailable > int(params.MaxEvents) {
		more = true
		eventsAvailable = int(params.MaxEvents)
	}
	values = make([]string, eventsAvailable)
	copy(values, b.events[:eventsAvailable])

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
		in:          make(chan interface{}, 100),
		Out:         make(chan interface{}),
		events:      []interface{}{},
		eventsMutex: sync.Mutex{},
	}

	if len(initialJtis) > 0 {
		buffer.addEvents(initialJtis)
	}

	go func() {
		inCh := buffer.in
		for {
			buffer.eventsMutex.Lock()
			var outCh chan interface{}
			var next interface{}
			if len(buffer.events) > 0 {
				outCh = buffer.Out
				next = buffer.events[0]
			}

			if inCh == nil && outCh == nil {
				buffer.eventsMutex.Unlock()
				break
			}
			buffer.eventsMutex.Unlock()

			select {
			case v, ok := <-inCh:
				buffer.eventsMutex.Lock()
				if !ok {
					inCh = nil
				} else {
					buffer.events = append(buffer.events, v)
				}
				buffer.eventsMutex.Unlock()
			case outCh <- next:
				buffer.eventsMutex.Lock()
				buffer.events = buffer.events[1:]
				buffer.eventsMutex.Unlock()
			}
		}
		close(buffer.Out)
		bLog.Info("Stream buffer closing")
		buffer.eventsMutex.Lock()
		if len(buffer.events) > 0 {
			bLog.Warn("The following JTIs were not read", "jtis", buffer.events)
		}
		buffer.eventsMutex.Unlock()
	}()
	return buffer
}

func (b *EventPushBuffer) Cnt() int {
	b.eventsMutex.Lock()
	defer b.eventsMutex.Unlock()
	return len(b.events)
}

func (b *EventPushBuffer) addEvents(jtis []string) {
	b.eventsMutex.Lock()
	defer b.eventsMutex.Unlock()
	for _, jti := range jtis {
		b.events = append(b.events, jti)
	}
}

func (b *EventPushBuffer) SubmitEvent(jti string) {
	b.eventsMutex.Lock()
	in := b.in
	b.eventsMutex.Unlock()

	if in == nil {
		return
	}
	defer func() {
		recover()
	}()
	in <- jti
}

func (b *EventPushBuffer) IsClosed() bool {
	b.eventsMutex.Lock()
	defer b.eventsMutex.Unlock()
	return b.in == nil
}

func (b *EventPushBuffer) Close() {
	b.eventsMutex.Lock()
	defer b.eventsMutex.Unlock()
	if b.in == nil {
		return
	}
	close(b.in)
	b.in = nil
}

func (b *EventPushBuffer) Wakeup() {
	// Not used for push buffer
}
