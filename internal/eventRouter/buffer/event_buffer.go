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
	WakeupCh() <-chan struct{}
}

type EventPollBuffer struct {
	in        chan string
	events    []string
	mutex     sync.Mutex
	closed    bool
	notifier  chan struct{}
	pollReady bool
	// defaultTimeoutSecs is the long-poll timeout applied when a receiver
	// omits timeoutSecs (sends 0). 0 means "no implicit long-poll" — return
	// immediately on empty buffer when ReturnImmediately is false and
	// TimeoutSecs is 0.
	defaultTimeoutSecs int
	// maxTimeoutSecs caps receiver-supplied timeoutSecs. 0 disables the cap.
	maxTimeoutSecs int
}

// CreateEventPollBuffer queues up events via an in channel; subsequently
// retrieved via EventPollBuffer.GetEvents(). The two timeout parameters
// govern long-poll behaviour for this buffer: defaultTimeoutSecs is applied
// when a receiver omits timeoutSecs, and maxTimeoutSecs (>0) caps receiver
// requests. See docs/configuration_properties.md
// (I2SIG_POLL_DEFAULT_TIMEOUT, I2SIG_POLL_MAX_TIMEOUT) for the wired-up env vars.
func CreateEventPollBuffer(initialJtis []string, defaultTimeoutSecs, maxTimeoutSecs int) *EventPollBuffer {

	buffer := &EventPollBuffer{
		in:                 make(chan string, 100),
		events:             []string{},
		pollReady:          false,
		closed:             false,
		notifier:           make(chan struct{}),
		defaultTimeoutSecs: defaultTimeoutSecs,
		maxTimeoutSecs:     maxTimeoutSecs,
	}

	if len(initialJtis) > 0 {
		buffer.addEvents(initialJtis)
	}

	// Capture buffer.in on the spawning goroutine so the read sequences
	// before the `go` statement (program-order happens-before to the
	// spawned goroutine). Close() later writes buffer.in = nil under the
	// mutex; the spawned goroutine works against the captured channel
	// rather than re-reading buffer.in without synchronisation.
	inCh := buffer.in

	go func() {
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

// resolveTimeoutSecs applies the per-buffer default+max policy to a
// receiver-supplied timeoutSecs. Result <=0 means "return immediately".
//
//   - requested == 0: apply defaultTimeoutSecs (may itself be 0, meaning
//     no implicit long-poll).
//   - requested > 0 and maxTimeoutSecs > 0 and requested > maxTimeoutSecs:
//     silently clamp to maxTimeoutSecs (RFC8936 §2.4 makes timeoutSecs a
//     SHOULD, so clamping is spec-compliant).
//   - maxTimeoutSecs == 0: cap disabled; honour receiver value as given.
//   - requested < 0: treat as 0 (defensive; PollParameters typing makes
//     this unreachable in practice).
func (b *EventPollBuffer) resolveTimeoutSecs(requested int) int {
	if requested <= 0 {
		return b.defaultTimeoutSecs
	}
	if b.maxTimeoutSecs > 0 && requested > b.maxTimeoutSecs {
		return b.maxTimeoutSecs
	}
	return requested
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
	b.SubmitEvents([]string{jti})
}

func (b *EventPollBuffer) SubmitEvents(jtis []string) {
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
	for _, jti := range jtis {
		in <- jti
	}
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

func (b *EventPollBuffer) WakeupCh() <-chan struct{} {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	return b.notifier
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
			timeoutSecs := b.resolveTimeoutSecs(params.TimeoutSecs)
			if timeoutSecs <= 0 {
				// Empty buffer, no implicit long-poll: return immediately.
				defer b.mutex.Unlock()
				return nil, false
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
	wakeup      chan struct{}
	events      []interface{}
	eventsMutex sync.Mutex
}

// CreateEventPushBuffer creates an input and output channel that allows events to be queued up (using in channel) for a reader
// that is sending events one at a time using the Out channel
func CreateEventPushBuffer(initialJtis []string) *EventPushBuffer {

	buffer := &EventPushBuffer{
		in:          make(chan interface{}, 100),
		Out:         make(chan interface{}),
		wakeup:      make(chan struct{}, 1),
		events:      []interface{}{},
		eventsMutex: sync.Mutex{},
	}

	if len(initialJtis) > 0 {
		for _, jti := range initialJtis {
			buffer.events = append(buffer.events, jti)
		}
	}

	// Capture buffer.in on the spawning goroutine; see the matching note
	// in CreateEventPollBuffer for the happens-before reasoning.
	inCh := buffer.in

	go func() {
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

			if outCh != nil {
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
			} else {
				v, ok := <-inCh
				buffer.eventsMutex.Lock()
				if !ok {
					inCh = nil
				} else {
					buffer.events = append(buffer.events, v)
				}
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
	b.SubmitEvents([]string{jti})
}

func (b *EventPushBuffer) SubmitEvents(jtis []string) {
	b.eventsMutex.Lock()
	in := b.in
	b.eventsMutex.Unlock()

	if in == nil {
		return
	}
	defer func() {
		recover()
	}()
	for _, jti := range jtis {
		in <- jti
	}
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
	select {
	case b.wakeup <- struct{}{}:
	default:
	}
}

func (b *EventPushBuffer) WakeupCh() <-chan struct{} {
	return b.wakeup
}
