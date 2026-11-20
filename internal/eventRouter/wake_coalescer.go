package eventRouter

import (
	"sync"
	"time"
)

// WakeCoalesceWindow is the window a cluster wake is coalesced over, on both
// the sending and the receiving node.
const WakeCoalesceWindow = 250 * time.Millisecond

// wakeCoalescerIdle is how long a key may sit unused before it is swept.
const wakeCoalescerIdle = time.Minute

// WakeCoalescer coalesces a burst of wakes for one key into at most one wake
// per window, on both edges (#347). The first wake of a burst fires at once;
// a wake suppressed inside the window arms one trailing wake at the window's
// end, which every further wake in that window shares. A wake says only "this
// target has work", so coalescing on the leading edge alone lost the wake for
// work that arrived just after the first: the trailing wake always follows the
// last wake of a burst.
type WakeCoalescer struct {
	window    time.Duration
	mu        sync.Mutex
	keys      map[string]*wakeKeyState
	lastSweep time.Time
}

type wakeKeyState struct {
	last     time.Time
	trailing bool
}

// NewWakeCoalescer returns a coalescer over window.
func NewWakeCoalescer(window time.Duration) *WakeCoalescer {
	return &WakeCoalescer{window: window, keys: map[string]*wakeKeyState{}, lastSweep: time.Now()}
}

// Admit reports whether the wake for key fires now, the leading edge. When it
// does not, fire is called once at the end of the window, off the caller's
// goroutine, unless a trailing wake is already armed for key.
func (c *WakeCoalescer) Admit(key string, fire func()) bool {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sweepLocked(now)

	st, ok := c.keys[key]
	if !ok || now.Sub(st.last) >= c.window {
		if !ok {
			st = &wakeKeyState{}
			c.keys[key] = st
		}
		st.last = now
		return true
	}
	if !st.trailing {
		st.trailing = true
		time.AfterFunc(st.last.Add(c.window).Sub(now), func() {
			c.mu.Lock()
			st.trailing = false
			st.last = time.Now()
			c.mu.Unlock()
			fire()
		})
	}
	return false
}

// Empty reports whether no key has been admitted (or all have been swept).
func (c *WakeCoalescer) Empty() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.keys) == 0
}

func (c *WakeCoalescer) sweepLocked(now time.Time) {
	if now.Sub(c.lastSweep) < wakeCoalescerIdle {
		return
	}
	c.lastSweep = now
	for k, st := range c.keys {
		if !st.trailing && now.Sub(st.last) >= wakeCoalescerIdle {
			delete(c.keys, k)
		}
	}
}
