package eventRouter

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/i2-open/i2goSignals/internal/eventRouter/buffer"
	"github.com/i2-open/i2goSignals/internal/eventRouter/peer"
)

// A well-formed sstp-server wake hands its references to the owner's queue and
// buffer, keeping each re-signed copy's acknowledgement JTI (#363, #365).
func TestHandleWake_WellFormedRefsAreAccepted(t *testing.T) {
	h := newTestRouter(t)
	txSid := "sstp-tx-wake-refs"
	buf := h.router.sstpServerBufferFor(txSid)
	wakeCh := buf.WakeupCh()

	h.router.HandleWake(peer.WakeMessage{Sid: txSid, Mode: peer.ModeSstpServer,
		Jtis:       []string{"j1", "j2"},
		AckJtis:    []string{"a1", "j2"},
		EnqueuedAt: []int64{time.Now().UnixMilli(), 0},
	})

	q := h.router.queueFor(txSid)
	q.mu.Lock()
	require.Len(t, q.refs, 2)
	assert.Equal(t, "a1", q.refs["j1"].ref.AckJti)
	assert.Equal(t, "j2", q.refs["j2"].ref.AckJti)
	q.mu.Unlock()
	assert.Eventually(t, func() bool { return buf.Cnt() == 2 }, time.Second, 5*time.Millisecond,
		"the references reach the buffer (SubmitEvents hands them to its pump)")
	assert.True(t, chanClosed(wakeCh, time.Second), "the wake still wakes the buffer")
}

// A wake whose AckJtis or EnqueuedAt list is not the length of Jtis is a
// reload (#363): no reference is accepted (a re-signed copy's acknowledgement
// JTI cannot be guessed), and the buffer is still woken so the owner reads
// pending.
func TestHandleWake_MismatchedListsAreAReload(t *testing.T) {
	cases := map[string]peer.WakeMessage{
		"ackJtis short":    {Jtis: []string{"j1", "j2"}, AckJtis: []string{"a1"}},
		"ackJtis absent":   {Jtis: []string{"j1", "j2"}},
		"enqueuedAt short": {Jtis: []string{"j1", "j2"}, AckJtis: []string{"a1", "a2"}, EnqueuedAt: []int64{1}},
	}
	for name, msg := range cases {
		for _, mode := range []string{peer.ModeSstpServer, peer.ModePoll} {
			t.Run(name+"/"+mode, func(t *testing.T) {
				h := newTestRouter(t)
				sid := "wake-mismatch"
				buf := h.router.sstpServerBufferFor(sid)
				if mode == peer.ModePoll {
					buf = buffer.CreateEventPollBuffer(nil, 1, 1)
					h.router.mu.Lock()
					h.router.pollBuffers[sid] = buf
					h.router.mu.Unlock()
				}
				wakeCh := buf.WakeupCh()
				msg.Sid, msg.Mode = sid, mode

				h.router.HandleWake(msg)

				q := h.router.queueFor(sid)
				q.mu.Lock()
				assert.Empty(t, q.refs, "a mismatched wake accepts no references")
				q.mu.Unlock()
				assert.True(t, chanClosed(wakeCh, time.Second), "the buffer is still woken to reload")
				assert.Never(t, func() bool { return buf.Cnt() != 0 }, 50*time.Millisecond, 5*time.Millisecond,
					"a mismatched wake submits nothing to the buffer")
			})
		}
	}
}
