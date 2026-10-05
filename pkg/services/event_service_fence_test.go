package services

import (
	"context"
	"errors"
	"testing"
)

// fakeFence is a FenceChecker reporting a fixed lease for every stream.
type fakeFence struct {
	token  int64
	leased bool
	err    error
	calls  int
}

func (f *fakeFence) CurrentFence(streamID string) (string, int64, bool, error) {
	f.calls++
	return "push-transmitter:" + streamID, f.token, f.leased, f.err
}

// TestAck_StaleFencingTokenRejectedBeforeWrite: an ack whose token is not the
// lease's current one is rejected with ErrStaleFencingToken and writes
// nothing, for both AckEvent and AckEvents (#334).
func TestAck_StaleFencingTokenRejectedBeforeWrite(t *testing.T) {
	fake := &fakeEventDAO{pending: map[string]struct{}{"j-1": {}}}
	svc := NewEventService(fake)
	fence := &fakeFence{token: 7, leased: true}
	svc.SetFenceChecker(fence)

	if err := svc.AckEvents(context.Background(), []string{"j-1"}, "s1", 6); !errors.Is(err, ErrStaleFencingToken) {
		t.Fatalf("AckEvents err = %v, want ErrStaleFencingToken", err)
	}
	if err := svc.AckEvent(context.Background(), "j-1", "s1", 6); !errors.Is(err, ErrStaleFencingToken) {
		t.Fatalf("AckEvent err = %v, want ErrStaleFencingToken", err)
	}
	if fake.removePendingManyCalls != 0 || fake.ackCalls != 0 || fake.markDeliveredManyCalls != 0 {
		t.Errorf("stale ack wrote: removePendingMany=%d ack=%d markDeliveredMany=%d",
			fake.removePendingManyCalls, fake.ackCalls, fake.markDeliveredManyCalls)
	}
	if fence.calls != 2 {
		t.Errorf("fence checked %d times, want once per ack call", fence.calls)
	}
}

// TestAck_ExpiredLeaseRejected: a lease that has expired reads as token 0, so
// the former holder's ack is rejected.
func TestAck_ExpiredLeaseRejected(t *testing.T) {
	fake := &fakeEventDAO{pending: map[string]struct{}{"j-1": {}}}
	svc := NewEventService(fake)
	svc.SetFenceChecker(&fakeFence{token: 0, leased: true})

	if err := svc.AckEvents(context.Background(), []string{"j-1"}, "s1", 3); !errors.Is(err, ErrStaleFencingToken) {
		t.Fatalf("AckEvents err = %v, want ErrStaleFencingToken", err)
	}
	if fake.removePendingManyCalls != 0 {
		t.Error("ack on an expired lease must not write")
	}
}

// TestAck_CurrentFencingTokenWrites: the holder's ack with the current token
// is written.
func TestAck_CurrentFencingTokenWrites(t *testing.T) {
	fake := &fakeEventDAO{pending: map[string]struct{}{"j-1": {}}}
	svc := NewEventService(fake)
	svc.SetFenceChecker(&fakeFence{token: 7, leased: true})

	if err := svc.AckEvents(context.Background(), []string{"j-1"}, "s1", 7); err != nil {
		t.Fatalf("AckEvents: %v", err)
	}
	if fake.markDeliveredManyCalls != 1 || len(fake.delivered) != 1 {
		t.Errorf("current-token ack not written: markDeliveredMany=%d delivered=%v", fake.markDeliveredManyCalls, fake.delivered)
	}
}

// TestAck_UnleasedStreamNotFenced: a stream with no lease (poll transmitter,
// SSTP server side) acks with NoFencingToken and is not fenced.
func TestAck_UnleasedStreamNotFenced(t *testing.T) {
	fake := &fakeEventDAO{pending: map[string]struct{}{"j-1": {}}}
	svc := NewEventService(fake)
	svc.SetFenceChecker(&fakeFence{token: 9, leased: false})

	if err := svc.AckEvents(context.Background(), []string{"j-1"}, "s1", NoFencingToken); err != nil {
		t.Fatalf("AckEvents: %v", err)
	}
	if fake.markDeliveredManyCalls != 1 {
		t.Error("unleased ack not written")
	}
}

// TestAck_NoFencingTokenRejectedOnLeasedStream: token 0 is never accepted on
// a leased stream once a coordinator is wired (#334) — the exemption for
// lease-less modes comes from the checker, not from the token.
func TestAck_NoFencingTokenRejectedOnLeasedStream(t *testing.T) {
	fake := &fakeEventDAO{pending: map[string]struct{}{"j-1": {}}}
	svc := NewEventService(fake)
	svc.SetFenceChecker(&fakeFence{token: 7, leased: true})

	if err := svc.AckEvents(context.Background(), []string{"j-1"}, "s1", NoFencingToken); !errors.Is(err, ErrStaleFencingToken) {
		t.Fatalf("AckEvents err = %v, want ErrStaleFencingToken", err)
	}
	if fake.markDeliveredManyCalls != 0 || fake.removePendingManyCalls != 0 {
		t.Error("zero-token ack on a leased stream was written")
	}
}

// TestAck_NoFencingTokenRejectedOnExpiredLease: an expired lease reads as
// token 0; a 0-token ack must not match it.
func TestAck_NoFencingTokenRejectedOnExpiredLease(t *testing.T) {
	fake := &fakeEventDAO{pending: map[string]struct{}{"j-1": {}}}
	svc := NewEventService(fake)
	svc.SetFenceChecker(&fakeFence{token: 0, leased: true})

	if err := svc.AckEvent(context.Background(), "j-1", "s1", NoFencingToken); !errors.Is(err, ErrStaleFencingToken) {
		t.Fatalf("AckEvent err = %v, want ErrStaleFencingToken", err)
	}
	if fake.markDeliveredManyCalls != 0 {
		t.Error("zero-token ack on an expired lease was written")
	}
}

// TestAck_FenceLookupErrorFailsClosed: a checker error is returned and nothing
// is written.
func TestAck_FenceLookupErrorFailsClosed(t *testing.T) {
	boom := errors.New("coordinator down")
	fake := &fakeEventDAO{pending: map[string]struct{}{"j-1": {}}}
	svc := NewEventService(fake)
	svc.SetFenceChecker(&fakeFence{leased: true, err: boom})

	if err := svc.AckEvents(context.Background(), []string{"j-1"}, "s1", 1); !errors.Is(err, boom) {
		t.Fatalf("AckEvents err = %v, want %v", err, boom)
	}
	if fake.removePendingManyCalls != 0 {
		t.Error("ack after a failed fence lookup must not write")
	}
}
