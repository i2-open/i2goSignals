package main

import (
	"reflect"
	"testing"
)

func TestPollReceiverBases(t *testing.T) {
	gs1 := "https://gs1:8888"
	if got := pollReceiverBases(gs1, &options{}); !reflect.DeepEqual(got, []string{gs1}) {
		t.Fatalf("default polls goSignals1 only: %v", got)
	}
	if got := pollReceiverBases(gs1, &options{gs1bInternal: "https://gs1b:8887/"}); !reflect.DeepEqual(got, []string{"https://gs1b:8887"}) {
		t.Fatalf("--gs1b-internal moves the one receiver: %v", got)
	}
	o := &options{gs1bInternal: "https://gs1b:8887/", pollTargets: pollTargetsBoth}
	if got := pollReceiverBases(gs1, o); !reflect.DeepEqual(got, []string{gs1, "https://gs1b:8887"}) {
		t.Fatalf("--poll-targets both polls each node: %v", got)
	}
}

func TestValidatePollOptions(t *testing.T) {
	ok := []options{
		{},
		{pollTargets: pollTargetsOne},
		{gs1b: "https://localhost:8887", gs1bInternal: "https://gs1b:8888", pollTargets: pollTargetsBoth},
		{gs1b: "https://localhost:8887", pollPinOwner: true},
	}
	for i, o := range ok {
		if err := validatePollOptions(&o); err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
	}
	bad := []options{
		{pollTargets: "three"},
		{pollTargets: pollTargetsBoth},                                 // no second node
		{gs1b: "https://localhost:8887", pollTargets: pollTargetsBoth}, // no internal URL for it
		{pollPinOwner: true},                                           // nothing to pin the lease on
		{gs1b: "https://localhost:8887", gs1bInternal: "https://gs1b:8888", pollPinOwner: true}, // receiver would poll the owner
		{gs1b: "https://localhost:8887", gs1bInternal: "https://gs1b:8888", pollTargets: pollTargetsBoth, pollPinOwner: true},
	}
	for i, o := range bad {
		if err := validatePollOptions(&o); err == nil {
			t.Fatalf("case %d must be rejected: %+v", i, o)
		}
	}
}

func TestLegDeliveredSumsEveryReceiver(t *testing.T) {
	before := &streamCounters{In: map[string]float64{"rx1": 10, "rx2": 1}}
	now := &streamCounters{In: map[string]float64{"rx1": 40, "rx2": 21}}
	if got := legDelivered(now, before, &legResult{RxStream: "rx1"}); got != 30 {
		t.Fatalf("one receiver: %d", got)
	}
	if got := legDelivered(now, before, &legResult{RxStream: "rx1", RxStream2: "rx2"}); got != 50 {
		t.Fatalf("two receivers: %d", got)
	}
}
