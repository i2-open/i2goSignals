package main

import (
	"errors"
	"fmt"
	"strings"
	"time"

	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// --poll-targets values (#366, for #367's POLL leg). A node takes a poll
// stream's poll-transmitter lease on first touch and keeps it, so a receiver
// that polls one node only ever polls the owner and the non-owner poll path
// (a peer claim) never runs.
const (
	pollTargetsOne  = "one"  // one goSignals2 receiver, at goSignals1 (or --gs1b-internal)
	pollTargetsBoth = "both" // one goSignals2 receiver per node, so polls land on both
)

// validatePollOptions checks --poll-targets and --poll-pin-owner against the
// second-node flags.
func validatePollOptions(o *options) error {
	switch o.pollTargets {
	case "", pollTargetsOne:
	case pollTargetsBoth:
		if o.gs1b == "" || o.gs1bInternal == "" {
			return errors.New("--poll-targets both needs --gs1b and --gs1b-internal")
		}
	default:
		return fmt.Errorf("--poll-targets must be %q or %q, got %q", pollTargetsOne, pollTargetsBoth, o.pollTargets)
	}
	if o.pollPinOwner {
		if o.gs1b == "" {
			return errors.New("--poll-pin-owner needs --gs1b")
		}
		if o.gs1bInternal != "" || o.pollTargets == pollTargetsBoth {
			return errors.New("--poll-pin-owner points the receiver at goSignals1 only; drop --gs1b-internal and --poll-targets both")
		}
	}
	return nil
}

// pollReceiverBases is the base URL of each goSignals2 poll receiver the run
// creates: goSignals1 and the --gs1b node with --poll-targets both, otherwise
// the single receiverLegBase.
func pollReceiverBases(gs1Internal string, o *options) []string {
	if o.pollTargets == pollTargetsBoth {
		return []string{gs1Internal, strings.TrimRight(o.gs1bInternal, "/")}
	}
	return []string{receiverLegBase(gs1Internal, o.gs1bInternal)}
}

// legDelivered is what goSignals2 counted on the leg's receiver streams.
func legDelivered(now, before *streamCounters, leg *legResult) int {
	n := now.In[leg.RxStream] - before.In[leg.RxStream]
	if leg.RxStream2 != "" {
		n += now.In[leg.RxStream2] - before.In[leg.RxStream2]
	}
	return int(n)
}

// pinPollOwner makes gs1b the poll-transmitter lease owner of txPoll before
// any receiver exists (--poll-pin-owner): it waits for gs1b to register the
// stream, then polls it once from the harness. The queue is empty, so the
// poll returns no events; it only takes the lease, which gs1b then renews.
// goSignals2 then polls goSignals1, a non-owner, for the whole leg.
func pinPollOwner(gs1b *node, txPoll *model.StreamConfiguration, o *options) error {
	if _, err := gs1b.waitForStreams([]string{txPoll.Id}, o.gs1bSyncTimeout, 500*time.Millisecond); err != nil {
		return fmt.Errorf("--poll-pin-owner: %w", err)
	}
	_, path, err := splitEndpoint(txPoll.Delivery.PollTransmitMethod.EndpointUrl)
	if err != nil {
		return err
	}
	req := map[string]any{"maxEvents": 1, "returnImmediately": true}
	if err := gs1b.doJSON("POST", path, txPoll.Delivery.PollTransmitMethod.AuthorizationHeader, req, nil, 200); err != nil {
		return fmt.Errorf("--poll-pin-owner: %w", err)
	}
	logf("poll-transmitter lease of %s taken by %s (pinned owner)", txPoll.Id, gs1b.name)
	return nil
}
