package goSetSstp

import "sort"

// SetErrDisposition is the SENDER-side partition of the per-JTI setErrs a peer
// returned: one bucket per SetErrClass verdict, so a caller executes the ADR-0040
// policy without re-deriving it. This is the consumer face of ClassifySetErr —
// the classifier answers "what kind of rejection is this", this answers "what do
// I do with my outbound buffer".
//
// The distinction matters because outbound bookkeeping is literal-ack: a JTI the
// sender clears is gone forever. Clearing every rejection regardless of code
// turns a peer-side JWKS rotation race into permanent, silent event loss with
// the stream still reporting healthy.
type SetErrDisposition struct {
	// Clear are the JTIs to remove from the outbound buffer: a REGISTERED
	// ClassSetErrNonRetryable code, where the rejection will not heal by
	// resending the same bytes. Leaving one pending would be an unbounded
	// claim/sign/POST/reject/release loop.
	//
	// Unregistered codes are deliberately NOT here — see Unrecognized.
	Clear []string

	// Retry are the JTIs to LEAVE pending (ClassSetErrRetryable): a JWKS refresh
	// or key-rotation settling can make the very same SET acceptable, so the
	// sender re-sends it on a later cycle rather than dropping the event.
	Retry []string

	// Fatal are the JTIs rejected with a stream-fatal verdict
	// (ClassSetErrStreamFatal — currently only ProblemBindingRevoked). The stream
	// itself is dead; every subsequent send is rejected the same way, so the
	// sender stops the direction rather than draining its queue into the void.
	Fatal []string

	// Unrecognized are the JTIs whose err string is in NEITHER half of the
	// registry — a vendor URI, a transient condition a peer invented, or a
	// future SSTP §2.3 keyword. Like Retry they are LEFT PENDING.
	//
	// ClassifySetErr resolves these to ClassSetErrNonRetryable by default-deny,
	// but ADR-0040 spells that verdict "park, never terminal, never hot-retried"
	// — and this sender has no park facility: its only two moves are clear
	// (permanent) and leave-pending. Clearing on a code we cannot even name
	// turns a peer-side condition we do not understand into permanent, silent
	// event loss, so the conservative move is to keep the event. That is also
	// what the pre-ADR-0040 sender did, which ignored setErrs entirely.
	//
	// They are a separate bucket rather than folded into Retry so a caller can
	// say WHY it is holding them: "the peer says this can heal" and "we do not
	// recognize what the peer said" are different operator stories.
	Unrecognized []string

	// FatalErr is the first (lowest JTI) stream-fatal setErr, carried so the
	// caller can put the peer's own words in the operator-visible reason. Zero
	// when Fatal is empty.
	FatalErr SetErr
}

// PartitionSetErrs splits setErrs into the four sender-side buckets. Each slice
// is sorted so the outcome does not depend on Go's randomized map iteration — a
// caller's logs, its ack list and its chosen fatal reason stay reproducible.
// A nil/empty map yields the zero SetErrDisposition.
//
// It uses LookupSetErrClass rather than ClassifySetErr because the sender needs
// the one distinction the total classifier throws away: whether the verdict was
// READ from the table or DEFAULTED into it. Only a registered non-retryable code
// authorizes deleting an event.
func PartitionSetErrs(setErrs map[string]SetErr) SetErrDisposition {
	var d SetErrDisposition
	for jti, se := range setErrs {
		class, registered := LookupSetErrClass(se.Err)
		if !registered {
			d.Unrecognized = append(d.Unrecognized, jti)
			continue
		}
		switch class {
		case ClassSetErrRetryable:
			d.Retry = append(d.Retry, jti)
		case ClassSetErrStreamFatal:
			d.Fatal = append(d.Fatal, jti)
		default:
			d.Clear = append(d.Clear, jti)
		}
	}
	sort.Strings(d.Clear)
	sort.Strings(d.Retry)
	sort.Strings(d.Fatal)
	sort.Strings(d.Unrecognized)
	if len(d.Fatal) > 0 {
		d.FatalErr = setErrs[d.Fatal[0]]
	}
	return d
}
