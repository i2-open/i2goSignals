package dao

import (
	"sort"
)

// StreamPending is one (stream, reference) target of an InsertWithPending
// pending map, as inverted by StreamsByJti.
type StreamPending struct {
	StreamID string
	Ref      PendingRef
}

// StreamsByJti inverts an InsertWithPending pending map (stream ID ->
// references) into inbound JTI -> the distinct streams it must be queued on,
// each with its reference, sorted by stream ID so every implementation writes
// a JTI's references in the same order. A (stream, JTI) pair listed more than
// once yields one entry (the first listed reference wins), so a coalesced
// write never creates two references for the same intent. A reference with an
// empty AckJti is returned with AckJti = Jti.
func StreamsByJti(pending map[string][]PendingRef) map[string][]StreamPending {
	if len(pending) == 0 {
		return nil
	}
	out := make(map[string][]StreamPending)
	seen := make(map[[2]string]struct{})
	for streamID, refs := range pending {
		for _, ref := range refs {
			k := [2]string{streamID, ref.Jti}
			if _, dup := seen[k]; dup {
				continue
			}
			seen[k] = struct{}{}
			if ref.AckJti == "" {
				ref.AckJti = ref.Jti
			}
			out[ref.Jti] = append(out[ref.Jti], StreamPending{StreamID: streamID, Ref: ref})
		}
	}
	for _, targets := range out {
		sort.Slice(targets, func(i, j int) bool { return targets[i].StreamID < targets[j].StreamID })
	}
	return out
}
