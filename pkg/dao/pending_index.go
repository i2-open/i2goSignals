package dao

import "sort"

// StreamsByJti inverts an InsertWithPending pending map (stream ID -> JTIs)
// into JTI -> the distinct stream IDs it must be queued on, sorted so every
// implementation writes a JTI's markers in the same order. A (stream, JTI)
// pair listed more than once yields one stream entry, so a coalesced write
// never creates two markers for the same intent.
func StreamsByJti(pending map[string][]string) map[string][]string {
	if len(pending) == 0 {
		return nil
	}
	out := make(map[string][]string)
	seen := make(map[[2]string]struct{})
	for streamID, jtis := range pending {
		for _, jti := range jtis {
			k := [2]string{streamID, jti}
			if _, dup := seen[k]; dup {
				continue
			}
			seen[k] = struct{}{}
			out[jti] = append(out[jti], streamID)
		}
	}
	for _, streams := range out {
		sort.Strings(streams)
	}
	return out
}
