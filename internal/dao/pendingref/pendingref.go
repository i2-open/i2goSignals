// Package pendingref holds module-internal helpers for converting between
// inbound JTIs and dao.PendingRef values.
package pendingref

import (
	"time"

	"github.com/i2-open/i2goSignals/pkg/dao"
)

// RefsFromJtis builds references with AckJti = Jti and the given enqueue time
// for every jti, in order.
func RefsFromJtis(jtis []string, enqueuedAt time.Time) []dao.PendingRef {
	if len(jtis) == 0 {
		return nil
	}
	refs := make([]dao.PendingRef, len(jtis))
	for i, jti := range jtis {
		refs[i] = dao.PendingRef{Jti: jti, AckJti: jti, EnqueuedAt: enqueuedAt}
	}
	return refs
}

// RefJtis returns the inbound JTIs of refs, in order.
func RefJtis(refs []dao.PendingRef) []string {
	if len(refs) == 0 {
		return nil
	}
	out := make([]string, len(refs))
	for i, r := range refs {
		out[i] = r.Jti
	}
	return out
}
