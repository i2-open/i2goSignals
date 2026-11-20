package services

import (
	"time"

	"github.com/i2-open/i2goSignals/internal/dao/pendingref"
	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
)

// Test shims for the #359 deliveries interface: callers that still think in
// inbound JTIs build self-acknowledged references (AckJti == Jti).

func refOf(jti string) interfaces.PendingRef {
	return interfaces.PendingRef{Jti: jti, AckJti: jti}
}

func refsFrom(jtis []string) []interfaces.PendingRef {
	return pendingref.RefsFromJtis(jtis, time.Time{})
}

func pendingRefsOf(m map[string][]string) map[string][]interfaces.PendingRef {
	if m == nil {
		return nil
	}
	out := make(map[string][]interfaces.PendingRef, len(m))
	for k, v := range m {
		out[k] = refsFrom(v)
	}
	return out
}

// selfAck maps every stream ID to an empty ackJti, which the stores default
// to the inbound JTI.
func selfAck(streamIDs []string) map[string]string {
	if streamIDs == nil {
		return nil
	}
	out := make(map[string]string, len(streamIDs))
	for _, sid := range streamIDs {
		out[sid] = ""
	}
	return out
}

// pageJtis flattens a PendingPage to the pre-#359 (jtis, total, err) shape.
func pageJtis(p interfaces.PendingPage, err error) ([]string, int64, error) {
	return pendingref.RefJtis(p.Refs), p.Total, err
}
