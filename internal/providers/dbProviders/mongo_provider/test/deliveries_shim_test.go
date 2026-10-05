package test

import (
	"github.com/i2-open/i2goSignals/internal/dao/pendingref"
	daoInterfaces "github.com/i2-open/i2goSignals/pkg/dao"
)

// pollJtis flattens a GetEventIds result to its inbound JTIs (#359).
func pollJtis(refs []daoInterfaces.PendingRef, more bool) ([]string, bool) {
	return pendingref.RefJtis(refs), more
}
