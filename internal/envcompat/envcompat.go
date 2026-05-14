// Package envcompat centralizes the v0.11.0 environment-variable rename
// migration. Call sites read configuration through Lookup (or
// LookupWithTranslate), which prefers the new name, falls back to the
// deprecated old name, and warns once per old name when an operator is
// still relying on the deprecated value. The deprecated names are
// expected to be removed in v0.12.0+.
package envcompat

import (
    "os"
    "sync"

    "github.com/i2-open/i2goSignals/pkg/logger"
)

var envLog = logger.Sub("ENVCOMPAT")

// warnedOldNames tracks which deprecated env-var names have already
// triggered a WARN this process. Keyed by old name so concurrent callers
// converge on a single warning.
var warnedOldNames sync.Map

// Lookup returns os.Getenv(newName) when non-empty. Otherwise it returns
// os.Getenv(oldName); if that supplied the value, a one-time WARN is
// logged naming both the deprecated name and its replacement. If both
// are set, the new value wins and a one-time WARN notes that both were
// observed. Returns "" if neither is set.
func Lookup(newName, oldName string) string {
    newVal := os.Getenv(newName)
    oldVal := os.Getenv(oldName)

    if newVal != "" {
        if oldVal != "" {
            warnOnce(oldName, "both deprecated and new env vars set; using new value",
                "deprecated", oldName, "replacement", newName)
        }
        return newVal
    }
    if oldVal != "" {
        warnOnce(oldName, "deprecated env var still in use; rename for v0.11.0",
            "deprecated", oldName, "replacement", newName)
        return oldVal
    }
    return ""
}

// LookupWithTranslate behaves like Lookup, but when the value originates
// from the deprecated old name it is run through translate before being
// returned. Used for renames that also change the value vocabulary
// (e.g. POLL_SRV_BEHAVIOR string → I2SIG_POLL_RESPECT_STATUS boolean).
// translate is never applied to a value taken from newName.
func LookupWithTranslate(newName, oldName string, translate func(string) string) string {
    newVal := os.Getenv(newName)
    oldVal := os.Getenv(oldName)

    if newVal != "" {
        if oldVal != "" {
            warnOnce(oldName, "both deprecated and new env vars set; using new value",
                "deprecated", oldName, "replacement", newName)
        }
        return newVal
    }
    if oldVal != "" {
        warnOnce(oldName, "deprecated env var still in use; rename for v0.11.0",
            "deprecated", oldName, "replacement", newName)
        return translate(oldVal)
    }
    return ""
}

func warnOnce(oldName, msg string, kv ...any) {
    if _, loaded := warnedOldNames.LoadOrStore(oldName, struct{}{}); loaded {
        return
    }
    envLog.Warn(msg, kv...)
}

// resetWarnOnceForTest clears the warn-once tracker. Test-only.
func resetWarnOnceForTest() {
    warnedOldNames.Range(func(k, _ any) bool {
        warnedOldNames.Delete(k)
        return true
    })
}
