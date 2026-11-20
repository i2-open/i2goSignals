package model

import (
	"bytes"
	"log/slog"
	"slices"
	"strings"
	"testing"
)

// aiEventType is a vocabulary an operator might carry over goSignals that the
// compiled-in SCIM/CAEP/RISC/WISE packs know nothing about — the case issue #261
// was reopened for (independentid/i2gosignals-ai#2 routes its own analysis
// verdicts through an SSTP two-hop).
const aiEventType = "urn:i2:gosignals-ai:v1:analysis:tier0-deny"

// TestGetSupportedEvents_ExtendedByEnv is the core of the extensible-catalog
// contract: a URI named in I2SIG_EVENT_TYPES_EXTRA is advertised exactly like a
// builtin one, so events_requested can name it and the negotiated
// events_delivered can carry it.
func TestGetSupportedEvents_ExtendedByEnv(t *testing.T) {
	t.Setenv(EnvEventTypesExtra, aiEventType)

	supported := GetSupportedEvents()

	if !slices.Contains(supported, aiEventType) {
		t.Errorf("configured extra event type %q is missing from the supported catalog", aiEventType)
	}
}

// TestGetSupportedEvents_ExtraSkipsInvalidEntries: the extension is operator
// input typed into a deployment manifest, so a stray comma or a bare word is a
// realistic mistake. A non-absolute-URI entry must not reach the catalog — a
// bare word would otherwise be advertised in events_supported and matched
// against by the router — and the operator has to be able to find out why the
// event type they configured never showed up.
func TestGetSupportedEvents_ExtraSkipsInvalidEntries(t *testing.T) {
	logs := captureExtraEventLogs(t)
	t.Setenv(EnvEventTypesExtra, "not-a-uri,\t"+aiEventType+"  urn:i2:gosignals-ai:v1:analysis:tier1-allow,,")

	supported := GetSupportedEvents()

	assertCatalogContains(t, supported, aiEventType)
	assertCatalogContains(t, supported, "urn:i2:gosignals-ai:v1:analysis:tier1-allow")
	if slices.Contains(supported, "not-a-uri") {
		t.Error("a non-absolute-URI extension entry must not be advertised in the supported catalog")
	}
	if !strings.Contains(logs.String(), "not-a-uri") {
		t.Errorf("the skipped entry must be named in a WARN so an operator can find the typo; logs were:\n%s", logs)
	}
}

func assertCatalogContains(t *testing.T, supported []string, uri string) {
	t.Helper()
	if !slices.Contains(supported, uri) {
		t.Errorf("configured extra event type %q is missing from the supported catalog", uri)
	}
}

// captureExtraEventLogs swaps slog.Default for one writing to a buffer, the
// same trick pkg/services tests use: logger.Sub() re-reads slog.Default() per
// record, so a sub-logger built at package init still lands in the buffer.
func captureExtraEventLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

// TestGetSupportedEvents_ExtraDoesNotDuplicate: events_supported is a SET of
// event type URIs (SSF 1.0 §7.1.1), and "*" resolves events_delivered straight
// from it, so a duplicate entry would be advertised twice to every receiver and
// negotiated twice into every wildcard stream. An operator pasting a builtin URI
// into the extension list — or the same custom URI twice — is a no-op, not a
// doubling. Matching is case-insensitive because that is how the router compares
// an event's types against events_delivered.
func TestGetSupportedEvents_ExtraDoesNotDuplicate(t *testing.T) {
	builtin := len(GetSupportedEvents())
	t.Setenv(EnvEventTypesExtra,
		strings.ToUpper(EventScimFeedAdd)+","+aiEventType+","+aiEventType)

	supported := GetSupportedEvents()

	if got, want := len(supported), builtin+1; got != want {
		t.Errorf("catalog has %d entries, want %d - a duplicate extension entry must not extend the catalog", got, want)
	}
	assertCatalogContains(t, supported, aiEventType)
}
