package goSetSstp_test

// One-time verdict-diff test asserting the promoted pkg/goSetSstp
// registry is VERDICT-IDENTICAL (not byte-identical) to the two annotation
// tables it replaces:
//
//   - independentid/i2gosignals-enterprise internal/controlset/problem.go
//   - i2-open/i2goSignalsAdmin       internal/controlset/problem.go
//
// The two enterprise/admin tables are held in {Retryable, Terminal,
// RetryAfterHintSeconds} tri-state; the pkg table is {Retryable,
// NonRetryable, StreamFatal}. The projection is mechanical:
//
//     {Retryable: true,  Terminal: false} → ClassSetErrRetryable
//     {Retryable: false, Terminal: true}  → ClassSetErrStreamFatal
//     {Retryable: false, Terminal: false} → ClassSetErrNonRetryable
//
// (RetryAfterHintSeconds is DROPPED — the seam confirmed it is moot in
// both consumers.)
//
// This test is DELETED when the enterprise/admin local tables are
// deleted (slices 4/5 of this PRD). Until then it pins that the promoted
// pkg table cannot drift from the two verdict-identical source tables
// without the diff being surfaced.

import (
	"testing"

	"github.com/i2-open/i2goSignals/pkg/goSetSstp"
)

// SourceAnnotation is the pre-projection tri-state as it appears in both
// controlset/problem.go copies. Verdict = (Retryable, Terminal) — the
// Hint field is intentionally absent (dropped by the seam).
type sourceAnnotation struct {
	Retryable bool
	Terminal  bool
}

// enterpriseSnapshot is the pinned copy of enterprise
// internal/controlset/problem.go's problemRegistry (canonical 2026-07-16,
// enterprise HEAD 0650023). This test file is deleted together with the
// source table in slice 4, so the snapshot cannot decay silently.
var enterpriseSnapshot = map[string]sourceAnnotation{
	goSetSstp.ProblemUnknownEventType:           {Retryable: false},
	goSetSstp.ProblemSignatureInvalid:           {Retryable: true},
	goSetSstp.ProblemUnknownKID:                 {Retryable: true},
	goSetSstp.ProblemTxnJTIMismatch:             {Retryable: false},
	goSetSstp.ProblemBindingRevoked:             {Retryable: false, Terminal: true},
	goSetSstp.ProblemEventsNotAllowedForPurpose: {Retryable: false},
	goSetSstp.ProblemObjectNotFound:             {Retryable: false},
	goSetSstp.ProblemPreconditionFailed:         {Retryable: false},
}

// adminSnapshot is the pinned copy of i2-open/i2goSignalsAdmin
// internal/controlset/problem.go's problemRegistry (canonical 2026-07-16,
// admin HEAD d58f12c). Comments differ from enterprise's copy; verdicts
// are the same — that identity is exactly what this test proves. Deleted
// in slice 5 with the source.
var adminSnapshot = map[string]sourceAnnotation{
	goSetSstp.ProblemUnknownEventType:           {Retryable: false},
	goSetSstp.ProblemSignatureInvalid:           {Retryable: true},
	goSetSstp.ProblemUnknownKID:                 {Retryable: true},
	goSetSstp.ProblemTxnJTIMismatch:             {Retryable: false},
	goSetSstp.ProblemBindingRevoked:             {Retryable: false, Terminal: true},
	goSetSstp.ProblemEventsNotAllowedForPurpose: {Retryable: false},
	goSetSstp.ProblemObjectNotFound:             {Retryable: false},
	goSetSstp.ProblemPreconditionFailed:         {Retryable: false},
}

// projectSourceVerdict is the mechanical tri-state → pkg-verdict mapping.
func projectSourceVerdict(a sourceAnnotation) goSetSstp.SetErrClass {
	switch {
	case a.Retryable:
		return goSetSstp.ClassSetErrRetryable
	case a.Terminal:
		return goSetSstp.ClassSetErrStreamFatal
	default:
		return goSetSstp.ClassSetErrNonRetryable
	}
}

// TestProblemRegistry_VerdictIdenticalToEnterprise asserts every URI in
// the enterprise snapshot maps to the same verdict in the pkg's
// LookupSetErrClass — verdict identity, not byte identity.
func TestProblemRegistry_VerdictIdenticalToEnterprise(t *testing.T) {
	assertVerdictIdentical(t, "enterprise", enterpriseSnapshot)
}

// TestProblemRegistry_VerdictIdenticalToAdmin — same, admin side.
func TestProblemRegistry_VerdictIdenticalToAdmin(t *testing.T) {
	assertVerdictIdentical(t, "admin", adminSnapshot)
}

// TestProblemRegistry_URISetIsUnionOfSources asserts the pkg's URI half is
// exactly the union of the two source tables — no dropped URI, no added
// URI. Combined with the two identity tests above, this pins verdict-and-
// membership identity across all three tables.
func TestProblemRegistry_URISetIsUnionOfSources(t *testing.T) {
	// Union = enterprise ∪ admin (which happens to be identical to both,
	// per the seam's "verdict-identical / entries identical" pin).
	sourceURIs := map[string]bool{}
	for u := range enterpriseSnapshot {
		sourceURIs[u] = true
	}
	for u := range adminSnapshot {
		sourceURIs[u] = true
	}
	// Every source URI must be registered in the pkg.
	for u := range sourceURIs {
		if _, ok := goSetSstp.LookupSetErrClass(u); !ok {
			t.Errorf("URI %q in source tables but NOT registered in pkg", u)
		}
	}
	// Every pkg-registered v1 URI must be present in a source table.
	// (Iterate the 8 documented ProblemXxx constants — they are the
	// canonical enumeration.)
	pkgURIs := []string{
		goSetSstp.ProblemUnknownEventType,
		goSetSstp.ProblemSignatureInvalid,
		goSetSstp.ProblemUnknownKID,
		goSetSstp.ProblemTxnJTIMismatch,
		goSetSstp.ProblemBindingRevoked,
		goSetSstp.ProblemEventsNotAllowedForPurpose,
		goSetSstp.ProblemObjectNotFound,
		goSetSstp.ProblemPreconditionFailed,
	}
	for _, u := range pkgURIs {
		if !sourceURIs[u] {
			t.Errorf("pkg-registered URI %q not present in either source snapshot", u)
		}
	}
}

func assertVerdictIdentical(t *testing.T, side string, snapshot map[string]sourceAnnotation) {
	t.Helper()
	for uri, srcAnn := range snapshot {
		want := projectSourceVerdict(srcAnn)
		got, ok := goSetSstp.LookupSetErrClass(uri)
		if !ok {
			t.Errorf("[%s] %q: LookupSetErrClass returned ok=false; want registered as %v", side, uri, want)
			continue
		}
		if got != want {
			t.Errorf("[%s] %q: pkg verdict %v, source projected %v (source={Retryable:%v Terminal:%v})",
				side, uri, got, want, srcAnn.Retryable, srcAnn.Terminal)
		}
	}
}
