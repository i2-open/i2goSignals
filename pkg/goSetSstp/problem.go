package goSetSstp

// v1 problem-URI registry + total per-JTI classifier for the SSTP setErrs
// vocabulary (draft-hunt-secevent-sstp-00 §2.3 + planning ADR-0040 & the
// enterprise/admin cross-repo registry). The eight ProblemXxx URI constants
// below are the canonical vocabulary; the two verdict tables (URI half +
// SSTP §2.3 keyword half) together map every well-formed SetErr to one of
// three verdicts. Consumers execute the verdict; policy stays consumer-local
// (ADR-0067 carve-out).
//
// This registry is PROMOTED from the two verdict-identical annotation
// tables in enterprise internal/controlset/problem.go and admin's copy;
// under this PRD's slices 4/5 both consumer copies are deleted so this
// pkg becomes the single source. A one-time diff test in this pkg pins
// verdict equivalence to the two source tables until they are removed
// (problem_diff_test.go).
//
// Emission contract (pinned cross-repo, see the promoted comment): a
// setErrs rejection with a registry semantic MUST carry the canonical v1
// problem URI — never an SSTP §2.3 keyword — because the peer's retryability
// dispatch is an exact lookup against this table (a keyword for a
// retryable condition would default-deny and park retryable work).
// Rejections with no registry semantic (e.g. wrong audience, unparsable
// SET) keep the §2.3 keyword; the two value spaces are disjoint (keywords
// carry no '/'), and receivers treat every non-registry value as
// ClassSetErrNonRetryable — never terminal, never hot-retried (ADR-0040).

// problemURIPrefix is the v1 problem-URI namespace root (ADR-0029).
const problemURIPrefix = "https://schemas.independentid.com/secevent/i2sig/problem/v1/"

// v1 SSTP setErrs problem URIs — 8 constants, promoted verbatim from the
// enterprise/admin controlset tables. Comments preserve the emission
// intent; the pkg verdict table below is the single source of retryability.
const (
	// ProblemUnknownEventType: receiver does not implement the event-type
	// URI. Not retryable → failed_unrecoverable.
	ProblemUnknownEventType = problemURIPrefix + "unknown-event-type"
	// ProblemSignatureInvalid: JWS verification failed at the recipient.
	// Retryable — a JWKS force-refresh may heal it on the next exchange.
	ProblemSignatureInvalid = problemURIPrefix + "signature-invalid"
	// ProblemUnknownKID: the SET's kid is not in the recipient's cached
	// JWKS. Retryable — a JWKS refresh may heal it.
	ProblemUnknownKID = problemURIPrefix + "unknown-kid"
	// ProblemTxnJTIMismatch: the same jti arrived with a different txn —
	// a sender bug. Not retryable → failed_unrecoverable.
	ProblemTxnJTIMismatch = problemURIPrefix + "txn-jti-mismatch"
	// ProblemBindingRevoked: the stream is revoked and the receiver
	// refuses all new SETs on it. Not retryable and STREAM-FATAL: the
	// sender transitions the stream to revoked and drains its outbox to
	// aborted.
	ProblemBindingRevoked = problemURIPrefix + "binding-revoked"
	// ProblemEventsNotAllowedForPurpose: the events URI is outside the
	// per-purpose whitelist of the receiving stream. Not retryable.
	ProblemEventsNotAllowedForPurpose = problemURIPrefix + "events-not-allowed-for-purpose"
	// ProblemObjectNotFound: a referenced object (stream/peer/key/issuer)
	// does not exist on this server — an error-result problem on a
	// command verdict, not a transport setErr. Not retryable.
	ProblemObjectNotFound = problemURIPrefix + "object-not-found"
	// ProblemPreconditionFailed: a state precondition for the command
	// was not met. Not retryable.
	ProblemPreconditionFailed = problemURIPrefix + "precondition-failed"
)

// SetErrClass is the three-way verdict a well-formed SetErr resolves to.
// Consumer policy executes off this enum: retry vs park vs stream-fatal.
type SetErrClass int

const (
	// ClassSetErrRetryable: the peer's rejection MAY heal on a subsequent
	// retry (typically after the caller performs a recovery action such
	// as a JWKS refresh — the recovery action is consumer-local policy;
	// the pkg only classifies).
	ClassSetErrRetryable SetErrClass = iota + 1

	// ClassSetErrNonRetryable: the rejection will not heal by retrying
	// the same SET bytes; the sender should PARK the SET (surface for
	// operator triage, never hot-retry, never terminal — ADR-0040).
	// This is the default-deny verdict for any unregistered problem URI
	// or unrecognized §2.3 keyword.
	ClassSetErrNonRetryable

	// ClassSetErrStreamFatal: the rejection means the stream itself is
	// dead — every subsequent send will be rejected the same way. The
	// sender transitions the stream to revoked and drains its outbox to
	// aborted. Reserved for ProblemBindingRevoked.
	ClassSetErrStreamFatal
)

// String returns a stable log/metric label for the verdict.
func (c SetErrClass) String() string {
	switch c {
	case ClassSetErrRetryable:
		return "Retryable"
	case ClassSetErrNonRetryable:
		return "NonRetryable"
	case ClassSetErrStreamFatal:
		return "StreamFatal"
	default:
		return "Unknown"
	}
}

// setErrClassTable is the total classifier table for well-formed SetErr
// values. It unions the v1 URI half (mechanical from the promoted
// enterprise/admin tri-state) with the SSTP §2.3 keyword half (all 12
// constants from errcode.go). Every entry is a pinned verdict — no
// implicit defaults; unknown keys are handled explicitly in ClassifySetErr
// and LookupSetErrClass so an unknown never silently maps to a keyword's
// verdict.
var setErrClassTable = map[string]SetErrClass{
	// -- v1 URI half (promoted from enterprise/admin) -------------------
	// Retryable: JWKS rotation / kid propagation can heal these.
	ProblemSignatureInvalid: ClassSetErrRetryable,
	ProblemUnknownKID:       ClassSetErrRetryable,
	// Stream-fatal: the stream itself is dead.
	ProblemBindingRevoked: ClassSetErrStreamFatal,
	// Non-retryable: sender or content is wrong at rest; retry cannot heal.
	ProblemUnknownEventType:           ClassSetErrNonRetryable,
	ProblemTxnJTIMismatch:             ClassSetErrNonRetryable,
	ProblemEventsNotAllowedForPurpose: ClassSetErrNonRetryable,
	ProblemObjectNotFound:             ClassSetErrNonRetryable,
	ProblemPreconditionFailed:         ClassSetErrNonRetryable,

	// -- SSTP §2.3 keyword half (all 12 constants) ----------------------
	// Retryable: key/JWKS rotation can heal (parity with SignatureInvalid /
	// UnknownKID — these are the keyword-space equivalents).
	ErrJwtCrypto: ClassSetErrRetryable,
	// Non-retryable: retransmitting the same bytes cannot become valid;
	// directional = pair misconfig — parks per ADR-0040 default-deny,
	// never terminal.
	ErrJson:        ClassSetErrNonRetryable,
	ErrJwtParse:    ClassSetErrNonRetryable,
	ErrJwtHdr:      ClassSetErrNonRetryable,
	ErrJws:         ClassSetErrNonRetryable,
	ErrJwe:         ClassSetErrNonRetryable,
	ErrJwtAud:      ClassSetErrNonRetryable,
	ErrJwtIss:      ClassSetErrNonRetryable,
	ErrSetType:     ClassSetErrNonRetryable,
	ErrSetParse:    ClassSetErrNonRetryable,
	ErrSetData:     ClassSetErrNonRetryable,
	ErrDirectional: ClassSetErrNonRetryable,
}

// ClassifySetErr is the total classifier: every well-formed SetErr returns
// exactly one SetErrClass. Unknown err strings (neither a v1 URI nor a
// §2.3 keyword) resolve to ClassSetErrNonRetryable — the default-deny
// verdict from ADR-0040 (park, never terminal, never hot-retried). This
// preserves forward compatibility: a peer emitting a future URI or
// keyword we don't recognize yet parks by construction rather than
// hot-retrying or tearing down the stream.
func ClassifySetErr(e SetErr) SetErrClass {
	if class, ok := setErrClassTable[e.Err]; ok {
		return class
	}
	return ClassSetErrNonRetryable
}

// LookupSetErrClass is the REGISTERED-AWARE lookup: it returns the verdict
// AND a boolean indicating whether the input was a REGISTERED entry (URI
// or keyword). Consumers that need to preserve the emission behavior of
// enterprise's NewCommandError (command.go:92-104) — the i2sig:retryable
// annotation is OMITTED for unregistered URIs — use the ok bool. The
// two return positions are independent: verdict is total (unknown ⇒
// ClassSetErrNonRetryable), while ok distinguishes "I recognized this"
// from "I defaulted to park".
func LookupSetErrClass(errString string) (SetErrClass, bool) {
	class, ok := setErrClassTable[errString]
	if !ok {
		return ClassSetErrNonRetryable, false
	}
	return class, true
}
