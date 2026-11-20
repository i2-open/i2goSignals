package server

import (
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"github.com/i2-open/i2goSignals/pkg/goSetValidate"
)

// Shared SET builders for the event-validation tests. Each returns a SET whose
// engaged validator reports a known disposition, so the transport tests can
// exercise the mode matrix without re-deriving the SSF §8.1.4.1 / §8.1.5 claim
// rules the pkg/goSetValidate unit tests already cover.

// streamManagementSet builds the envelope both SSF stream-management events
// require: a top-level opaque sub_id whose id is the stream id.
func streamManagementSet(streamId string) *goSet.SecurityEventToken {
	set := goSet.CreateSet(nil, "https://transmitter.example.com", []string{"https://receiver.example.com"})
	set.SubjectId = &goSet.SubjectIdentifier{
		Format:           "opaque",
		OpaqueIdentifier: goSet.OpaqueIdentifier{Id: streamId},
	}
	return &set
}

// verificationSetForTest builds a WELL-FORMED SSF Verification Event, which
// validates clean on any stream because NewValidatorSet always engages it.
func verificationSetForTest(streamId, state string) *goSet.SecurityEventToken {
	set := streamManagementSet(streamId)
	set.AddEventPayload(goSetValidate.SsfVerificationEventUri, map[string]any{"state": state})
	return set
}

// malformedStreamUpdatedSetForTest builds an SSF Stream Updated Event whose
// "status" claim is outside the §8.1.2 vocabulary — the Malformed row of the mode
// matrix, and always in contract so no stream escapes it by narrow scoping.
func malformedStreamUpdatedSetForTest(streamId string) *goSet.SecurityEventToken {
	set := streamManagementSet(streamId)
	set.AddEventPayload(goSetValidate.SsfStreamUpdatedEventUri, map[string]any{"status": "bogus-status"})
	return set
}

// unsupportedEventSetForTest builds a SET carrying only an event URI no engaged
// validator vouches for — the Unsupported row of the mode matrix.
func unsupportedEventSetForTest(streamId string) *goSet.SecurityEventToken {
	set := streamManagementSet(streamId)
	set.AddEventPayload(testUnsupportedUri, map[string]any{"reason": "event-validation test"})
	return set
}

// mixedEventSetForTest builds a multi-URI SET: a well-formed verification event
// alongside an unrecognized companion payload. Worst-disposition-wins makes it
// Unsupported as a whole, so it forwards under ENFORCE and is rejected under
// STRICT.
func mixedEventSetForTest(streamId string) *goSet.SecurityEventToken {
	set := verificationSetForTest(streamId, "mixed-state")
	set.AddEventPayload(testUnsupportedUri, map[string]any{"reason": "companion payload"})
	return set
}
