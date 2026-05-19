package services

import (
	"context"
	"testing"

	"github.com/i2-open/i2goSignals/internal/dao/memory"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// emailSubject builds a simple RFC9493 email-format subject identifier.
func emailSubject(addr string) *goSet.SubjectIdentifier {
	s := &goSet.SubjectIdentifier{Format: "email"}
	return s.AddEmail(addr)
}

// noneStream builds a transmitter stream whose baseline policy is NONE.
func noneStream(id string) *model.StreamStateRecord {
	st := &model.StreamStateRecord{DefaultSubjects: model.DefaultSubjectsNone}
	st.StreamConfiguration.Id = id
	return st
}

// allStream builds a transmitter stream whose baseline policy is ALL.
func allStream(id string) *model.StreamStateRecord {
	st := &model.StreamStateRecord{DefaultSubjects: model.DefaultSubjectsAll}
	st.StreamConfiguration.Id = id
	return st
}

// eventFor builds an event record carrying the given subject.
func eventFor(subject *goSet.SubjectIdentifier) *model.AgEventRecord {
	return &model.AgEventRecord{Event: goSet.SecurityEventToken{SubjectId: subject}}
}

// TestSubjectFilterService_NoneStream_DeliversAfterAdd is the tracer bullet for
// issue #92: on a NONE stream nothing delivers until a matching subject is
// added, after which the matching event delivers.
func TestSubjectFilterService_NoneStream_DeliversAfterAdd(t *testing.T) {
	t.Setenv("I2SIG_SUBJECT_FILTERING", "ENABLED")
	ctx := context.Background()

	svc := NewSubjectFilterService(memory.NewSubjectFilterDAO())
	stream := noneStream("stream-1")
	subject := emailSubject("alice@example.com")
	event := eventFor(subject)

	if svc.Allows(ctx, stream, event) {
		t.Fatal("NONE stream with an empty filter must not deliver")
	}

	if err := svc.AddSubject(ctx, stream, subject, false); err != nil {
		t.Fatalf("AddSubject: %v", err)
	}

	if !svc.Allows(ctx, stream, event) {
		t.Fatal("after AddSubject the matching event must deliver")
	}
}

// TestSubjectFilterService_AllStream_StopsAfterRemove verifies that on an ALL
// stream every subject delivers until one is removed, after which that
// subject's events stop (#92 acceptance criterion 2).
func TestSubjectFilterService_AllStream_StopsAfterRemove(t *testing.T) {
	t.Setenv("I2SIG_SUBJECT_FILTERING", "ENABLED")
	ctx := context.Background()

	svc := NewSubjectFilterService(memory.NewSubjectFilterDAO())
	stream := allStream("stream-1")
	subject := emailSubject("alice@example.com")
	event := eventFor(subject)

	if !svc.Allows(ctx, stream, event) {
		t.Fatal("ALL stream with an empty filter must deliver every subject")
	}

	if err := svc.RemoveSubject(ctx, stream, subject); err != nil {
		t.Fatalf("RemoveSubject: %v", err)
	}

	if svc.Allows(ctx, stream, event) {
		t.Fatal("after RemoveSubject the removed subject's events must stop")
	}
}

// TestSubjectFilterService_ClearFilterEmptiesTheFilter verifies ClearFilter
// drops every entry for a stream, restoring the baseline delivery policy. It is
// the service side of the defaultSubjects-flip filter clear (#92 criterion 5).
func TestSubjectFilterService_ClearFilterEmptiesTheFilter(t *testing.T) {
	t.Setenv("I2SIG_SUBJECT_FILTERING", "ENABLED")
	ctx := context.Background()

	svc := NewSubjectFilterService(memory.NewSubjectFilterDAO())
	stream := noneStream("stream-1")
	subject := emailSubject("alice@example.com")
	event := eventFor(subject)

	if err := svc.AddSubject(ctx, stream, subject, false); err != nil {
		t.Fatalf("AddSubject: %v", err)
	}
	if !svc.Allows(ctx, stream, event) {
		t.Fatal("precondition: added subject must deliver")
	}

	if err := svc.ClearFilter(ctx, stream.StreamConfiguration.Id); err != nil {
		t.Fatalf("ClearFilter: %v", err)
	}

	if svc.Allows(ctx, stream, event) {
		t.Fatal("after ClearFilter the NONE stream must deliver nothing again")
	}
}

// opaqueSubject builds a simple RFC9493 opaque-format subject identifier, used
// as a complex-subject member.
func opaqueSubject(id string) *goSet.SubjectIdentifier {
	s := &goSet.SubjectIdentifier{Format: "opaque"}
	s.Id = id
	return s
}

// TestSubjectFilterService_ComplexAddMatchesNarrowerEvent verifies that adding
// a broad complex subject (few members) matches a narrower, more-specific
// complex event per SSF §8.1.3.1 — an undefined member acts as a wildcard
// (#92 acceptance criterion 4).
func TestSubjectFilterService_ComplexAddMatchesNarrowerEvent(t *testing.T) {
	t.Setenv("I2SIG_SUBJECT_FILTERING", "ENABLED")
	ctx := context.Background()

	svc := NewSubjectFilterService(memory.NewSubjectFilterDAO())
	stream := noneStream("stream-1")

	// Broad subscription: only the tenant member is defined.
	subscription := &goSet.SubjectIdentifier{}
	subscription.Tenant = opaqueSubject("tenant-1")

	// Narrower event: same tenant plus a user member.
	eventSubject := &goSet.SubjectIdentifier{}
	eventSubject.Tenant = opaqueSubject("tenant-1")
	eventSubject.User = opaqueSubject("user-9")
	event := eventFor(eventSubject)

	if svc.Allows(ctx, stream, event) {
		t.Fatal("precondition: NONE stream with empty filter must not deliver")
	}

	if err := svc.AddSubject(ctx, stream, subscription, false); err != nil {
		t.Fatalf("AddSubject: %v", err)
	}

	if !svc.Allows(ctx, stream, event) {
		t.Fatal("a broad complex subscription must match a narrower complex event")
	}
}

// TestSubjectFilterService_VerifiedFlagStoredNoFilteringEffect verifies the
// verified flag is persisted for audit and has no effect on the delivery
// decision (#92 acceptance criterion 8).
func TestSubjectFilterService_VerifiedFlagStoredNoFilteringEffect(t *testing.T) {
	t.Setenv("I2SIG_SUBJECT_FILTERING", "ENABLED")
	ctx := context.Background()

	dao := memory.NewSubjectFilterDAO()
	svc := NewSubjectFilterService(dao)
	stream := noneStream("stream-1")
	subject := emailSubject("alice@example.com")

	if err := svc.AddSubject(ctx, stream, subject, true); err != nil {
		t.Fatalf("AddSubject: %v", err)
	}

	entry, err := dao.Get(ctx, stream.StreamConfiguration.Id, "email:alice@example.com")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !entry.Verified {
		t.Fatal("the verified flag must be stored on the filter entry")
	}

	// verified has no effect: the subject delivers exactly as an unverified one.
	if !svc.Allows(ctx, stream, eventFor(subject)) {
		t.Fatal("a verified subject must deliver just like any added subject")
	}
}
