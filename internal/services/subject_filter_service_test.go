package services

import (
	"context"
	"fmt"
	"testing"
	"time"

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

// TestSubjectFilterService_SimpleMembershipScalesConstantly verifies #92
// acceptance criterion 10: simple-subject membership is an indexed lookup, so a
// stream whose filter holds a very large number of subjects still filters in
// roughly constant time per event — it never degrades into a collection scan.
//
// It measures the per-event Allows cost against a small filter and against a
// filter ~200x larger. An indexed lookup keeps the ratio near 1; an O(N) scan
// would make the large filter ~200x slower. A generous 10x bound proves the
// complexity class while leaving ample headroom for measurement noise.
func TestSubjectFilterService_SimpleMembershipScalesConstantly(t *testing.T) {
	t.Setenv("I2SIG_SUBJECT_FILTERING", "ENABLED")

	const (
		smallN = 1000
		largeN = 200000
		probes = 4000
	)

	// measure builds a NONE stream whose filter holds n simple subjects, then
	// times `probes` distinct Allows calls. Probes are unique so every call is a
	// match-cache miss and exercises the real indexed DAO lookup.
	measure := func(n int) time.Duration {
		ctx := context.Background()
		svc := NewSubjectFilterService(memory.NewSubjectFilterDAO())
		stream := noneStream("stream-scale")
		for i := 0; i < n; i++ {
			subj := emailSubject(fmt.Sprintf("member-%d@example.com", i))
			if err := svc.AddSubject(ctx, stream, subj, false); err != nil {
				t.Fatalf("AddSubject: %v", err)
			}
		}
		// Sanity: a member in the filter delivers, a non-member does not.
		if !svc.Allows(ctx, stream, eventFor(emailSubject("member-0@example.com"))) {
			t.Fatal("a subject in the filter must deliver")
		}
		if svc.Allows(ctx, stream, eventFor(emailSubject("absent@example.com"))) {
			t.Fatal("a subject not in the filter must not deliver")
		}
		start := time.Now()
		for i := 0; i < probes; i++ {
			subj := emailSubject(fmt.Sprintf("probe-%d@example.com", i))
			svc.Allows(ctx, stream, eventFor(subj))
		}
		return time.Since(start)
	}

	small := measure(smallN)
	large := measure(largeN)

	// An indexed lookup is O(1): a 200x-larger filter must not be dramatically
	// slower per event. 10x leaves headroom for noise while still failing a
	// regression to an O(N) collection scan.
	if large > small*10+time.Millisecond {
		t.Fatalf("simple-subject membership did not scale: small filter (%d entries) took %v for %d probes, large filter (%d entries) took %v — expected roughly constant time, not an O(N) scan",
			smallN, small, probes, largeN, large)
	}
}
