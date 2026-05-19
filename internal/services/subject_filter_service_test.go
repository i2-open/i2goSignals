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

	if err := svc.AddSubject(ctx, stream.StreamConfiguration.Id, subject, false); err != nil {
		t.Fatalf("AddSubject: %v", err)
	}

	if !svc.Allows(ctx, stream, event) {
		t.Fatal("after AddSubject the matching event must deliver")
	}
}
