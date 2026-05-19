package model

import "github.com/i2-open/i2goSignals/pkg/goSet"

// Subject kinds for a SubjectFilterEntry, mirroring subjectid.SubjectKind. The
// kind selects the ADR-0003 storage/match path: simple subjects are matched by
// indexed canonical-key membership, complex subjects by a linear field-wise
// scan.
const (
    SubjectKindSimple  = "simple"
    SubjectKindComplex = "complex"
    SubjectKindAliases = "aliases"
)

// SubjectFilterEntry is one row of a stream's SSF §8.1.3 subject filter: a
// single subject the receiver has Added (on a NONE stream) or Removed (on an
// ALL stream). The filter stores only the non-default set, so an entry always
// carries the meaning opposite to the stream's DefaultSubjects baseline.
//
// CanonicalKey is the ADR-0003 canonical key (see pkg/subjectid) and is the
// indexed lookup key for simple-subject membership. Verified is stored for
// audit only and has no effect on filtering.
type SubjectFilterEntry struct {
    StreamId     string                   `json:"stream_id" bson:"stream_id"`
    CanonicalKey string                   `json:"canonical_key" bson:"canonical_key"`
    Kind         string                   `json:"kind" bson:"kind"`
    Subject      *goSet.SubjectIdentifier `json:"subject" bson:"subject"`
    Verified     bool                     `json:"verified,omitempty" bson:"verified,omitempty"`
}
