package dao

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestJwkKeyRec_NewerThan pins the one rule that decides which of two records
// of a keyName is the newer (i2goSignals#316). Records minted before CreatedAt
// existed carry random ids, so a creation time outranks id order, and id order
// decides only between records whose times do not.
func TestJwkKeyRec_NewerThan(t *testing.T) {
	const (
		lowId  = "6aa991b90123456789abcdef" // a freshly minted id
		highId = "f1c2a9e00123456789abcdef" // a legacy random id that sorts above it
	)
	minted := time.Date(2026, 9, 15, 18, 0, 0, 0, time.UTC)

	tests := []struct {
		name string
		a, b JwkKeyRec
		// aNewer is whether a is newer than b; the reverse question must always
		// get the opposite answer.
		aNewer bool
	}{
		{
			name:   "both stamped: the later time wins over a higher id",
			a:      JwkKeyRec{Id: lowId, CreatedAt: minted.Add(time.Second)},
			b:      JwkKeyRec{Id: highId, CreatedAt: minted},
			aNewer: true,
		},
		{
			name:   "both stamped with equal times: the higher id wins",
			a:      JwkKeyRec{Id: highId, CreatedAt: minted},
			b:      JwkKeyRec{Id: lowId, CreatedAt: minted},
			aNewer: true,
		},
		{
			name: "times equal once truncated to Mongo's milliseconds: the higher id wins",
			a:    JwkKeyRec{Id: highId, CreatedAt: minted.Add(100 * time.Microsecond)},
			b:    JwkKeyRec{Id: lowId, CreatedAt: minted.Add(900 * time.Microsecond)},
			// Stored in Mongo both read back as the same millisecond, so the
			// order must not depend on the sub-millisecond part.
			aNewer: true,
		},
		{
			name:   "only one stamped: the stamped record wins over a higher id",
			a:      JwkKeyRec{Id: lowId, CreatedAt: minted},
			b:      JwkKeyRec{Id: highId},
			aNewer: true,
		},
		{
			name:   "only one stamped, other argument order: the stamped record still wins",
			a:      JwkKeyRec{Id: highId},
			b:      JwkKeyRec{Id: lowId, CreatedAt: minted},
			aNewer: false,
		},
		{
			name:   "neither stamped: the higher id wins",
			a:      JwkKeyRec{Id: highId},
			b:      JwkKeyRec{Id: lowId},
			aNewer: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.aNewer, tc.a.NewerThan(&tc.b), "a newer than b")
			assert.Equal(t, !tc.aNewer, tc.b.NewerThan(&tc.a), "b newer than a")
		})
	}
}

// TestJwkKeyRec_NewerThanNil: any record is newer than no record, so a caller
// picking the newest can start from nil.
func TestJwkKeyRec_NewerThanNil(t *testing.T) {
	rec := JwkKeyRec{Id: "6aa991b90123456789abcdef"}
	assert.True(t, rec.NewerThan(nil))
}
