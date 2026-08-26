package goSet

import (
	"testing"
	"uuid"

	"github.com/stretchr/testify/assert"
)

func TestGenerateJti(t *testing.T) {
	seen := map[string]struct{}{}
	prev := ""
	for i := 0; i < 100; i++ {
		jti := GenerateJti()
		u, err := uuid.Parse(jti)
		assert.NoError(t, err, "jti must be a valid UUID")
		assert.EqualValues(t, 7, u[6]>>4, "jti must be a UUIDv7")
		assert.EqualValues(t, 0b10, u[8]>>6, "jti must carry the RFC 9562 variant bits")
		// v7 is chosen so jtis sort into issue order; the poll and buffer paths
		// lean on that, so the ordering is part of the contract, not an accident.
		assert.Greater(t, jti, prev, "jtis must be strictly increasing")
		prev = jti
		_, dup := seen[jti]
		assert.False(t, dup)
		seen[jti] = struct{}{}
	}
}

func BenchmarkGenerateJti(b *testing.B) {
	for i := 0; i < b.N; i++ {
		GenerateJti()
	}
}
