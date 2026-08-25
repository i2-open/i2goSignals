package goSet

import (
	"testing"

	"github.com/segmentio/ksuid"
	"github.com/stretchr/testify/assert"
)

func TestGenerateJti(t *testing.T) {
	seen := map[string]struct{}{}
	for i := 0; i < 100; i++ {
		jti := GenerateJti()
		_, err := ksuid.Parse(jti)
		assert.NoError(t, err, "jti must be a valid ksuid")
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
