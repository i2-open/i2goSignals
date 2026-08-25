package authSupport

import (
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenerateAlias_LengthAndCharset(t *testing.T) {
	for _, n := range []int{1, 4, 16, 64} {
		alias := GenerateAlias(n)
		assert.Len(t, alias, n)
		for _, c := range alias {
			assert.True(t, strings.ContainsRune(letterBytes, c), "unexpected char %q", c)
		}
	}
	assert.Equal(t, "", GenerateAlias(0))
}

func TestGenerateAlias_Unique(t *testing.T) {
	seen := map[string]struct{}{}
	for i := 0; i < 1000; i++ {
		a := GenerateAlias(16)
		_, dup := seen[a]
		assert.False(t, dup, "duplicate alias %s", a)
		seen[a] = struct{}{}
	}
}

// Concurrent IAT issuance must be race-free (run with -race). Issue #267.
func TestIssueProjectIat_Concurrent(t *testing.T) {
	const workers = 32
	var wg sync.WaitGroup
	var mu sync.Mutex
	projects := map[string]struct{}{}
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			iat, err := auth.IssueProjectIat(nil)
			if !assert.NoError(t, err) {
				return
			}
			eat, err := auth.ParseAuthToken(iat)
			if !assert.NoError(t, err) {
				return
			}
			assert.Len(t, eat.ProjectId, 4)
			mu.Lock()
			projects[eat.ProjectId] = struct{}{}
			mu.Unlock()
		}()
	}
	wg.Wait()
	// 52^4 space; 32 draws colliding would be astronomically unlikely
	assert.Greater(t, len(projects), workers/2)
}
