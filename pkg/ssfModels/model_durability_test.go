package model

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseDurabilityMode(t *testing.T) {
	for in, want := range map[string]DurabilityMode{
		"":           DurabilityUnset,
		"majority":   DurabilityMajority,
		" MAJORITY ": DurabilityMajority,
		"local":      DurabilityLocal,
		"Local":      DurabilityLocal,
	} {
		got, err := ParseDurabilityMode(in)
		require.NoError(t, err, in)
		assert.Equal(t, want, got, in)
	}
	_, err := ParseDurabilityMode("eventual")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "eventual")
	assert.Contains(t, err.Error(), "majority, local")
}

func TestDurabilityMode_IsLocal(t *testing.T) {
	assert.True(t, DurabilityLocal.IsLocal())
	assert.True(t, DurabilityMode("LOCAL").IsLocal())
	assert.False(t, DurabilityMajority.IsLocal())
	assert.False(t, DurabilityUnset.IsLocal())
	assert.False(t, DurabilityMode("bogus").IsLocal())
}

// The knob and the derived effective value round-trip on the operator JSON
// surface, but only the knob is persisted (EffectiveDurability is bson:"-").
func TestStreamStateRecord_DurabilityJSON(t *testing.T) {
	rec := StreamStateRecord{Durability: DurabilityLocal, EffectiveDurability: DurabilityMajority}
	b, err := json.Marshal(rec)
	require.NoError(t, err)
	assert.Contains(t, string(b), `"durability":"local"`)
	assert.Contains(t, string(b), `"effective_durability":"majority"`)

	empty, err := json.Marshal(StreamStateRecord{})
	require.NoError(t, err)
	assert.NotContains(t, string(empty), "durability")
}
