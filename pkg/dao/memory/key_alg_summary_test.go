package memory

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
)

// TestKeySummary_ReportsAlgOldestFirst (spec #114, S-ALG): every keyStates[]
// entry names its key's alg, and kid[]/keyStates[] run oldest-first by
// creation whatever order the records were stored in, so the last active entry
// of an alg is that type's newest key.
func TestKeySummary_ReportsAlgOldestFirst(t *testing.T) {
	ctx := context.Background()
	dao := NewKeyDAO()
	base := time.Now().Add(-time.Hour)
	material := []byte("k")

	// Stored newest-first on purpose.
	for _, rec := range []*interfaces.JwkKeyRec{
		{KeyName: "iss", Kid: "pq", Alg: "ML-DSA-65", KeyBytes: material, CreatedAt: base.Add(3 * time.Minute)},
		{KeyName: "iss", Kid: "es", Alg: "ES256", KeyBytes: material, CreatedAt: base.Add(2 * time.Minute)},
		{KeyName: "iss", Kid: "rsa", Alg: "", KeyBytes: material, PubKeyBytes: material, CreatedAt: base.Add(time.Minute)},
	} {
		require.NoError(t, dao.Insert(ctx, rec))
	}

	summary, err := dao.KeySummary(ctx, "iss")
	require.NoError(t, err)
	require.NotNil(t, summary)
	assert.Equal(t, []string{"rsa", "es", "pq"}, summary.Kids)
	var algs []string
	for _, st := range summary.KeyStates {
		algs = append(algs, st.Alg)
	}
	assert.Equal(t, []string{"RS256", "ES256", "ML-DSA-65"}, algs)
}

// A record with no key material (an external JWKS URL) has no alg.
func TestKeyState_NoMaterialOmitsAlg(t *testing.T) {
	ext := &interfaces.JwkKeyRec{KeyName: "rx", Kid: "rx", ReceiverJwksUrl: "https://rx.example/jwks"}
	assert.Empty(t, ext.ToKeyState().Alg)
	pub := &interfaces.JwkKeyRec{KeyName: "rx", Kid: "rx", PubKeyBytes: []byte("k")}
	assert.Equal(t, "RS256", pub.ToKeyState().Alg)
}
