package services

import (
	"context"
	"testing"

	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Issue #311: StrandedByKeyChange judges a key change from exactly the records
// it retires and the signing keys it adds, per algorithm, so a replace that acts
// on one algorithm (#314) is judged as correctly as one that deletes every key.

func TestStrandedByKeyChange_JudgesEachAlgorithmFromWhatTheChangeRetiresAndAdds(t *testing.T) {
	svc := signingKeyFixture(t)
	ctx := context.Background()
	_, err := svc.keyService.EnsureSigningKeyForAlg(ctx, keyedIssuer, "ES256", "test-project")
	require.NoError(t, err)
	for _, rec := range []model.StreamStateRecord{
		pollTransmitterRecord("rs-1", "RS256"),
		pollTransmitterRecord("es-1", "ES256"),
		// An empty signing_alg is satisfied by any active key type (spec #114).
		pollTransmitterRecord("any-1", ""),
	} {
		require.NoError(t, svc.PersistStreamStateRecord(ctx, &rec))
	}
	retireES256 := RetireAlg("ES256")

	cases := []struct {
		name     string
		change   KeyChange
		algs     []string
		stranded []string
	}{
		{"delete ES256 and create ES256", KeyChange{Retires: retireES256, Adds: []string{"ES256"}}, nil, nil},
		{"delete ES256 and create RSA", KeyChange{Retires: retireES256, Adds: []string{"RS256"}}, []string{"ES256"}, []string{"es-1"}},
		{"delete every key and create RSA", KeyChange{Retires: RetireAllKeys, Adds: []string{"RS256"}}, []string{"ES256"}, []string{"es-1"}},
		{"delete ES256 and create none", KeyChange{Retires: retireES256}, []string{"ES256"}, []string{"es-1"}},
		{"suspend every key", KeyChange{Retires: RetireAllKeys}, []string{"ES256", "RS256"}, []string{"any-1", "es-1", "rs-1"}},
		{"suspend the RSA kid", KeyChange{Retires: RetireKid(keyedIssuer)}, []string{"RS256"}, []string{"rs-1"}},
		{"delete RSA keys and create none", KeyChange{Retires: RetireAlg("RS256")}, []string{"RS256"}, []string{"rs-1"}},
		{"add only", KeyChange{Adds: []string{"RS256"}}, nil, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			algs, stranded, err := svc.StrandedByKeyChange(ctx, keyedIssuer, tc.change)
			require.NoError(t, err)
			assert.Equal(t, tc.algs, algs)
			var ids []string
			for _, s := range stranded {
				ids = append(ids, s.StreamId)
			}
			assert.Equal(t, tc.stranded, ids)
		})
	}
}

// An empty-signing_alg stream is reported under the alg it signs with now: that
// of the issuer's newest active key (spec #114).
func TestStrandedByKeyChange_AnAnyTypeStreamReportsItsEffectiveAlg(t *testing.T) {
	svc := signingKeyFixture(t)
	ctx := context.Background()
	_, err := svc.keyService.EnsureSigningKeyForAlg(ctx, keyedIssuer, "ES256", "test-project")
	require.NoError(t, err)
	rec := pollTransmitterRecord("any-1", "")
	require.NoError(t, svc.PersistStreamStateRecord(ctx, &rec))

	// Retiring only the older RSA key leaves the ES256 key: nothing strands.
	_, stranded, err := svc.StrandedByKeyChange(ctx, keyedIssuer, KeyChange{Retires: RetireAlg("RS256")})
	require.NoError(t, err)
	assert.Empty(t, stranded)

	_, stranded, err = svc.StrandedByKeyChange(ctx, keyedIssuer, KeyChange{Retires: RetireAllKeys})
	require.NoError(t, err)
	require.Len(t, stranded, 1)
	assert.Equal(t, "any-1", stranded[0].StreamId)
	assert.Equal(t, "ES256", stranded[0].SigningAlg, "the newest key is ES256")
}

func TestStrandedByKeyChange_AnAlgorithmWithNoActiveKeyNowIsNotCounted(t *testing.T) {
	svc := signingKeyFixture(t)
	ctx := context.Background()
	rec := pollTransmitterRecord("es-1", "ES256") // keyedIssuer has no ES256 key
	require.NoError(t, svc.PersistStreamStateRecord(ctx, &rec))

	algs, stranded, err := svc.StrandedByKeyChange(ctx, keyedIssuer, KeyChange{Retires: RetireAllKeys})
	require.NoError(t, err)
	assert.Empty(t, algs)
	assert.Empty(t, stranded)
}

func pollTransmitterRecord(sid, signingAlg string) model.StreamStateRecord {
	rec := pollSigningRequest(keyedIssuer, "")
	rec.StreamConfiguration.Id = sid
	rec.StreamConfiguration.SigningAlg = signingAlg
	rec.Status = model.StreamStateEnabled
	return rec
}
