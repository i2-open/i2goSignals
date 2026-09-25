package services

// Newest-record selection on a key store that holds records minted with
// random ids (i2goSignals#316). Records minted by v0.11.0 through
// v0.12.0-alpha.19 carry fully random ids, and about 58% of them sort above
// any id minted today. Newest is decided by a record's creation time, with id
// order only for records that have none, so a rotation, create or load on such
// a store takes effect at once.

import (
	"context"
	"crypto"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/dao/memory"
	"github.com/i2-open/i2goSignals/pkg/goSet/mldsa"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
)

// legacyRandomId is a record id of the random kind: its leading bytes put it
// above every id ids.NewObjectID mints this century.
const legacyRandomId = "f1c2a9e0d3b4c5a6e7f80912"

// seedLegacySigningRec stores an active signing record of algorithm alg the way
// a pre-upgrade server left it: a random id and no creation time. It returns the
// record's kid.
func seedLegacySigningRec(t *testing.T, dao interfaces.KeyDAO, keyName string, alg string, id string) string {
	t.Helper()
	storedAlg, err := storedAlgFor(alg)
	require.NoError(t, err)
	key, err := generateSigningKey(storedAlg)
	require.NoError(t, err)
	encAlg, priv, pub, err := encodeSigningKey(key)
	require.NoError(t, err)
	kid := keyName + "-" + id
	require.NoError(t, dao.Insert(context.Background(), &interfaces.JwkKeyRec{
		Id:          id,
		KeyName:     keyName,
		Kid:         kid,
		Use:         "sig",
		Alg:         encAlg,
		KeyBytes:    priv,
		PubKeyBytes: pub,
	}))
	return kid
}

// TestRotateKey_OnAStoreWithALegacyRandomIdKeySelectsTheNewKeyAtOnce: the next
// SET signed for the issuer carries the rotated key's kid, not the legacy one.
func TestRotateKey_OnAStoreWithALegacyRandomIdKeySelectsTheNewKeyAtOnce(t *testing.T) {
	for _, alg := range []string{"RS256", "ES256", mldsa.Alg} {
		t.Run(alg, func(t *testing.T) {
			ctx := context.Background()
			dao := memory.NewKeyDAO()
			svc := NewKeyService(dao, "DEFAULT", nil, nil)
			legacyKid := seedLegacySigningRec(t, dao, rtIssuer, alg, legacyRandomId)
			_, kid, err := svc.GetSigner(ctx, rtIssuer, alg)
			require.NoError(t, err)
			require.Equal(t, legacyKid, kid, "before the rotation the legacy key signs")

			_, newKid, err := svc.RotateKey(ctx, rtIssuer, alg, "")
			require.NoError(t, err)

			_, kid, err = svc.GetSigner(ctx, rtIssuer, alg)
			require.NoError(t, err)
			assert.Equal(t, newKid, kid, "the rotated key signs at once")
		})
	}
}

// TestRotateKey_OnTheTokenIssuerWithALegacyRandomIdKeyIssuesUnderTheNewKid: a
// node that starts after the rotation loads the rotated key as the auth token
// key, so the tokens it issues carry the new kid.
func TestRotateKey_OnTheTokenIssuerWithALegacyRandomIdKeyIssuesUnderTheNewKid(t *testing.T) {
	ctx := context.Background()
	dao := memory.NewKeyDAO()
	seedLegacySigningRec(t, dao, "DEFAULT", "RS256", legacyRandomId)
	svc := NewKeyService(dao, "DEFAULT", nil, nil)
	require.NoError(t, svc.InitializeTokenKey(ctx, "DEFAULT"))

	_, newKid, err := svc.RotateKey(ctx, "DEFAULT", "RS256", "")
	require.NoError(t, err)

	restarted := NewKeyService(dao, "DEFAULT", nil, nil)
	require.NoError(t, restarted.InitializeTokenKey(ctx, "DEFAULT"))
	client := model.SsfClient{Id: model.NewRecordId(), ProjectIds: []string{"p"}}
	tok, err := restarted.GetAuthIssuer().IssueStreamClientToken(client, "p", true, "")
	require.NoError(t, err)
	assert.Equal(t, newKid, tokenKid(t, tok), "a token issued after a restart carries the rotated kid")
	_, err = restarted.GetAuthIssuer().ParseAuthToken(tok)
	assert.NoError(t, err, "and verifies")
}

// tokenKid reads the kid from a compact JWS header without verifying it.
func tokenKid(t *testing.T, tok string) string {
	t.Helper()
	parsed, _, err := jwt.NewParser().ParseUnverified(tok, jwt.MapClaims{})
	require.NoError(t, err)
	kid, _ := parsed.Header["kid"].(string)
	return kid
}

// TestCreateKeyPairForAlg_AlongsideALegacyRandomIdKeySelectsTheNewKeyAtOnce: an
// operator's create next to an older key of the same algorithm signs at once.
func TestCreateKeyPairForAlg_AlongsideALegacyRandomIdKeySelectsTheNewKeyAtOnce(t *testing.T) {
	for _, alg := range []string{"RS256", "ES256", mldsa.Alg} {
		t.Run(alg, func(t *testing.T) {
			ctx := context.Background()
			dao := memory.NewKeyDAO()
			svc := NewKeyService(dao, "DEFAULT", nil, nil)
			seedLegacySigningRec(t, dao, rtIssuer, alg, legacyRandomId)

			_, newKid, err := svc.CreateKeyPairForAlg(ctx, rtIssuer, alg, "sig", "")
			require.NoError(t, err)

			_, kid, err := svc.GetSigner(ctx, rtIssuer, alg)
			require.NoError(t, err)
			assert.Equal(t, newKid, kid, "the created key signs at once")
		})
	}
}

// TestAddKey_AlongsideALegacyRandomIdKeySelectsTheLoadedKeyAtOnce: a key load
// (POST /jwks/{keyName} with force=rotate mints a kid like this one) next to an
// older RSA key signs at once.
func TestAddKey_AlongsideALegacyRandomIdKeySelectsTheLoadedKeyAtOnce(t *testing.T) {
	ctx := context.Background()
	dao := memory.NewKeyDAO()
	svc := NewKeyService(dao, "DEFAULT", nil, nil)
	seedLegacySigningRec(t, dao, rtIssuer, "RS256", legacyRandomId)
	loaded, err := generateSigningKey("")
	require.NoError(t, err)

	loadKid := newKeyKid(rtIssuer, "")
	require.NoError(t, svc.AddKey(ctx, rtIssuer, "sig", loadKid, loaded, nil, ""))

	_, kid, err := svc.GetSigner(ctx, rtIssuer, "RS256")
	require.NoError(t, err)
	assert.Equal(t, loadKid, kid, "the loaded key signs at once")
}

// TestGetSigner_AStoreOfOnlyLegacyRecordsSelectsWhatItSelectedBefore: upgrading
// changes nothing for records that predate CreatedAt: the highest id still
// signs, as it did before the upgrade.
func TestGetSigner_AStoreOfOnlyLegacyRecordsSelectsWhatItSelectedBefore(t *testing.T) {
	ctx := context.Background()
	dao := memory.NewKeyDAO()
	svc := NewKeyService(dao, "DEFAULT", nil, nil)
	seedLegacySigningRec(t, dao, rtIssuer, "RS256", "3b0f6c1d2e4a5b6c7d8e9f01")
	highest := seedLegacySigningRec(t, dao, rtIssuer, "RS256", legacyRandomId)
	seedLegacySigningRec(t, dao, rtIssuer, "RS256", "a07e9d8c7b6a5f4e3d2c1b0a")

	_, kid, err := svc.GetSigner(ctx, rtIssuer, "RS256")
	require.NoError(t, err)
	assert.Equal(t, highest, kid)
}

// TestRotateKey_CarriesTheUseOfTheNewestRecordByCreationTime: a rotation keeps
// the use of the keyName's newest record of the algorithm, and newest is the
// same record signing selection would take, not the highest id.
func TestRotateKey_CarriesTheUseOfTheNewestRecordByCreationTime(t *testing.T) {
	ctx := context.Background()
	dao := memory.NewKeyDAO()
	svc := NewKeyService(dao, "DEFAULT", nil, nil)
	seedLegacySigningRec(t, dao, rtIssuer, "RS256", legacyRandomId) // use "sig", highest id
	_, newestKid, err := svc.CreateKeyPairForAlg(ctx, rtIssuer, "RS256", "enc", "")
	require.NoError(t, err)

	_, rotatedKid, err := svc.RotateKey(ctx, rtIssuer, "RS256", "")
	require.NoError(t, err)

	newest, err := dao.FindByKid(ctx, newestKid)
	require.NoError(t, err)
	rotated, err := dao.FindByKid(ctx, rotatedKid)
	require.NoError(t, err)
	assert.Equal(t, newest.Use, rotated.Use, "the rotated key keeps the newest record's use")
	assert.Equal(t, "enc", rotated.Use)
}

// newestRecordScenario returns three active RSA signing records of rtIssuer and
// the one every newest-record site must pick. The legacy record has the highest
// id and no creation time. The other two were minted in the same millisecond,
// so once Mongo truncates their times they tie and the higher id wins, even
// though the lower id's time is 800µs later within that millisecond.
func newestRecordScenario(t *testing.T) (recs []*interfaces.JwkKeyRec, newest *interfaces.JwkKeyRec) {
	t.Helper()
	minted := time.Date(2026, 9, 15, 18, 0, 0, 0, time.UTC)
	rec := func(id string, createdAt time.Time) *interfaces.JwkKeyRec {
		key, err := generateSigningKey("")
		require.NoError(t, err)
		_, priv, pub, err := encodeSigningKey(key)
		require.NoError(t, err)
		return &interfaces.JwkKeyRec{Id: id, KeyName: rtIssuer, Kid: rtIssuer + "-" + id, Use: "sig",
			KeyBytes: priv, PubKeyBytes: pub, CreatedAt: createdAt}
	}
	legacy := rec(legacyRandomId, time.Time{})
	laterInSameMillisecond := rec("6aa991b90123456789000001", minted.Add(900*time.Microsecond))
	newest = rec("6aa991b90123456789000002", minted.Add(100*time.Microsecond))
	return []*interfaces.JwkKeyRec{legacy, newest, laterInSameMillisecond}, newest
}

// TestNewestRecordSites_AllPickTheSameRecord: signing selection, the use a
// rotation carries over, the record that wins a kid collision in the
// verification JWKS, and the memory KeyDAO's FindLatestByKeyName all apply
// JwkKeyRec.NewerThan, so for the same records they pick the same one. The
// stranding guard asks latestActiveSigningRec, so it agrees by construction.
// The Mongo KeyDAO is held to the same scenario in internal/dao/mongo.
func TestNewestRecordSites_AllPickTheSameRecord(t *testing.T) {
	ctx := context.Background()
	recs, newest := newestRecordScenario(t)

	t.Run("signing selection", func(t *testing.T) {
		got, _ := latestActiveSigningRec(recs, "", time.Now())
		require.NotNil(t, got)
		assert.Equal(t, newest.Id, got.Id)
	})

	t.Run("memory FindLatestByKeyName and GetSigner", func(t *testing.T) {
		dao := memory.NewKeyDAO()
		for _, rec := range recs {
			stored := *rec
			require.NoError(t, dao.Insert(ctx, &stored))
		}
		got, err := dao.FindLatestByKeyName(ctx, rtIssuer)
		require.NoError(t, err)
		assert.Equal(t, newest.Id, got.Id)

		_, kid, err := NewKeyService(dao, "DEFAULT", nil, nil).GetSigner(ctx, rtIssuer, "RS256")
		require.NoError(t, err)
		assert.Equal(t, newest.Kid, kid)
	})

	t.Run("rotation use carry-over", func(t *testing.T) {
		dao := memory.NewKeyDAO()
		for _, rec := range recs {
			stored := *rec
			if stored.Id == newest.Id {
				stored.Use = "enc"
			}
			require.NoError(t, dao.Insert(ctx, &stored))
		}
		_, rotatedKid, err := NewKeyService(dao, "DEFAULT", nil, nil).RotateKey(ctx, rtIssuer, "RS256", "")
		require.NoError(t, err)
		rotated, err := dao.FindByKid(ctx, rotatedKid)
		require.NoError(t, err)
		assert.Equal(t, "enc", rotated.Use)
	})

	t.Run("JWKS kid collision", func(t *testing.T) {
		// Records sharing a kid overwrite each other oldest-first, so the newest
		// record's public key is the one published for the kid.
		shared := make([]*interfaces.JwkKeyRec, 0, len(recs))
		for _, rec := range recs {
			stored := *rec
			stored.Kid = rtIssuer
			shared = append(shared, &stored)
		}
		for _, order := range [][]*interfaces.JwkKeyRec{shared, {shared[2], shared[1], shared[0]}} {
			published := jwksFromRecs(order, nil, "").ReadOnlyKeys()[rtIssuer]
			require.NotNil(t, published)
			want, err := recPublicKey(newest)
			require.NoError(t, err)
			assert.True(t, want.(interface{ Equal(crypto.PublicKey) bool }).Equal(published),
				"the newest record's key is published for the shared kid")
		}
	})
}

// TestKeyService_EveryMintedRecordCarriesACreationTimeThatStatusChangesKeep:
// each path that mints a key record stamps CreatedAt, and suspending,
// reactivating or revoking the record leaves it as minted.
func TestKeyService_EveryMintedRecordCarriesACreationTimeThatStatusChangesKeep(t *testing.T) {
	ctx := context.Background()
	dao := memory.NewKeyDAO()
	svc := NewKeyService(dao, "DEFAULT", nil, nil)
	before := time.Now().UTC().Truncate(time.Millisecond)

	mint := map[string]func() string{
		"CreateKeyPair": func() string {
			_, err := svc.CreateKeyPair(ctx, "https://created.example", "sig", "")
			require.NoError(t, err)
			return "https://created.example"
		},
		"CreateKeyPairForAlg": func() string {
			_, kid, err := svc.CreateKeyPairForAlg(ctx, rtIssuer, "ES256", "sig", "")
			require.NoError(t, err)
			return kid
		},
		"RotateKey": func() string {
			_, kid, err := svc.RotateKey(ctx, rtIssuer, mldsa.Alg, "")
			require.NoError(t, err)
			return kid
		},
		"EnsureSigningKeyForAlg": func() string {
			created, err := svc.EnsureSigningKeyForAlg(ctx, "https://ensured.example", mldsa.Alg, "")
			require.NoError(t, err)
			require.True(t, created)
			recs, err := dao.FindByKeyName(ctx, "https://ensured.example")
			require.NoError(t, err)
			require.Len(t, recs, 1)
			return recs[0].Kid
		},
		"AddKey": func() string {
			key, err := generateSigningKey("")
			require.NoError(t, err)
			require.NoError(t, svc.AddKey(ctx, "https://loaded.example", "sig", "", key, nil, ""))
			return "https://loaded.example"
		},
		"StoreExternalKey": func() string {
			require.NoError(t, svc.StoreExternalKey(ctx, "https://receiver.example", nil, "sid", "enc", "https://receiver.example/jwks"))
			return "https://receiver.example"
		},
	}
	for path, mintRec := range mint {
		t.Run(path, func(t *testing.T) {
			kid := mintRec()
			rec, err := dao.FindByKid(ctx, kid)
			require.NoError(t, err)
			require.False(t, rec.CreatedAt.IsZero(), "a minted record carries a creation time")
			assert.False(t, rec.CreatedAt.Before(before), "CreatedAt %v is the mint time (after %v)", rec.CreatedAt, before)
			assert.False(t, rec.CreatedAt.After(time.Now().UTC()), "CreatedAt %v is not in the future", rec.CreatedAt)
			minted := rec.CreatedAt

			for _, status := range []string{interfaces.KeyStatusSuspended, interfaces.KeyStatusActive, interfaces.KeyStatusRevoked} {
				_, _, err := svc.SetKeyStatus(ctx, rec.KeyName, kid, status)
				require.NoError(t, err, status)
				after, err := dao.FindByKid(ctx, kid)
				require.NoError(t, err)
				require.Equal(t, status, after.Status())
				assert.True(t, minted.Equal(after.CreatedAt), "%s leaves CreatedAt as minted", status)
			}
		})
	}
}
