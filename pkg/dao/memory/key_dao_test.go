package memory

import (
	"context"
	"testing"
	"time"

	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
	"github.com/i2-open/i2goSignals/pkg/dao/ids"
	"github.com/stretchr/testify/suite"
)

type KeyDAOMemorySuite struct {
	suite.Suite
	dao interfaces.KeyDAO
}

func (suite *KeyDAOMemorySuite) SetupTest() {
	suite.dao = NewKeyDAO()
}

func TestKeyDAOMemorySuite(t *testing.T) {
	suite.Run(t, new(KeyDAOMemorySuite))
}

func (suite *KeyDAOMemorySuite) TestKeySummaryRotations() {
	ctx := context.Background()
	keyName := "test-key"

	// Case 1: 1 key -> 0 rotations
	key1 := &interfaces.JwkKeyRec{
		Id:      ids.NewObjectID(),
		KeyName: keyName,
		Kid:     keyName,
		Use:     "sig",
	}
	err := suite.dao.Insert(ctx, key1)
	suite.NoError(err)

	summary, err := suite.dao.KeySummary(ctx, keyName)
	suite.NoError(err)
	suite.NotNil(summary)
	suite.Equal(keyName, summary.KeyName)
	suite.Equal(key1.Kid, summary.Kids[0])
	suite.Equal(key1.Use, summary.Use)
	suite.Equal(0, summary.Rotations)

	// Case 2: Add 2 more keys -> 3 keys total -> 2 rotations
	key2 := &interfaces.JwkKeyRec{
		Id:      ids.NewObjectID(),
		KeyName: keyName,
		Kid:     keyName + "-2",
		Use:     "sig",
	}
	key3 := &interfaces.JwkKeyRec{
		Id:      ids.NewObjectID(),
		KeyName: keyName,
		Kid:     keyName + "-3",
		Use:     "sig",
	}
	_ = suite.dao.Insert(ctx, key2)
	_ = suite.dao.Insert(ctx, key3)

	summary, err = suite.dao.KeySummary(ctx, keyName)
	suite.NoError(err)
	suite.NotNil(summary)
	suite.Equal(2, summary.Rotations)
}

func (suite *KeyDAOMemorySuite) TestSetKeyStatus_ByKid() {
	ctx := context.Background()
	keyName := "kn"
	k1 := &interfaces.JwkKeyRec{Id: ids.NewObjectID(), KeyName: keyName, Kid: keyName}
	k2 := &interfaces.JwkKeyRec{Id: ids.NewObjectID(), KeyName: keyName, Kid: keyName + "-2"}
	suite.NoError(suite.dao.Insert(ctx, k1))
	suite.NoError(suite.dao.Insert(ctx, k2))

	now := time.Now()
	n, err := suite.dao.SetKeyStatus(ctx, keyName, k2.Kid, &now, nil)
	suite.NoError(err)
	suite.Equal(1, n, "only the targeted kid is updated")

	got1, _ := suite.dao.FindByKid(ctx, k1.Kid)
	got2, _ := suite.dao.FindByKid(ctx, k2.Kid)
	suite.True(got1.IsActive(), "untargeted kid stays active")
	suite.Equal(interfaces.KeyStatusSuspended, got2.Status())

	// Clear suspension on k2 (reactivate).
	zero := time.Time{}
	n, err = suite.dao.SetKeyStatus(ctx, keyName, k2.Kid, &zero, nil)
	suite.NoError(err)
	suite.Equal(1, n)
	got2, _ = suite.dao.FindByKid(ctx, k2.Kid)
	suite.True(got2.IsActive(), "suspension cleared restores active")
}

func (suite *KeyDAOMemorySuite) TestSetKeyStatus_AllUnderKeyName() {
	ctx := context.Background()
	keyName := "kn"
	suite.NoError(suite.dao.Insert(ctx, &interfaces.JwkKeyRec{Id: ids.NewObjectID(), KeyName: keyName, Kid: keyName}))
	suite.NoError(suite.dao.Insert(ctx, &interfaces.JwkKeyRec{Id: ids.NewObjectID(), KeyName: keyName, Kid: keyName + "-2"}))

	now := time.Now()
	n, err := suite.dao.SetKeyStatus(ctx, keyName, "", nil, &now)
	suite.NoError(err)
	suite.Equal(2, n, "empty kid updates every record under keyName")

	recs, _ := suite.dao.FindByKeyName(ctx, keyName)
	for _, r := range recs {
		suite.Equal(interfaces.KeyStatusRevoked, r.Status())
	}
}

func (suite *KeyDAOMemorySuite) TestSetKeyStatus_RevokedIsWriteOnce() {
	ctx := context.Background()
	keyName := "kn"
	k := &interfaces.JwkKeyRec{Id: ids.NewObjectID(), KeyName: keyName, Kid: keyName}
	suite.NoError(suite.dao.Insert(ctx, k))

	first := time.Now().Add(-time.Hour)
	_, err := suite.dao.SetKeyStatus(ctx, keyName, "", nil, &first)
	suite.NoError(err)

	// A second revoke stamp must NOT overwrite the original RevokedAt.
	later := time.Now()
	_, err = suite.dao.SetKeyStatus(ctx, keyName, "", nil, &later)
	suite.NoError(err)
	got, _ := suite.dao.FindByKid(ctx, k.Kid)
	suite.WithinDuration(first, got.RevokedAt, time.Second, "RevokedAt is write-once")
}

func (suite *KeyDAOMemorySuite) TestSetKeyStatus_NotFound() {
	ctx := context.Background()
	now := time.Now()
	_, err := suite.dao.SetKeyStatus(ctx, "missing", "", &now, nil)
	suite.ErrorIs(err, interfaces.ErrKeyNotFound)
}

func (suite *KeyDAOMemorySuite) TestKeySummary_CarriesPerKidState() {
	ctx := context.Background()
	keyName := "kn"
	k1 := &interfaces.JwkKeyRec{Id: ids.NewObjectID(), KeyName: keyName, Kid: keyName}
	k2 := &interfaces.JwkKeyRec{Id: ids.NewObjectID(), KeyName: keyName, Kid: keyName + "-2"}
	suite.NoError(suite.dao.Insert(ctx, k1))
	suite.NoError(suite.dao.Insert(ctx, k2))
	now := time.Now()
	_, _ = suite.dao.SetKeyStatus(ctx, keyName, k2.Kid, &now, nil)

	summary, err := suite.dao.KeySummary(ctx, keyName)
	suite.NoError(err)
	suite.Len(summary.KeyStates, 2)
	byKid := map[string]string{}
	for _, st := range summary.KeyStates {
		byKid[st.Kid] = st.Status
	}
	suite.Equal(interfaces.KeyStatusActive, byKid[k1.Kid])
	suite.Equal(interfaces.KeyStatusSuspended, byKid[k2.Kid])
}

func (suite *KeyDAOMemorySuite) TestListSummaries() {
	ctx := context.Background()

	// Add keys for multiple key names
	_ = suite.dao.Insert(ctx, &interfaces.JwkKeyRec{
		Id:      ids.NewObjectID(),
		KeyName: "key-a",
		Kid:     "key-a",
	})
	_ = suite.dao.Insert(ctx, &interfaces.JwkKeyRec{
		Id:      ids.NewObjectID(),
		KeyName: "key-b",
		Kid:     "key-b",
	})
	_ = suite.dao.Insert(ctx, &interfaces.JwkKeyRec{
		Id:      ids.NewObjectID(),
		KeyName: "key-b",
		Kid:     "key-b-2",
	})

	summaries, err := suite.dao.ListSummaries(ctx)
	suite.NoError(err)
	suite.Len(summaries, 2)

	var foundA, foundB bool
	for _, s := range summaries {
		if s.KeyName == "key-a" {
			suite.Equal(0, s.Rotations)
			foundA = true
		} else if s.KeyName == "key-b" {
			suite.Equal(1, s.Rotations)
			foundB = true
		}
	}
	suite.True(foundA)
	suite.True(foundB)
}
