package memory

import (
	"context"
	"testing"

	"github.com/i2-open/i2goSignals/internal/dao/ids"
	"github.com/i2-open/i2goSignals/internal/dao/interfaces"
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
