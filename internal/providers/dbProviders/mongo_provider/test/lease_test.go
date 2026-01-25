package test

import (
	"testing"
	"time"

	"github.com/i2-open/i2goSignals/internal/providers/dbProviders/mongo_provider"
	"github.com/stretchr/testify/suite"
)

type LeaseTestSuite struct {
	suite.Suite
	provider *mongo_provider.MongoProvider
}

func (s *LeaseTestSuite) SetupSuite() {
	dbUrl := "mongodb://root:dockTest@localhost:30001,localhost:30002,localhost:30003/?retryWrites=true&replicaSet=dbrs&readPreference=primary&serverSelectionTimeoutMS=5000&connectTimeoutMS=10000&authSource=admin&authMechanism=SCRAM-SHA-256"
	dbName := "ssef_test_lease"
	p, err := mongo_provider.Open(dbUrl, dbName)
	if err != nil {
		s.T().Skip("MongoDB not available for testing")
		return
	}
	s.provider = p
	_ = s.provider.ResetDb(true)
}

func (s *LeaseTestSuite) TearDownSuite() {
	if s.provider != nil {
		_ = s.provider.Close()
	}
}

func (s *LeaseTestSuite) TestLeaseAcquisition() {
	resource := "test-resource"
	node1 := "node-1"
	node2 := "node-2"

	// 1. Node 1 acquires lease
	acquired, token1, err := s.provider.TryAcquireOrRenewLease(resource, node1, 2*time.Second)
	s.NoError(err)
	s.True(acquired)
	s.Greater(token1, int64(0))

	// 2. Node 2 tries to acquire (should fail)
	acquired, token2, err := s.provider.TryAcquireOrRenewLease(resource, node2, 2*time.Second)
	s.NoError(err)
	s.False(acquired)
	s.Equal(int64(0), token2)

	// 3. Node 1 renews lease
	acquired, token3, err := s.provider.TryAcquireOrRenewLease(resource, node1, 2*time.Second)
	s.NoError(err)
	s.True(acquired)
	s.Greater(token3, token1)

	// 4. Wait for lease to expire
	time.Sleep(2500 * time.Millisecond)

	// 5. Node 2 acquires lease
	acquired, token4, err := s.provider.TryAcquireOrRenewLease(resource, node2, 2*time.Second)
	s.NoError(err)
	s.True(acquired)
	s.Greater(token4, token3)
}

func (s *LeaseTestSuite) TestLeaseRelease() {
	resource := "test-resource-release"
	node1 := "node-1"
	node2 := "node-2"

	// 1. Node 1 acquires lease
	acquired, _, err := s.provider.TryAcquireOrRenewLease(resource, node1, 10*time.Second)
	s.Require().True(acquired)
	s.Require().NoError(err)

	// 2. Node 1 releases lease
	err = s.provider.ReleaseLeaseIfOwned(resource, node1)
	s.NoError(err)

	// 3. Node 2 acquires lease (should succeed because leaseUntil was shortened)
	acquired, _, err = s.provider.TryAcquireOrRenewLease(resource, node2, 10*time.Second)
	s.NoError(err)
	s.True(acquired)
}

func TestLeaseSuite(t *testing.T) {
	suite.Run(t, new(LeaseTestSuite))
}
