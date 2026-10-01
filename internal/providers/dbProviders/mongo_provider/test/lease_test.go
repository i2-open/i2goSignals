package test

import (
	"testing"
	"time"

	"github.com/i2-open/i2goSignals/internal/providers/dbProviders/mongo_provider"
	model "github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/stretchr/testify/suite"
)

type LeaseTestSuite struct {
	suite.Suite
	provider *mongo_provider.MongoProvider
}

func (s *LeaseTestSuite) SetupSuite() {
	setMongoResumeFileTempDir(s.T())
	dbName := "ssef_test_lease"
	p, err := mongo_provider.Open(mongoURL(), dbName)
	if err != nil {
		s.T().Skip("MongoDB client error: " + err.Error())
		return
	}
	if err := p.Check(); err != nil {
		s.T().Skip("MongoDB Server not available: " + err.Error())
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

	// 3. Node 1 renews its live lease — the fencing token is kept (#334)
	acquired, token3, err := s.provider.TryAcquireOrRenewLease(resource, node1, 2*time.Second)
	s.NoError(err)
	s.True(acquired)
	s.Equal(token1, token3)

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

// TestExpiredLeaseReadsUnowned proves, on an injected clock, that an elapsed
// lease reads as unowned without a release, that a released lease reads as
// unowned at once, and that re-acquiring an expired lease is a new tenure with
// a higher token even for its former owner (#334).
func (s *LeaseTestSuite) TestExpiredLeaseReadsUnowned() {
	coord, ok := s.provider.Coordinator().(*mongo_provider.MongoCoordinator)
	s.Require().True(ok)
	clock := time.Now().UTC().Truncate(time.Millisecond)
	coord.SetClock(func() time.Time { return clock })
	defer coord.SetClock(nil)
	resource := "test-resource-expiry"

	acquired, t1, err := coord.TryAcquireOrRenewLease(resource, "node-1", 30*time.Second)
	s.Require().NoError(err)
	s.Require().True(acquired)
	owner, _, tok, err := coord.GetLeaseOwner(resource)
	s.NoError(err)
	s.Equal("node-1", owner)
	s.Equal(t1, tok)

	clock = clock.Add(30 * time.Second)
	owner, until, tok, err := coord.GetLeaseOwner(resource)
	s.NoError(err)
	s.Equal("", owner, "an expired lease has no owner")
	s.True(until.IsZero())
	s.Equal(int64(0), tok)

	acquired, t2, err := coord.TryAcquireOrRenewLease(resource, "node-1", 30*time.Second)
	s.NoError(err)
	s.True(acquired)
	s.Greater(t2, t1, "re-acquiring an expired lease is a new tenure")

	s.NoError(coord.ReleaseLeaseIfOwned(resource, "node-1"))
	owner, _, _, err = coord.GetLeaseOwner(resource)
	s.NoError(err)
	s.Equal("", owner, "a released lease has no owner")
}

// TestPurgeExpiredLeasesAndStaleNodes proves the Mongo Reaper matches the
// memory reference (#350): an expired lease row whose resource keep rejects is
// deleted (the next tenure restarts at token 1), a kept or live row is
// untouched, and a node last seen before the cutoff is deleted.
func (s *LeaseTestSuite) TestPurgeExpiredLeasesAndStaleNodes() {
	coord, ok := s.provider.Coordinator().(*mongo_provider.MongoCoordinator)
	s.Require().True(ok)
	clock := time.Now().UTC().Truncate(time.Millisecond)
	coord.SetClock(func() time.Time { return clock })
	defer coord.SetClock(nil)

	deleted, kept, live := "push-transmitter:reap-deleted", "push-transmitter:reap-kept", "push-transmitter:reap-live"
	for _, res := range []string{deleted, kept, live} {
		for i := 0; i < 3; i++ {
			acquired, _, err := coord.TryAcquireOrRenewLease(res, "node-1", time.Second)
			s.Require().NoError(err)
			s.Require().True(acquired)
			s.Require().NoError(coord.ReleaseLeaseIfOwned(res, "node-1"))
		}
	}
	clock = clock.Add(5 * time.Minute)
	_, _, err := coord.TryAcquireOrRenewLease(live, "node-1", 30*time.Second)
	s.Require().NoError(err)

	keep := func(resource string) bool { return resource == kept }
	n, err := coord.PurgeExpiredLeases(clock.Add(-90*time.Second), keep)
	s.Require().NoError(err)
	s.GreaterOrEqual(n, 1, "other suite tests may leave expired rows too")

	_, tok, _ := coord.TryAcquireOrRenewLease(deleted, "node-2", time.Second)
	s.Equal(int64(1), tok, "the purged row is gone")
	_, tok, _ = coord.TryAcquireOrRenewLease(kept, "node-2", time.Second)
	s.Equal(int64(4), tok, "a kept row keeps its fencing history")
	owner, _, _, _ := coord.GetLeaseOwner(live)
	s.Equal("node-1", owner, "a live lease is untouched")

	now := time.Now().UTC()
	s.Require().NoError(coord.RegisterNode(model.ClusterNode{Id: "reap-gone", LastSeenAt: now.Add(-5 * time.Minute)}))
	s.Require().NoError(coord.RegisterNode(model.ClusterNode{Id: "reap-live", LastSeenAt: now}))
	_, err = coord.PurgeStaleNodes(now.Add(-90 * time.Second))
	s.Require().NoError(err)
	gone, err := coord.GetNode("reap-gone")
	s.NoError(err)
	s.Nil(gone)
	liveNode, err := coord.GetNode("reap-live")
	s.NoError(err)
	s.NotNil(liveNode)
}

func TestLeaseSuite(t *testing.T) {
	suite.Run(t, new(LeaseTestSuite))
}
