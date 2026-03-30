package test

import (
	"time"

	"github.com/i2-open/i2goSignals/pkg/ssfModels"
)

func (s *MongoProviderSuite) TestClusterMethods() {
	node := model.ClusterNode{
		Id:         "node-1",
		Address:    "http://node-1:8080",
		Version:    "1.0.0",
		StartedAt:  time.Now().UTC(),
		LastSeenAt: time.Now().UTC(),
	}

	// Test RegisterNode
	err := s.provider.RegisterNode(node)
	s.NoError(err)

	// Test GetNode
	retrievedNode, err := s.provider.GetNode("node-1")
	s.NoError(err)
	s.NotNil(retrievedNode)
	s.Equal(node.Id, retrievedNode.Id)
	s.Equal(node.Address, retrievedNode.Address)

	// Test GetNode not found
	nilNode, err := s.provider.GetNode("non-existent")
	s.NoError(err)
	s.Nil(nilNode)

	// Test TryAcquireOrRenewLease
	resource := "test-resource"
	acquired, token, err := s.provider.TryAcquireOrRenewLease(resource, "node-1", 10*time.Second)
	s.NoError(err)
	s.True(acquired)
	s.Greater(token, int64(0))

	// Test GetLeaseOwner
	owner, until, leaseToken, err := s.provider.GetLeaseOwner(resource)
	s.NoError(err)
	s.Equal("node-1", owner)
	s.True(until.After(time.Now()))
	s.Equal(token, leaseToken)

	// Test GetLeaseOwner not found
	owner2, until2, token2, err := s.provider.GetLeaseOwner("non-existent-resource")
	s.NoError(err)
	s.Empty(owner2)
	s.True(until2.IsZero())
	s.Equal(int64(0), token2)

	// Test GetActiveNodeCount
	count, err := s.provider.GetActiveNodeCount()
	s.NoError(err)
	s.GreaterOrEqual(count, int64(1))
}
