package services

import (
	"context"
	"testing"

	"github.com/i2-open/i2goSignals/internal/dao/memory"
	"github.com/i2-open/i2goSignals/internal/model"
	"github.com/stretchr/testify/suite"
)

type ServerServiceTestSuite struct {
	suite.Suite
	service *ServerService
}

func (s *ServerServiceTestSuite) SetupTest() {
	dao := memory.NewServerDAO()
	s.service = NewServerService(dao)
}

func (s *ServerServiceTestSuite) TestCreateServer() {
	server := &model.Server{
		Alias: "test-server",
		Type:  model.ServerTypeGosignals,
	}

	err := s.service.CreateServer(context.Background(), server)
	s.NoError(err)

	// Try to create another with same alias
	server2 := &model.Server{
		Alias: "test-server",
		Type:  model.ServerTypeSsf,
	}
	err = s.service.CreateServer(context.Background(), server2)
	s.Error(err)
	s.ErrorIs(err, ErrServerAlreadyExists)
}

func (s *ServerServiceTestSuite) TestCRUD() {
	server := &model.Server{
		Alias: "test-server",
		Type:  model.ServerTypeGosignals,
	}

	err := s.service.CreateServer(context.Background(), server)
	s.NoError(err)
	s.NotEmpty(server.Id)

	// Get
	retrieved, err := s.service.GetServer(context.Background(), server.Id.Hex())
	s.NoError(err)
	s.Equal(server.Alias, retrieved.Alias)

	// Update
	server.Alias = "updated-alias"
	err = s.service.UpdateServer(context.Background(), server)
	s.NoError(err)

	retrieved, _ = s.service.GetServer(context.Background(), server.Id.Hex())
	s.Equal("updated-alias", retrieved.Alias)

	// List
	servers, err := s.service.ListServers(context.Background())
	s.NoError(err)
	s.Len(servers, 1)

	// Delete
	err = s.service.DeleteServer(context.Background(), server.Id.Hex())
	s.NoError(err)

	_, err = s.service.GetServer(context.Background(), server.Id.Hex())
	s.Error(err)
}

func TestServerServiceSuite(t *testing.T) {
	suite.Run(t, new(ServerServiceTestSuite))
}
