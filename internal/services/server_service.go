package services

import (
	"context"
	"errors"

	"github.com/i2-open/i2goSignals/internal/dao/interfaces"
	"github.com/i2-open/i2goSignals/internal/logger"
	"github.com/i2-open/i2goSignals/internal/model"
)

var srvLog = logger.Sub("SERVER_SERVICE")

var ErrServerAlreadyExists = errors.New("server alias already exists")

type ServerService struct {
	serverDAO interfaces.ServerDAO
}

func NewServerService(serverDAO interfaces.ServerDAO) *ServerService {
	return &ServerService{
		serverDAO: serverDAO,
	}
}

func (s *ServerService) CreateServer(ctx context.Context, server *model.Server) error {
	existing, err := s.serverDAO.FindByAlias(ctx, server.Alias)
	if err == nil && existing != nil {
		return ErrServerAlreadyExists
	}

	return s.serverDAO.Create(ctx, server)
}

func (s *ServerService) GetServer(ctx context.Context, id string) (*model.Server, error) {
	return s.serverDAO.FindByID(ctx, id)
}

func (s *ServerService) GetServerByAlias(ctx context.Context, alias string) (*model.Server, error) {
	return s.serverDAO.FindByAlias(ctx, alias)
}

func (s *ServerService) UpdateServer(ctx context.Context, server *model.Server) error {
	existing, err := s.serverDAO.FindByAlias(ctx, server.Alias)
	if err == nil && existing != nil && existing.Id != server.Id {
		return ErrServerAlreadyExists
	}
	return s.serverDAO.Update(ctx, server)
}

func (s *ServerService) DeleteServer(ctx context.Context, id string) error {
	return s.serverDAO.Delete(ctx, id)
}

func (s *ServerService) ListServers(ctx context.Context) ([]model.Server, error) {
	return s.serverDAO.List(ctx)
}
