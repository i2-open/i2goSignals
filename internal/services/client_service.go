package services

import (
	"context"

	"github.com/i2-open/i2goSignals/internal/dao/interfaces"
	"github.com/i2-open/i2goSignals/pkg/logger"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
)

var csLog = logger.Sub("CLIENT_SERVICE")

type ClientService struct {
	clientDAO  interfaces.ClientDAO
	keyService *KeyService
}

func NewClientService(clientDAO interfaces.ClientDAO, keyService *KeyService) *ClientService {
	return &ClientService{
		clientDAO:  clientDAO,
		keyService: keyService,
	}
}

func (s *ClientService) RegisterClient(ctx context.Context, client model.SsfClient, projectID string) *model.RegisterResponse {
	err := s.clientDAO.Insert(ctx, &client)
	if err != nil {
		csLog.Error("Error registering client", "error", err)
		return nil
	}

	token, err := s.keyService.GetAuthIssuer().IssueStreamClientToken(client, projectID, true)
	if err != nil {
		csLog.Error("Error issuing stream admin token", "error", err)
		return nil
	}

	return &model.RegisterResponse{Token: token}
}

func (s *ClientService) GetClient(ctx context.Context, id string) (*model.SsfClient, error) {
	return s.clientDAO.FindByID(ctx, id)
}

func (s *ClientService) DeleteClient(ctx context.Context, id string) error {
	return s.clientDAO.Delete(ctx, id)
}
