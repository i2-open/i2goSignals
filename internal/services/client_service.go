package services

import (
	"context"
	"slices"

	"github.com/i2-open/i2goSignals/internal/dao/interfaces"
	"github.com/i2-open/i2goSignals/pkg/authSupport"
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

	// Issue a token reflecting only the scopes the client was actually granted.
	// A self-registered client is capped below stream_admin by the registration
	// handler's privilege ceiling, so admin is granted only when the client's
	// AllowedScopes explicitly carry stream_admin (out-of-band provisioning).
	admin := slices.Contains(client.AllowedScopes, authSupport.ScopeStreamAdmin)
	token, err := s.keyService.GetAuthIssuer().IssueStreamClientToken(client, projectID, admin)
	if err != nil {
		csLog.Error("Error issuing stream client token", "error", err)
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
