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

// RegisterClient persists the client and mints its stream-client token. parentJTI
// is the JTI of the IAT redeemed to register the client; it is threaded onto the
// minted token as its lineage parent (ADR 0007). It may be empty.
func (s *ClientService) RegisterClient(ctx context.Context, client model.SsfClient, projectID string, parentJTI string) *model.RegisterResponse {
	err := s.clientDAO.Insert(ctx, &client)
	if err != nil {
		csLog.Error("Error registering client", "error", err)
		return nil
	}

	// Issue the stream-client (management) token. Only stream-management roles are
	// minted here: stream_mgmt always, and stream_admin when AllowedScopes carries
	// it (out-of-band provisioning, capped below by the /register ceiling).
	//
	// event_delivery is deliberately NOT minted, even when AllowedScopes records it
	// as a granted capability. Event delivery is authorized by a separate per-stream
	// delivery token (IssueStreamToken), so the management token's roles diverge
	// from AllowedScopes by design (#140). See SsfClient.AllowedScopes.
	admin := slices.Contains(client.AllowedScopes, authSupport.ScopeStreamAdmin)
	token, err := s.keyService.GetAuthIssuer().IssueStreamClientToken(client, projectID, admin, parentJTI)
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
