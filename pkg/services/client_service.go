package services

import (
	"context"
	"slices"

	"github.com/i2-open/i2goSignals/pkg/authSupport"
	interfaces "github.com/i2-open/i2goSignals/pkg/dao"
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

	// Issue the stream-client token from the client's granted capabilities:
	// stream_mgmt always, stream_admin when AllowedScopes carries it (out-of-band
	// provisioning, capped by the /register ceiling), and event_delivery when
	// granted. Minting event_delivery as a role lets a single registered token
	// drive both stream management and the delivery endpoints (poll/events) — a
	// token with empty StreamIds authorizes any stream in the project and the
	// delivery handlers take the stream id from the request path. This supersedes
	// the earlier #140 divergence, which withheld event from the token on the
	// (incorrect) premise that such a token would be rejected at delivery anyway.
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
