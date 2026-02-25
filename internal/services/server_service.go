package services

import (
	"context"
	"errors"
	"reflect"

	"github.com/i2-open/i2goSignals/internal/dao/interfaces"
	"github.com/i2-open/i2goSignals/internal/logger"
	"github.com/i2-open/i2goSignals/internal/model"
	oauthclient "github.com/i2-open/i2goSignals/internal/oauthClient"
)

var srvLog = logger.Sub("SERVICE")

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

	if server.OAuthClientConfig != nil {
		if err := s.validateOAuthClientConfig(ctx, server); err != nil {
			srvLog.Warn("Failed to validate OAuth client config", "alias", server.Alias, "err", err)
			return err
		}
	} else if (server.ClientToken == nil || *server.ClientToken == "") && (server.IatToken == nil || *server.IatToken == "") {
		return errors.New("either OAuthClientConfig, ClientToken, or IatToken must be provided")
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
	existing, err := s.serverDAO.FindByID(ctx, server.Id.Hex())
	if err != nil {
		return err
	}

	// Check if alias changed and if new alias already exists
	if existing.Alias != server.Alias {
		aliasCheck, err := s.serverDAO.FindByAlias(ctx, server.Alias)
		if err == nil && aliasCheck != nil {
			srvLog.Warn("Server alias already exists", "alias", server.Alias)
			return ErrServerAlreadyExists
		}
	}

	// Validate OAuthClientConfig if it has changed
	if !reflect.DeepEqual(existing.OAuthClientConfig, server.OAuthClientConfig) {
		if server.OAuthClientConfig != nil {
			if err := s.validateOAuthClientConfig(ctx, server); err != nil {
				srvLog.Warn("Failed to validate OAuth client config", "alias", server.Alias, "err", err)
				return err
			}
		} else if (server.ClientToken == nil || *server.ClientToken == "") && (server.IatToken == nil || *server.IatToken == "") {
			return errors.New("either OAuthClientConfig, ClientToken, or IatToken must be provided")
		}
	}

	return s.serverDAO.Update(ctx, server)
}

func (s *ServerService) validateOAuthClientConfig(ctx context.Context, server *model.Server) error {
	if server.OAuthClientConfig == nil {
		return nil
	}

	if server.OAuthClientConfig.TokenURL == "" {
		tokenURL, err := oauthclient.DiscoverTokenURL(ctx, server.Host)
		if err != nil {
			return err
		}
		server.OAuthClientConfig.TokenURL = tokenURL
	}

	cfg := oauthclient.Config{
		TokenURL:     server.OAuthClientConfig.TokenURL,
		ClientID:     server.OAuthClientConfig.ClientID,
		ClientSecret: server.OAuthClientConfig.ClientSecret,
		Audience:     server.OAuthClientConfig.Audience,
		Resource:     server.OAuthClientConfig.Resource,
		Scopes:       server.OAuthClientConfig.Scopes,
	}

	return oauthclient.ValidateClientCredentials(ctx, cfg)
}

func (s *ServerService) DeleteServer(ctx context.Context, id string) error {
	return s.serverDAO.Delete(ctx, id)
}

func (s *ServerService) ListServers(ctx context.Context) ([]model.Server, error) {
	return s.serverDAO.List(ctx)
}
