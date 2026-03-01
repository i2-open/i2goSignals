package services

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"reflect"

	"strings"

	"slices"

	"github.com/i2-open/i2goSignals/internal/dao/interfaces"
	"github.com/i2-open/i2goSignals/internal/logger"
	"github.com/i2-open/i2goSignals/internal/model"
	"github.com/i2-open/i2goSignals/internal/oauthClient"
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

	switch server.GetAuthMode() {
	case model.AuthModeClient:
		if err := s.validateOAuthClientConfig(ctx, server); err != nil {
			srvLog.Warn("Failed to validate OAuth client config", "alias", server.Alias, "err", err)
			return err
		}
	case model.AuthModeSts:
		srvLog.Warn("Authentication mode (e.g. STS) not supported for SSF streams", "alias", server.Alias, "err", err)
		return errors.New("either OAuthClientConfig, ClientToken, or IatToken must be provided")
	case model.AuthModeToken:
		if err := s.validateTokenConfig(ctx, server); err != nil {
			srvLog.Warn("Failed to validate client token config", "alias", server.Alias, "err", err)
			return err
		}
	case model.AuthModeIaT:
		srvLog.Info("Authentication using an IAT for a Server cannot be validated in advance.", "alias", server.Alias)
		// TODO: Validate IAT token based config? Issue is that validation of an IAT may cause IAT to expire
	}

	// We are assuming the client previously validated the server. We may still need to deal with connectivity issues where the admin server can reach the SSF server but this server cannot.

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
	cfg := oauthClient.Config{
		TokenURL:     server.OAuthClientConfig.TokenURL,
		ClientID:     server.OAuthClientConfig.ClientID,
		ClientSecret: server.OAuthClientConfig.ClientSecret,
		Audience:     server.OAuthClientConfig.Audience,
		Resource:     server.OAuthClientConfig.Resource,
		Scopes:       server.OAuthClientConfig.Scopes,
	}
	if server.OAuthClientConfig.TokenURL == "" {
		tokenURL, err := oauthClient.DiscoverTokenURL(ctx, server.Host, nil)
		if err != nil {
			return err
		}
		server.OAuthClientConfig.TokenURL = tokenURL
		cfg.TokenURL = tokenURL
	}

	client, err := oauthClient.GetClientCredentialsClient(ctx, cfg, server)
	if err != nil {
		srvLog.Warn("Failed to obtain client credentials", "alias", server.Alias, "server", server.Host, "err", err)
		return err
	}
	srvLog.Debug("Obtained client token transmitter", "alias", server.Alias, "server", server.Host, "tokenUrl", cfg.TokenURL)

	err = CheckTransmitterWellknown(ctx, client, "", server)
	if err != nil {
		srvLog.Warn("Failed to validate transmitter server configuration", "alias", server.Alias, "err", err)
	}
	return err
}

func (s *ServerService) DeleteServer(ctx context.Context, id string) error {
	return s.serverDAO.Delete(ctx, id)
}

func (s *ServerService) ListServers(ctx context.Context) ([]model.Server, error) {
	return s.serverDAO.List(ctx)
}

func (s *ServerService) validateTokenConfig(ctx context.Context, server *model.Server) error {
	client := oauthClient.GetBaseHTTPClientForServer(server)
	token := *server.ClientToken
	if !strings.Contains(token, " ") {
		token = "Bearer " + token
	}

	return CheckTransmitterWellknown(ctx, client, token, server)
}

// CheckTransmitterWellknown checks that we are able to communicate with the transmitter host by querying its well-known OpenID configuration endpoint
func CheckTransmitterWellknown(ctx context.Context, client *http.Client, auth string, server *model.Server) error {
	serverURL, err := url.Parse(server.Host)
	if err != nil {
		return err
	}
	if serverURL.Scheme != "https" && serverURL.Scheme != "http" {
		serverURL.Scheme = "https"
	}
	var candidates []string
	basePath := serverURL.Path
	if idx := strings.Index(serverURL.Path, "/.well-known"); idx != -1 {
		candidates = append(candidates, serverURL.Path)
		basePath = serverURL.Path[:idx]
	}
	basePath = strings.TrimSuffix(basePath, "/")
	calculatedPath := basePath + "/.well-known/ssf-configuration"
	if !slices.Contains(candidates, calculatedPath) {
		candidates = append(candidates, calculatedPath)
	}

	success := false
	var resp *http.Response
	var req *http.Request
	for _, path := range candidates {
		serverURL.Path = path
		req, err = http.NewRequestWithContext(ctx, http.MethodGet, serverURL.String(), nil)
		if err != nil {
			return err
		}
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		srvLog.Debug("Checking transmitter", "alias", server.Alias, "url", serverURL.String())
		resp, err = client.Do(req)

		if err != nil {
			srvLog.Warn("Failed to connect to transmitter", "alias", server.Alias, "url", serverURL.String(), "err", err)
			continue // this didn't work
		}
		_ = resp.Body.Close() // only interested in connectivity
		if resp.StatusCode == 200 {
			success = true
			break
		}
	}
	if !success {
		errMsg := fmt.Sprintf("transmitter not reachable at %s", serverURL.String())
		if err != nil {
			errMsg = errMsg + fmt.Sprintf(" error: %s", err.Error())
		}
		return errors.New(errMsg)
	}
	srvLog.Debug("Transmitter well-known endpoint reachable", "alias", server.Alias, "url", serverURL.String())
	return nil
}
