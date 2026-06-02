package services

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"reflect"

	"strings"

	"github.com/i2-open/i2goSignals/internal/dao/interfaces"
	"github.com/i2-open/i2goSignals/pkg/logger"
	"github.com/i2-open/i2goSignals/pkg/oauthClient"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/i2-open/i2goSignals/pkg/wellKnownSupport"
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

		srvLog.Warn("STS admin credential exchange mode not supported for server-to-server communications", "alias", server.Alias, "err", err)
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

	// Determine the server Type via well-known discovery when the caller leaves
	// it empty. An explicit caller value always wins. The CLI deliberately
	// leaves Type unset (PRD #83 / #85: no --type flag), so the server is
	// authoritative. See resolveServerType for the discovery ladder.
	if server.Type == "" {
		server.Type = s.resolveServerType(ctx, server)
	}

	// We are assuming the client previously validated the server. We may still need to deal with connectivity issues where the admin server can reach the SSF server but this server cannot.

	return s.serverDAO.Create(ctx, server)
}

// resolveServerType classifies a peer server by querying its well-known
// metadata rather than guessing from the auth mode (issue #141). The only
// positive signal for a goSignals peer is gosignals_version in SSF discovery;
// PRM/OIDC are used for reachability + endpoint harvest, never to decide type.
//
// Discovery ladder (runs for OAuth-client / token / IAT modes):
//
//	1. SSF discovery parses AND has gosignals_version -> gosignals
//	2. SSF discovery parses, but no gosignals_version  -> ssf
//	3. No SSF discovery, but PRM resolves              -> ssf (harvest endpoints)
//	4. Nothing resolves                                -> gosignals (provenance)
//
// SPIFFE skips the ladder and stays gosignals by provenance (closed trust
// domain, never a foreign SSF peer; avoids a handshake just to classify).
func (s *ServerService) resolveServerType(ctx context.Context, server *model.Server) string {
	if server.GetAuthMode() == model.AuthModeSpiffe {
		return model.ServerTypeGosignals
	}

	client, closeClient, err := oauthClient.GetClientForServer(ctx, server)
	if err != nil {
		srvLog.Debug("Type discovery: could not build client, defaulting to gosignals by provenance",
			"alias", server.Alias, "err", err)
		return model.ServerTypeGosignals
	}
	defer closeClient()

	// Step 1 & 2: SSF discovery is the only signal that can yield gosignals.
	if cfg, err := wellKnownSupport.FetchSSFConfiguration(ctx, client, server.Host); err == nil && cfg != nil {
		server.ServerConfiguration = cfg
		if cfg.IsGoSignalsServer() {
			return model.ServerTypeGosignals
		}
		return model.ServerTypeSsf
	}

	// Step 3: No (parseable) SSF discovery -> try PRM. An external RFC8935/8936
	// server is ssf; harvest its overlapping metadata into ServerConfiguration.
	if prm, err := wellKnownSupport.FetchProtectedResourceMetadata(ctx, client, server.Host); err == nil && prm != nil {
		if server.ServerConfiguration == nil {
			server.ServerConfiguration = &model.TransmitterConfiguration{}
		}
		server.ServerConfiguration.AuthorizationServers = prm.AuthorizationServers
		server.ServerConfiguration.ScopesSupported = prm.ScopesSupported
		server.ServerConfiguration.BearerMethodsSupported = prm.BearerMethodsSupported
		return model.ServerTypeSsf
	}

	// Step 4: Nothing resolved -> keep gosignals by provenance. OAuth-client
	// mode has already hard-failed reachability upstream, so this path is for
	// token/IAT peers we simply could not probe.
	srvLog.Debug("Type discovery: no SSF/PRM metadata, defaulting to gosignals by provenance",
		"alias", server.Alias, "host", server.Host)
	return model.ServerTypeGosignals
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
		tokenURL, err := oauthClient.DiscoverTokenURL(ctx, server.Host, oauthClient.GetBaseHTTPClientForServer(server))
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

// CheckTransmitterWellknown checks that we are able to communicate with the transmitter host by querying its well-known SSF configuration endpoint
func CheckTransmitterWellknown(ctx context.Context, client *http.Client, auth string, server *model.Server) error {
	if client == nil {
		client = http.DefaultClient
	}
	if auth != "" {
		// Create a new client with the auth header if necessary, or wrap the existing one.
		// However, the existing client might already have a RoundTripper that handles auth.
		// If we are passed an 'auth' string here, it's usually a Bearer token.
		// We can use a custom RoundTripper to add the header.
		originalTransport := client.Transport
		if originalTransport == nil {
			originalTransport = http.DefaultTransport
		}
		client = &http.Client{
			Transport: &authRoundTripper{
				next:  originalTransport,
				token: auth,
			},
			Timeout: client.Timeout,
		}
	}

	srvLog.Debug("Checking transmitter", "alias", server.Alias, "url", server.Host)
	err := wellKnownSupport.CheckSSFConfiguration(ctx, client, server.Host)
	if err != nil {
		srvLog.Warn("Failed to connect to transmitter", "alias", server.Alias, "url", server.Host, "err", err)
		return fmt.Errorf("transmitter not reachable at %s error: %w", server.Host, err)
	}

	srvLog.Debug("Transmitter well-known endpoint reachable", "alias", server.Alias, "url", server.Host)
	return nil
}

type authRoundTripper struct {
	next  http.RoundTripper
	token string
}

func (a *authRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("Authorization", a.token)
	return a.next.RoundTrip(req)
}
