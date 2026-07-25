// nolint
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/i2-open/i2goSignals/pkg/authSupport"
	"github.com/i2-open/i2goSignals/pkg/goScim/resource"
	"github.com/i2-open/i2goSignals/pkg/httpSupport"
	"github.com/i2-open/i2goSignals/pkg/ssfModels"
	"github.com/i2-open/i2goSignals/pkg/tlsSupport"
	"github.com/i2-open/i2goSignals/pkg/wellKnownSupport"
	"go.mongodb.org/mongo-driver/v2/bson"

	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/alecthomas/kong"
	_ "github.com/golang-jwt/jwt/v5"
	"github.com/i2-open/i2goSignals/pkg/goSet"
	"gopkg.in/yaml.v3"
)

// getHttpClient returns a standard or SPIFFE-aware HTTP client.
// I2SIG_TX_TLS_SKIP_VERIFY=true (conformance-only) disables cert verification
// for outbound CLI calls — the same knob the server honors for outbound push
// delivery. Used by the receiver-conformance harness against the suite's
// emulated transmitter, whose dev cert has no matching SAN.
// normalizeJWTAud rewrites a top-level `"aud": "x"` to `"aud": ["x"]` in the
// given JSON body so model.StreamConfiguration (Aud []string) can unmarshal a
// scalar audience. Per RFC 7519 §4.1.3 the `aud` claim may be a string or
// array; goSignals' wire model only handles the array form. No-op when aud is
// already an array, null, or absent. Scope: response normalization only —
// outbound bodies still emit an array.
func normalizeJWTAud(body []byte) []byte {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return body
	}
	audRaw, ok := raw["aud"]
	if !ok {
		return body
	}
	trimmed := bytes.TrimSpace(audRaw)
	if len(trimmed) == 0 || trimmed[0] != '"' {
		return body
	}
	var s string
	if err := json.Unmarshal(trimmed, &s); err != nil {
		return body
	}
	wrapped, err := json.Marshal([]string{s})
	if err != nil {
		return body
	}
	raw["aud"] = wrapped
	out, err := json.Marshal(raw)
	if err != nil {
		return body
	}
	return out
}

func getHttpClient(timeout time.Duration) *http.Client {
	client := &http.Client{Timeout: timeout}
	if spiffeSource != nil {
		transport, err := tlsSupport.NewResilientMTLSClientTransport(spiffeSource)
		if err == nil {
			client.Transport = transport
		} else {
			log.Printf("Warning: Failed to create resilient SPIFFE transport: %v", err)
			client.Transport = tlsSupport.NewClusterMTLSClientTransport(spiffeSource)
		}
	} else if strings.EqualFold(os.Getenv("I2SIG_TX_TLS_SKIP_VERIFY"), "true") {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // explicit opt-in via I2SIG_TX_TLS_SKIP_VERIFY (conformance-only)
		}
	} else {
		tlsSupport.CheckCaInstalled(client)
	}
	return client
}

type AddServerCmd struct {
	Alias        string   `arg:"" help:"A unique name to identify the server"`
	Host         string   `arg:"" required:"" help:"Http URL for a goSignals server"`
	Desc         string   `help:"Description of project"`
	Email        string   `help:"Contact email for project"`
	Iat          string   `help:"Registration Initial Access Auth if provided (non-interactive)"`
	Token        string   `help:"Administration authorization token (non-interactive)"`
	ClientId     string   `help:"OAuth client_id for a foreign SSF transmitter (client-credentials grant)"`
	ClientSecret string   `help:"OAuth client secret for non-interactive client-credentials use"`
	TokenUrl     string   `help:"OAuth token endpoint for the transmitter (optional; discovered if omitted)"`
	Scopes       []string `sep:"," help:"Comma-separated OAuth scopes for the client-credentials grant"`
	Bootstrap    bool     `help:"Use the I2SIG_BOOTSTRAP_TOKEN shared secret to mint an IAT (non-interactive)"`
	StrictSsf    bool     `name:"strict-ssf" help:"Treat the server as a strict-spec SSF transmitter (SSF §8.1.1.1): the CLI will strip iss/aud/issuerJWKSUrl from publisher-leg POSTs. Use for the OpenID conformance suite; leave off for goSignals-to-goSignals cluster connections."`
}

func (as *AddServerCmd) Run(c *CLI) error {
	_, exists := c.Data.Servers[as.Alias]
	if exists {
		return errors.New("server alias already exists")
	}
	var serverUrl *url.URL
	var err error
	if strings.Index(strings.ToUpper(as.Host), "HTTP") == -1 {
		serverUrl = &url.URL{
			Scheme:     "https",
			Host:       as.Host,
			OmitHost:   false,
			ForceQuery: false,
		}
	} else {
		serverUrl, err = url.Parse(as.Host)
		if err != nil {
			return err
		}
	}
	server := SsfServer{
		Alias:     as.Alias,
		Host:      serverUrl.String(),
		Streams:   map[string]Stream{},
		StrictSsf: as.StrictSsf,
	}
	// Build the discovery URL per SSF §7.2 / RFC 8615 (issue #187): the
	// well-known component is INSERTED between the host and any issuer path,
	// not appended. The OpenID conformance suite's emulated transmitter lives
	// under /test/a/<alias>, so an issuer of
	//   https://host/test/a/<alias>
	// must be probed at
	//   https://host/.well-known/ssf-configuration/test/a/<alias>
	// A host-only issuer yields https://host/.well-known/ssf-configuration.
	discoveryUrlStr, err := wellKnownSupport.InsertWellKnownURL(serverUrl.String(), wellKnownSupport.SSFConfigurationPath)
	if err != nil {
		return err
	}
	tryUrl, err := url.Parse(discoveryUrlStr)
	if err != nil {
		return err
	}
	fmt.Println("Loading server configuration from: " + tryUrl.String())
	var resp *http.Response
	client := getHttpClient(30 * time.Second)
	resp, err = client.Get(tryUrl.String())
	defer httpSupport.HandleRespClose(resp)
	if err != nil {
		if strings.Contains(err.Error(), "gave HTTP response") {
			tryUrl.Scheme = "http"
			serverUrl.Scheme = "http"
			fmt.Println("Warning: HTTPS not supported trying HTTP at: " + tryUrl.String())
			resp, err = client.Get(tryUrl.String())
			defer httpSupport.HandleRespClose(resp)
			if err != nil {
				return err
			}
			serverUrl.Scheme = "http"
			server.Host = serverUrl.String()
		} else {
			return err
		}
	}
	body, _ := io.ReadAll(resp.Body)
	var transmitterConfiguration model.TransmitterConfiguration
	err = json.Unmarshal(body, &transmitterConfiguration)
	if err != nil {
		return err
	}
	server.ServerConfiguration = &transmitterConfiguration

	// SSF §7.2.4 issuer binding: the issuer advertised in the discovery document
	// must equal the location it was retrieved from (server.Host carries any
	// HTTP-fallback scheme change). jwks_uri is free-form and not checked. A
	// strict-spec transmitter (--strict-ssf) must bind exactly or the add aborts;
	// a flexible peer only warns. Keyed off the per-server StrictSsf posture, NOT
	// the goSsfServer-only I2SIG_STRICT_SSF env flag.
	if warn, berr := wellKnownSupport.EvaluateIssuerBinding(transmitterConfiguration.Issuer, server.Host, as.StrictSsf); berr != nil {
		return berr
	} else if warn != "" {
		fmt.Println("Warning: " + warn)
	}

	// `add server` is connect-only: it performs SSF discovery and records the
	// server without minting any credential. Interactive auth happens later via
	// `login <alias>` (PKCE). The --iat/--token/--client-secret/--bootstrap
	// flags remain for non-interactive (CI/bootstrap) use.
	// oauthStaged tracks whether this is a foreign SSF transmitter registered
	// via OAuth client credentials. Such a server is a polling target, not the
	// active management server, so it must NOT become Selected.
	oauthStaged := false
	switch {
	case as.ClientId != "":
		// Foreign SSF transmitter via OAuth client-credentials. Stage only the
		// NON-SECRET fields into config.json; the client secret is held in
		// memory (consumed in-process) and never persisted. No POST /server is
		// made here — registration happens at `create stream poll receive
		// --tx-alias` time (slice #86) against the receiver node.
		server.OAuthClientConfig = &model.OAuthClientConfig{
			ClientID: cleanQuotes(as.ClientId),
			TokenURL: cleanQuotes(as.TokenUrl),
			Scopes:   as.Scopes,
		}
		if as.ClientSecret != "" {
			c.Data.stageSecret(as.Alias, cleanQuotes(as.ClientSecret))
		}
		oauthStaged = true
		fmt.Printf("Staged OAuth client credentials for transmitter '%s' (secret kept in memory, not written to config).\n", as.Alias)
	case as.Iat != "":
		server.IatToken = cleanQuotes(as.Iat)
	case as.Token != "":
		server.ClientToken = cleanQuotes(as.Token)
	case as.ClientSecret != "":
		// #127 surrogate: --client-secret WITHOUT --client-id. Stored for
		// non-interactive flows as a client token surrogate; the server
		// validates it on use.
		server.ClientToken = cleanQuotes(as.ClientSecret)
	case as.Bootstrap:
		// Explicit opt-in: mint an IAT using the shared bootstrap secret
		// (I2SIG_BOOTSTRAP_TOKEN). The anonymous /iat path is closed.
		boot := os.Getenv("I2SIG_BOOTSTRAP_TOKEN")
		if boot == "" {
			return errors.New("--bootstrap requires I2SIG_BOOTSTRAP_TOKEN to be set")
		}
		iatUrl, _ := serverUrl.Parse("/iat")
		fmt.Println("Obtaining authorization via bootstrap secret...")
		iatReq, _ := http.NewRequest(http.MethodGet, iatUrl.String(), nil)
		iatReq.Header.Set("Authorization", "Bearer "+boot)
		resp, err = client.Do(iatReq)
		defer httpSupport.HandleRespClose(resp)
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusOK {
			fmt.Println("Error: unable to obtain registration IAT token")
			return errors.New("unexpected status obtaining IAT: " + resp.Status)
		}
		regBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		var registration model.RegisterResponse
		if err = json.Unmarshal(regBytes, &registration); err != nil {
			return err
		}
		server.IatToken = registration.Token
		fmt.Println("Bootstrap mode: IAT recorded; client auto-registration skipped for " + as.Alias)
	default:
		// Connect-only. Attempt PRM discovery to cache the advertised
		// authorization_servers so a subsequent `login` can proceed without
		// re-discovery. Discovery failure is non-fatal (the server may simply
		// not advertise OAuth; bootstrap-secret flows still work).
		if prm, derr := discoverProtectedResource(server.Host); derr == nil && prm != nil {
			server.AuthorizationServers = prm.AuthorizationServers
			if len(prm.AuthorizationServers) > 0 {
				fmt.Printf("Discovered authorization server(s): %v\n", prm.AuthorizationServers)
				fmt.Printf("Run 'login %s' to authenticate.\n", as.Alias)
			} else {
				fmt.Println("Server does not advertise OAuth authorization_servers; use --bootstrap or --token for non-interactive auth.")
			}
		} else {
			fmt.Println("Server recorded (no protected-resource metadata advertised).")
		}
	}

	c.Data.Servers[as.Alias] = server
	if !oauthStaged {
		c.Data.Selected = as.Alias
	}
	cmd := ShowServerCmd{Alias: as.Alias}
	_ = cmd.Run(c)
	return c.Data.Save(&c.Globals)
}

type AddCmd struct {
	Server AddServerCmd `cmd:"" help:"Add a server to be configured."`
}

type CreatePollPublisherCmd struct {
	Alias string `arg:"" optional:"" help:"The alias of the server to create the stream on (default is selected server)"`
	Mode  string `optional:"" default:"PUBLISH" enum:"FORWARD,PUBLISH,F,P" help:"What should the receiver to with received events"`
}

func (p *CreatePollPublisherCmd) Run(cli *CLI) error {
	c := cli.Create.Stream

	reg := model.StreamConfiguration{
		Aud: c.Aud,
		Iss: c.Iss,
		Delivery: &model.OneOfStreamConfigurationDelivery{
			PollTransmitMethod: &model.PollTransmitMethod{
				Method: model.DeliveryPoll,
			},
		},
		EventsRequested: c.Events,
		IssuerJWKSUrl:   c.IssJwksUrl,
		RouteMode:       parseMode(p.Mode),
	}
	jsonString, _ := json.MarshalIndent(reg, "", "  ")
	server, err := cli.Data.GetServer(p.Alias)
	if err != nil {
		return err
	}
	out := fmt.Sprintf("Create publish POLL stream on: %s\n%s", server.ServerConfiguration.ConfigurationEndpoint, jsonString)
	fmt.Println(out)

	if !ConfirmProceed("") {
		return nil
	}
	_, err = cli.executeCreateRequest(c.Name, reg, server, "Poll Publisher", "")
	return err
}

type CreatePushPublisherCmd struct {
	Alias    string `arg:"" optional:"" help:"The alias of the server to create the stream on (default is selected server)"`
	EventUrl string `short:"e" group:"man" optional:"" help:"Provide the endpoint where events may be delivered using SET Push. Required if Connect not provided."`
	Auth     string `group:"man" help:"Provide the authorization header to used to submit events at the endpoint url. Required if Connect not provided."`
	Connect  string `short:"c" group:"auto" xor:"auto,man" help:"The Alias of a stream which is receiving events."`
	Mode     string `optional:"" default:"PUBLISH" enum:"FORWARD,PUBLISH,F,P" help:"What should the receiver to with received events"`
}

func (p *CreatePushPublisherCmd) Run(cli *CLI) error {
	c := cli.Create.Stream

	var eventUrl string
	var eventAuthorization string
	var reg model.StreamConfiguration

	if p.Connect != "" {

		stream, _ := cli.Data.GetStreamAndServer(p.Connect)

		if stream == nil {
			return errors.New("Could not find a stream identified by " + p.Connect)
		}
		config, err := cli.Data.GetStreamConfig(stream.Alias)
		if err != nil {
			return errors.New("Error obtaining destination stream configuration: " + err.Error())
		}
		if config.Delivery.GetMethod() != model.ReceivePush {
			return errors.New(fmt.Sprintf("The specified connection %s is not a Push Receiver", p.Connect))
		}
		reg = *createRegRequestFromParams(model.DeliveryPush, p.Mode, cli, config)

	} else {
		if p.EventUrl != "" {
			eventUrl = p.EventUrl
		}
		if p.Auth != "" {
			eventAuthorization = cleanQuotes(p.Auth)
		}

		if eventUrl == "" || eventAuthorization == "" {
			return errors.New("either --url and --token parameters or --connect parameters must be specified")
		}
		method := &model.PushTransmitMethod{
			Method:              model.DeliveryPush,
			EndpointUrl:         eventUrl,
			AuthorizationHeader: eventAuthorization,
		}
		reg = model.StreamConfiguration{
			Aud:             c.Aud,
			Iss:             c.Iss,
			EventsRequested: c.Events,
			Delivery:        &model.OneOfStreamConfigurationDelivery{PushTransmitMethod: method},
			IssuerJWKSUrl:   c.IssJwksUrl,
			RouteMode:       parseMode(p.Mode),
		}
	}

	// Should override be allowed if destAlias is set?

	jsonString, _ := json.MarshalIndent(reg, "", "  ")
	server, err := cli.Data.GetServer(p.Alias)
	if err != nil {
		return err
	}
	out := fmt.Sprintf("Create publish PUSH stream on: %s\n%s", server.ServerConfiguration.ConfigurationEndpoint, jsonString)
	fmt.Println(out)

	if !ConfirmProceed("") {
		return nil
	}
	_, err = cli.executeCreateRequest(c.Name, reg, server, "Push Publisher", "")
	return err
}

type CreatePollReceiverCmd struct {
	Alias    string `arg:"" optional:"" help:"The alias of the server to create the stream on (default is selected server)"`
	EventUrl string `short:"e" group:"man" help:"The event publishers polling endpoint URL. Required unless Connect specified."`
	Auth     string `group:"man" help:"An authorization header used to poll for events. Required unless Connect specified"`
	Connect  string `short:"c" group:"auto" xor:"man,auto" help:"The Alias of a stream which is publishing events using polling"`
	TxAlias  string `help:"Alias of a configured foreign SSF transmitter (e.g. 'add server --client-id'). Requires an ADMIN credential (not the IAT): the transmitter is registered on the node and the server-side TxAlias auto-registration path discovers and wires its poll endpoint."`
	Secret   string `help:"OAuth client secret for the tx-alias transmitter (non-interactive); resolved as staged->flag->env"`
	Mode     string `optional:"" default:"IMPORT" enum:"IMPORT,FORWARD,PUBLISH,I,F,P" help:"What should the receiver to with received events"`
}

func (p *CreatePollReceiverCmd) Run(cli *CLI) error {
	c := cli.Create.Stream

	var eventUrl string
	var eventAuthorization string
	var reg model.StreamConfiguration

	if p.TxAlias != "" {
		// Foreign SSF transmitter auto-registration (PRD #83 / slice #86). The
		// node owns the POST /server registration so its server-side TxAlias
		// auto-registration path can discover the transmitter's
		// ssf-configuration, register a stream, and wire the returned poll
		// endpoint. No EventUrl/Auth is supplied here — the server resolves them.
		reg = model.StreamConfiguration{
			Aud:             c.Aud,
			Iss:             c.Iss,
			Delivery:        &model.OneOfStreamConfigurationDelivery{PollReceiveMethod: &model.PollReceiveMethod{Method: model.ReceivePoll}},
			EventsRequested: c.Events,
			IssuerJWKSUrl:   c.IssJwksUrl,
			RouteMode:       parseMode(p.Mode),
			TxAlias:         &p.TxAlias,
		}
	} else if p.Connect != "" {
		stream, _ := cli.Data.GetStreamAndServer(p.Connect)
		if stream == nil {
			return errors.New("Could not find a stream identified by " + p.Connect)
		}
		config, err := cli.Data.GetStreamConfig(stream.Alias)
		if err != nil {
			return errors.New("Error obtaining source stream configuration: " + err.Error())
		}
		reg = *createRegRequestFromParams(model.ReceivePoll, p.Mode, cli, config)
	} else {
		if p.EventUrl != "" {
			eventUrl = p.EventUrl
		}
		if p.Auth != "" {
			eventAuthorization = cleanQuotes(p.Auth)
		}

		if eventUrl == "" || eventAuthorization == "" {
			return errors.New("either --url and --token parameters or --connect parameters must be specified")
		}

		method := &model.PollReceiveMethod{
			Method:              model.ReceivePoll,
			EndpointUrl:         eventUrl,
			AuthorizationHeader: eventAuthorization,
		}
		if eventAuthorization != "" {
			method.AuthorizationHeader = eventAuthorization
		}
		reg = model.StreamConfiguration{
			Aud:             c.Aud,
			Iss:             c.Iss,
			Delivery:        &model.OneOfStreamConfigurationDelivery{PollReceiveMethod: method},
			EventsRequested: c.Events,
			IssuerJWKSUrl:   c.IssJwksUrl,
			RouteMode:       parseMode(p.Mode),
		}
	}

	jsonString, _ := json.MarshalIndent(reg, "", "  ")
	server, err := cli.Data.GetServer(p.Alias)
	if err != nil {
		return err
	}
	out := fmt.Sprintf("Create receiver POLL stream on: %s\n%s", server.ServerConfiguration.ConfigurationEndpoint, jsonString)
	fmt.Println(out)

	if !ConfirmProceed("") {
		return nil
	}

	// When auto-registering against a foreign SSF transmitter, register the
	// transmitter on the node (POST /server) before creating the stream so the
	// server-side TxAlias auto-registration path can resolve it. A 409 Conflict
	// is benign (already registered). The client secret rides on the request
	// body only and is never persisted to config.json.
	if p.TxAlias != "" {
		if err = cli.registerTxAliasServer(server, p.TxAlias, p.Secret, ""); err != nil {
			return err
		}
	}

	_, err = cli.executeCreateRequest(c.Name, reg, server, "Poll Receiver", "")
	return err
}

type CreatePushReceiverCmd struct {
	Alias string `arg:"" optional:"" help:"The alias of the server to create the stream on (default is selected server)"`
	Mode  string `optional:"" default:"IMPORT" enum:"IMPORT,FORWARD,PUBLISH,I,F,P" help:"What should the receiver to with received events"`
}

func (p *CreatePushReceiverCmd) Run(cli *CLI) error {
	c := cli.Create.Stream

	method := &model.PushReceiveMethod{
		Method: model.ReceivePush,
	}
	reg := model.StreamConfiguration{
		Aud:             c.Aud,
		Iss:             c.Iss,
		Delivery:        &model.OneOfStreamConfigurationDelivery{PushReceiveMethod: method},
		EventsRequested: c.Events,
		IssuerJWKSUrl:   c.IssJwksUrl,
		RouteMode:       parseMode(p.Mode),
	}
	jsonString, _ := json.MarshalIndent(reg, "", "  ")
	server, err := cli.Data.GetServer(p.Alias)
	if err != nil {
		return err
	}

	out := fmt.Sprintf("Create receiver PUSH stream  on: %s\n%s", server.ServerConfiguration.ConfigurationEndpoint, jsonString)

	fmt.Println(out)

	if !ConfirmProceed("") {
		return nil
	}

	_, err = cli.executeCreateRequest(c.Name, reg, server, "Push Receiver", "")
	return err
}

type CreatePollConnectionCmd struct {
	SourceAlias string `arg:"" help:"The alias of the publishing server or existing stream alias."`
	DestAlias   string `arg:"" help:"The alias of receiving server."`
	Mode        string `optional:"" default:"IMPORT" enum:"IMPORT,FORWARD,REPUBLISH,I,F,R" help:"What should the receiver to with received events"`
}

// createRegRequestFromParams creates the complimentary connecting stream based on an input stream.
//
// Parameters include:
// - method indicates the delivery type desired (one of urn:ietf:rfc:8935|8936|8935:receive|8936:receive )
// - modParam indicates what a receiver should do with a received event (import-IM, forward-FW,or republish-PB)
// - connectingConfig is the configuration of a stream that will be connected to.
func createRegRequestFromParams(method string, modeParam string, cli *CLI, connectingConfig *model.StreamConfiguration) *model.StreamConfiguration {
	reg := &model.StreamConfiguration{}

	delivery := &model.OneOfStreamConfigurationDelivery{}

	switch method {
	case model.DeliveryPush:
		endpoint := ""
		auth := ""
		if connectingConfig != nil && connectingConfig.Delivery != nil && connectingConfig.Delivery.PushReceiveMethod != nil {
			endpoint = connectingConfig.Delivery.PushReceiveMethod.EndpointUrl
			auth = connectingConfig.Delivery.PushReceiveMethod.AuthorizationHeader
		}
		delivery.PushTransmitMethod = &model.PushTransmitMethod{
			Method:              model.DeliveryPush,
			EndpointUrl:         endpoint,
			AuthorizationHeader: auth,
		}

	case model.ReceivePush:
		delivery.PushReceiveMethod = &model.PushReceiveMethod{
			Method: model.ReceivePush,
		}

	case model.DeliveryPoll:
		delivery.PollTransmitMethod = &model.PollTransmitMethod{
			Method: model.DeliveryPoll,
		}

	case model.ReceivePoll:
		endpoint := ""
		auth := ""
		if connectingConfig != nil && connectingConfig.Delivery != nil && connectingConfig.Delivery.PollTransmitMethod != nil {
			endpoint = connectingConfig.Delivery.PollTransmitMethod.EndpointUrl
			auth = connectingConfig.Delivery.PollTransmitMethod.AuthorizationHeader
		}
		delivery.PollReceiveMethod = &model.PollReceiveMethod{
			Method:              model.ReceivePoll,
			EndpointUrl:         endpoint,
			AuthorizationHeader: auth,
		}
	}

	reg.Delivery = delivery

	reg.RouteMode = parseMode(modeParam)

	if connectingConfig != nil {
		reg.EventsRequested = connectingConfig.EventsDelivered
		reg.Aud = connectingConfig.Aud
		reg.Iss = connectingConfig.Iss
		reg.IssuerJWKSUrl = connectingConfig.IssuerJWKSUrl
	}

	// command parameters always override existing configuration
	streamParams := cli.Create.Stream

	if len(streamParams.Events) > 0 && streamParams.Events[0] != "*" {
		supportedEvents := model.GetSupportedEvents()
		if connectingConfig != nil {
			supportedEvents = connectingConfig.EventsDelivered
		}
		reg.EventsRequested = calculateEvents(streamParams.Events, supportedEvents)
	}

	if len(streamParams.Aud) > 0 {
		reg.Aud = streamParams.Aud
	}

	if streamParams.Iss != "" {
		reg.Iss = streamParams.Iss
	}

	if streamParams.IssJwksUrl != "" {
		reg.IssuerJWKSUrl = streamParams.IssJwksUrl
	}

	return reg
}

// calculateEvents resolves the operator's requested event patterns against the
// transmitter's advertised events_supported. The glob semantics live in
// model.MatchDeliveredEvents so the CLI and the server share exactly one
// implementation of the pattern -> URI matching.
func calculateEvents(requested []string, supported []string) []string {
	return model.MatchDeliveredEvents(requested, supported)
}

func (p *CreatePollConnectionCmd) Run(cli *CLI) error {
	// In this request, the PUSH ServerUrl is created first
	strCmdParams := cli.Create.Stream
	streamPub, serverPub := cli.Data.GetStreamAndServer(p.SourceAlias)
	streamRcv, serverRcv := cli.Data.GetStreamAndServer(p.DestAlias)

	if serverPub == nil {
		return errors.New("unable to match publication server for alias: " + p.SourceAlias)
	}

	if serverRcv == nil {
		return errors.New("unable to match destination server for destination alias: " + p.DestAlias)
	}
	if streamRcv != nil {
		return errors.New(fmt.Sprintf("connecting to an existing receiver stream (%s) is not supported for POLLING connections", streamRcv.Alias))
	}

	var regReceiveStreamRequest, regPublisherStreamRequest *model.StreamConfiguration

	name := generateAlias(3)
	pubName := name + "-pub"
	rcvName := name + "-rcv"
	if streamPub != nil {
		name = streamPub.Alias
		pubName = name
		rcvName = name + "-rcv"
	} else {
		if strCmdParams.Name != "" {
			name = strCmdParams.Name
			pubName = name + "-pub"
			rcvName = name + "-rcv"
		}
	}

	if streamPub != nil {
		streamConfig, err := cli.Data.GetStreamConfig(streamPub.Alias)
		if err != nil {
			return errors.New("Unable to load existing publisher stream configuration: " + err.Error())
		}
		regReceiveStreamRequest = createRegRequestFromParams(model.ReceivePoll, p.Mode, cli, streamConfig)

		fmt.Printf("Create a polling receiver to work with %s with the following request:", streamPub.Alias)
		jsonBytes, _ := json.MarshalIndent(regReceiveStreamRequest, "", " ")
		fmt.Println(string(jsonBytes))
		if !ConfirmProceed("") {
			return nil
		}
	} else {
		// Both a publisher and receiver must be generated

		// If issJwksUrl was omitted try to see if available on publisher
		if strCmdParams.IssJwksUrl == "" {
			// check if there is an issuer key on the publishing server.
			if strCmdParams.Iss == "" {
				return errors.New("a value for issuer 'iss' is required")
			}
			tryUrl := fmt.Sprintf("%s/jwks/%s", serverPub.Host, strCmdParams.Iss)
			jwks, err := goSet.GetJwks(tryUrl)
			if jwks != nil && err == nil {
				strCmdParams.IssJwksUrl = tryUrl
			} else {
				return errors.New("a value for 'issJwksUrl' is required")
			}
		}
		regPublisherStreamRequest = createRegRequestFromParams(model.DeliveryPoll, p.Mode, cli, nil)
		fmt.Printf("Creating publishing and receiver poll streams on %s and %s based on the following:", serverPub.Alias, serverRcv.Alias)
		jsonBytes, _ := json.MarshalIndent(regPublisherStreamRequest, "", " ")
		fmt.Println(string(jsonBytes))
		if !ConfirmProceed("") {
			return nil
		}
	}

	var pubConfig *model.StreamConfiguration
	var err error
	if regPublisherStreamRequest != nil {
		fmt.Println("Creating publisher stream...")
		pubConfig, err = cli.executeCreateRequest(pubName, *regPublisherStreamRequest, serverPub, "Poll Publisher Connection to "+rcvName, rcvName)
		if err != nil {
			return errors.New(fmt.Sprintf("Error creating polling publisher stream on %s: %s", serverPub.Alias, err.Error()))
		}
		fmt.Printf("... %s created.", pubName)
		streamPub, _ = cli.Data.GetStreamAndServer(pubName)
	}
	if regReceiveStreamRequest == nil {
		// if this is null it is because the publisher was created in the previous block (rather than pre-existing)

		// Build the receiver stream based on the new publisher stream
		regReceiveStreamRequest = createRegRequestFromParams(model.ReceivePoll, p.Mode, cli, pubConfig)
	}

	// Carry the foreign transmitter's bearer onto the receiver stream as
	// TxToken so outbound verify / status / stream-management calls back to
	// that transmitter are authenticated. The bearer is the operator-configured
	// token used when `add server <pub-alias> --token=<...>` registered the
	// publisher; without it those calls land unauthorized.
	if serverPub != nil && serverPub.ClientToken != "" {
		tok := serverPub.ClientToken
		regReceiveStreamRequest.TxToken = &tok
	}
	// Wire the foreign transmitter's stream id onto the receiver so cascade
	// DELETE (SSF §8.1.1.5) and verify-on-establish can address the publisher
	// stream by its transmitter-side id. Without this, CascadeReceiverStreamDelete
	// silently early-outs (conf.RemoteStreamId == nil) and the suite-side pub
	// stream is never deleted — the conformance test module stays in WAITING
	// and times out. The publisher already exists by this point (created
	// in-place above, or pre-existing in cli.Data), so we know its id.
	if pubConfig == nil && streamPub != nil {
		if existingPub, errPub := cli.Data.GetStreamConfig(streamPub.Alias); errPub == nil {
			pubConfig = existingPub
		}
	}
	if pubConfig != nil && pubConfig.Id != "" {
		rid := pubConfig.Id
		regReceiveStreamRequest.RemoteStreamId = &rid
	}
	// Wire the foreign transmitter's well-known URL onto the receiver so the
	// SUT can resolve the publisher's configuration_endpoint at cascade-DELETE
	// time. resolveTransmitterConfigEndpoint falls back to FetchSSFConfiguration
	// on TxWellKnownUrl when no TxAlias-keyed Server record exists — and the
	// conformance suite stream is foreign to the SUT, so no such record exists.
	// Without this, the cascade silently no-ops and the test module stays in
	// WAITING (SSF §8.1.1.5).
	if serverPub != nil && serverPub.Host != "" {
		if wkURL, errWk := wellKnownSupport.InsertWellKnownURL(serverPub.Host, wellKnownSupport.SSFConfigurationPath); errWk == nil && wkURL != "" {
			regReceiveStreamRequest.TxWellKnownUrl = &wkURL
		}
	}
	fmt.Println("Creating polling receiver stream...")
	_, err = cli.executeCreateRequest(rcvName, *regReceiveStreamRequest, serverRcv, "Poll Receivers Connection from "+pubName, pubName)
	if err != nil {
		return errors.New(fmt.Sprintf("Error creating polling receiver stream on %s: %s", serverRcv.Alias, err.Error()))
	}
	fmt.Printf("... %s created.", rcvName)
	return nil
}

type CreatePushConnectionCmd struct {
	SourceAlias string `arg:"" help:"The alias of the publishing server."`
	DestAlias   string `arg:"" help:"The alias of receiving server or existing stream alias."`
	Mode        string `optional:"" default:"IMPORT" enum:"IMPORT,FORWARD,REPUBLISH,I,F,R" help:"What should the receiver to with received events"`
}

func (p *CreatePushConnectionCmd) Run(cli *CLI) error {
	// In this request, the PUSH Receiver is created first
	strCmdParams := cli.Create.Stream
	streamPub, serverPub := cli.Data.GetStreamAndServer(p.SourceAlias)
	streamRcv, serverRcv := cli.Data.GetStreamAndServer(p.DestAlias)
	if strCmdParams.IssJwksUrl == "" {
		// check if there is an issuer key on the publishing server.

	}
	if serverPub == nil {
		return errors.New("unable to match publication server for alias: " + p.SourceAlias)
	}
	if serverRcv == nil {
		return errors.New("unable to match destination server for destination alias: " + p.DestAlias)
	}
	if streamPub != nil {
		return errors.New(fmt.Sprintf("connecting to an existing publisher stream (%s) is not supported for PUSH connections", streamPub.Alias))
	}

	var regReceiveStreamRequest, regPublisherStreamRequest *model.StreamConfiguration

	name := generateAlias(3)
	pubName := name + "-pub"
	rcvName := name + "-rcv"
	if streamRcv != nil {
		name = streamRcv.Alias
		pubName = name + "-pub"
		rcvName = name
	} else {
		if strCmdParams.Name != "" {
			name = strCmdParams.Name
			pubName = name + "-pub"
			rcvName = name + "-rcv"
		}
	}

	if streamRcv != nil {
		// The Stream Receiver already exists

		streamConfig, err := cli.Data.GetStreamConfig(streamRcv.Alias)
		if err != nil {
			return errors.New("Unable to load existing receiver stream configuration: " + err.Error())
		}
		regPublisherStreamRequest = createRegRequestFromParams(model.DeliveryPush, p.Mode, cli, streamConfig)

		fmt.Printf("Create a PUSH publisher to work with %s with the following request:\n", streamRcv.Alias)
		jsonBytes, _ := json.MarshalIndent(regPublisherStreamRequest, "", " ")
		fmt.Println(string(jsonBytes))
		if !ConfirmProceed("") {
			return nil
		}
	} else {
		// The stream receiver must be created
		// Both a publisher and receiver must be generated
		// If issJwksUrl was omitted try to see if available on publisher
		if strCmdParams.IssJwksUrl == "" {
			// check if there is an issuer key on the publishing server.
			if strCmdParams.Iss == "" {
				return errors.New("a value for issuer 'iss' is required")
			}
			tryUrl := fmt.Sprintf("%s/jwks/%s", serverPub.Host, strCmdParams.Iss)
			jwks, err := goSet.GetJwks(tryUrl)
			if jwks != nil && err == nil {
				strCmdParams.IssJwksUrl = tryUrl
			} else {
				return errors.New("a value for 'issJwksUrl' is required")
			}
		}
		regReceiveStreamRequest = createRegRequestFromParams(model.ReceivePush, p.Mode, cli, nil)
		fmt.Printf("Creating publishing and receiver push streams on %s and %s based on the following:\n", serverPub.Alias, serverRcv.Alias)
		jsonBytes, _ := json.MarshalIndent(regPublisherStreamRequest, "", " ")
		fmt.Println(string(jsonBytes))
		if !ConfirmProceed("") {
			return nil
		}
	}

	var streamConfig *model.StreamConfiguration
	var err error
	if regReceiveStreamRequest != nil {
		// See push-connection rationale above: plumb the foreign transmitter's
		// bearer onto the receiver stream so outbound verify / status /
		// stream-management calls back to the transmitter are authenticated.
		if serverPub != nil && serverPub.ClientToken != "" {
			tok := serverPub.ClientToken
			regReceiveStreamRequest.TxToken = &tok
		}
		fmt.Println("Creating push receiver stream...")
		streamConfig, err = cli.executeCreateRequest(rcvName, *regReceiveStreamRequest, serverRcv, "Push Receiver Connection from "+pubName, pubName)
		if err != nil {
			return errors.New(fmt.Sprintf("Error creating polling publisher stream on %s: %s", serverPub.Alias, err.Error()))
		}
		fmt.Printf("... %s created.", rcvName)
		streamRcv, _ = cli.Data.GetStreamAndServer(rcvName)
	}
	if regPublisherStreamRequest == nil {
		// Now, build the receiver stream based on the new publisher stream
		regPublisherStreamRequest = createRegRequestFromParams(model.DeliveryPush, p.Mode, cli, streamConfig)
	}

	fmt.Println("Creating push publisher stream...")
	pubStreamConfig, err := cli.executeCreateRequest(pubName, *regPublisherStreamRequest, serverPub, "Push Publisher to "+rcvName, rcvName)
	if err != nil {
		return errors.New(fmt.Sprintf("Error creating push publisher stream on %s: %s", serverPub.Alias, err.Error()))
	}
	fmt.Printf("... %s created.", pubName)

	// Back-patch the SUT-side receiver stream with the publisher (transmitter)
	// stream id so the receiver's verify-on-establish and status lookups quote
	// the transmitter's stream_id, not its own local id. The POLL path does this
	// implicitly in pkg/services/stream_service.go (sets config.RemoteStreamId
	// from the txStreamResp.Id) because that path drives both registrations from
	// a single in-process service call. The PUSH path creates the receiver
	// first, then the publisher, so the receiver record is persisted before the
	// remote stream id is known. Without this PATCH the SUT-side receiver sends
	// its OWN id when calling back to the transmitter (the conformance suite),
	// which 404s every verify/status request and blocks the verification and
	// supported-events modules. Best-effort: log and continue on failure so
	// connection creation itself is not regressed.
	if pubStreamConfig != nil && streamRcv != nil && serverRcv != nil &&
		serverRcv.ServerConfiguration.ConfigurationEndpoint != "" {
		patchBody := map[string]any{
			"stream_id":        streamRcv.Id,
			"remote_stream_id": pubStreamConfig.Id,
		}
		// Iss/Aud are transmitter-asserted (SSF 1.0 §7.1.1). The publisher
		// stream we just created on the foreign transmitter carries the values
		// it will sign and audience-stamp every SET with; without back-patching
		// them onto the local receiver record, inbound SETs fail
		// audience/issuer validation in goSetPush.ParseReceivedSET. The poll
		// receiver path applies these in-process during CreateStream, so this
		// patch is the push-only equivalent.
		if pubStreamConfig.Iss != "" {
			patchBody["iss"] = pubStreamConfig.Iss
		}
		if len(pubStreamConfig.Aud) > 0 {
			patchBody["aud"] = pubStreamConfig.Aud
		}
		if patchBytes, mErr := json.Marshal(patchBody); mErr == nil {
			patchUrl := serverRcv.ServerConfiguration.ConfigurationEndpoint + "?stream_id=" + streamRcv.Id
			patchReq, pErr := http.NewRequest(http.MethodPatch, patchUrl, bytes.NewReader(patchBytes))
			if pErr == nil {
				patchReq.Header.Set("Content-Type", "application/json")
				if bearer, bErr := serverBearer(&cli.Globals, serverRcv); bErr == nil && bearer != "" {
					patchReq.Header.Set("Authorization", "Bearer "+bearer)
				}
				patchClient := getHttpClient(0)
				patchResp, doErr := patchClient.Do(patchReq)
				if doErr != nil {
					fmt.Printf("warning: failed to back-patch remote_stream_id on receiver %s: %s\n", rcvName, doErr.Error())
				} else {
					if patchResp.StatusCode != http.StatusOK && patchResp.StatusCode != http.StatusNoContent {
						respBody, _ := io.ReadAll(patchResp.Body)
						fmt.Printf("warning: back-patch of remote_stream_id on receiver %s returned %s (body: %s)\n", rcvName, patchResp.Status, string(respBody))
					} else {
						cli.Data.ResetStreamConfig(rcvName)
					}
					httpSupport.HandleRespClose(patchResp)
				}
				patchClient.CloseIdleConnections()
			} else {
				fmt.Printf("warning: failed to build back-patch request for receiver %s: %s\n", rcvName, pErr.Error())
			}
		} else {
			fmt.Printf("warning: failed to marshal back-patch body for receiver %s: %s\n", rcvName, mErr.Error())
		}
	}

	return nil
}

// registerTxAliasServer POSTs a foreign SSF transmitter registration (built by
// the #85 helper ConfigData.BuildServerRegistration) to the target receiver
// node's /server endpoint so the server-side TxAlias auto-registration path can
// later resolve the alias. The call is authenticated with the node's bearer
// credential (reg/admin scoped — the caller's responsibility). A 409 Conflict
// means the transmitter is already registered on the node and is treated as
// success (idempotent). The resolved client secret rides on the request body
// only; it is never persisted to config.json.
func (cli *CLI) registerTxAliasServer(node *SsfServer, alias, flagSecret, envVar string) error {
	reg, err := cli.Data.BuildServerRegistration(alias, flagSecret, envVar)
	if err != nil {
		return err
	}

	serverUrl, err := url.Parse(node.Host)
	if err != nil {
		return err
	}
	regUrl, err := serverUrl.Parse("/server")
	if err != nil {
		return err
	}

	bodyBytes, err := json.Marshal(reg)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, regUrl.String(), bytes.NewReader(bodyBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	bearer, err := serverBearer(&cli.Globals, node)
	if err != nil {
		return err
	}
	// Proactive fail-fast (#139): registering a foreign transmitter requires
	// admin scope. When the resolved credential decodes to a goSignals
	// ClientToken whose scopes lack admin/root, short-circuit BEFORE the network
	// call with an actionable message. If the credential cannot be classified
	// locally (opaque/IdP token), degrade gracefully and fall through.
	if known, hasAdmin := clientTokenHasAdminScope(bearer); known && !hasAdmin {
		return errTxAliasAdminRequired
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}

	client := getHttpClient(0)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer httpSupport.HandleRespClose(resp)

	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated:
		return nil
	case http.StatusConflict:
		// Transmitter already registered on this node — proceed.
		fmt.Printf("Transmitter '%s' already registered on %s (409); proceeding.\n", alias, node.Alias)
		return nil
	case http.StatusUnauthorized, http.StatusForbidden:
		// Reactive translation (#139): surface the SAME actionable admin-scope
		// guidance instead of leaking a raw status/body.
		return errTxAliasAdminRequired
	default:
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unexpected status registering tx-alias '%s' on %s: %s (body: %s)", alias, node.Alias, resp.Status, string(body))
	}
}

// errTxAliasAdminRequired is the actionable guidance returned both proactively
// (offline precheck) and reactively (401/403 translation) when a tx-alias
// registration is attempted without an admin-scoped credential (#139).
var errTxAliasAdminRequired = errors.New("registering tx-alias requires admin scope; log in with an admin session or configure an admin client token")

// clientTokenHasAdminScope decodes a bearer as a goSignals ClientToken JWT
// WITHOUT verifying its signature and reports whether the scope could be
// determined (known) and, if so, whether it grants admin (root rides free). An
// opaque or non-goSignals token returns known=false so callers degrade
// gracefully and proceed to the network.
func clientTokenHasAdminScope(bearer string) (known bool, hasAdmin bool) {
	if bearer == "" {
		return false, false
	}
	var eat authSupport.EventAuthToken
	parser := jwt.NewParser()
	if _, _, err := parser.ParseUnverified(bearer, &eat); err != nil {
		return false, false
	}
	// A goSignals ClientToken carries roles and/or a scope claim. Absent both,
	// this is an IdP/opaque token we cannot classify here.
	if len(eat.Roles) == 0 && eat.Scope == "" {
		return false, false
	}
	return true, eat.IsScopeMatch([]string{authSupport.ScopeStreamAdmin})
}

// stripTransmitterSupplied returns a copy of reg with the fields the local SUT
// MUST assign itself cleared, so the CLI never pre-populates them on the wire:
// stream_id (transmitter-assigned), events_supported / events_delivered
// (derived from the SUT's static event catalog ∩ events_requested),
// min_verification_interval and inactivity_timeout (server-side policy). The
// goSignals-to-goSignals connection flow can carry these from the local
// receive stream's cached config; valid as local state but illegal on the wire.
//
// Iss, Aud, and IssuerJWKSUrl are PRESERVED by default on both paths:
//   - Transmitter-side (Delivery.method = DeliveryPush/Poll/Sstp): the operator
//     is asserting them via --iss / --aud / --iss-jwks-url. A goSignals SUT
//     acting as transmitter MUST honor that intent (without it, the SUT falls
//     back to its default issuer alias and silently drops the operator's
//     configured audience — Test4_PollStream depends on this).
//   - Receiver-side (Delivery.method = Receive*): these describe the FOREIGN
//     transmitter the local SUT will receive from. The SUT needs Iss /
//     IssuerJWKSUrl to discover the transmitter's SSF endpoints (verification,
//     status) for stream management, and Aud as the expected audience to
//     validate against inbound SETs' aud claim (RFC 8417 §2.2).
//
// When the target server is marked StrictSsf (see SsfServer.StrictSsf), the
// transmitter-side wire body is additionally stripped of Iss/Aud/IssuerJWKSUrl
// to satisfy SSF §8.1.1.1, which forbids the receiver from supplying these
// transmitter-owned fields on a publisher-leg POST. Strict transmitters such
// as the OpenID conformance suite reject the request with HTTP 400 otherwise.
// Receiver-side bodies are never additionally stripped — they go to the local
// SUT, which owns its own SSF wire cleanup on outbound calls.
func stripTransmitterSupplied(reg model.StreamConfiguration, strict bool) model.StreamConfiguration {
	return model.StripTransmitterSupplied(reg, strict)
}

func (cli *CLI) executeCreateRequest(streamAlias string, reg model.StreamConfiguration, server *SsfServer, typeDescription string, connectAlias string) (*model.StreamConfiguration, error) {

	serverUrl, err := url.Parse(server.Host)
	if err != nil {
		return nil, err
	}

	regUrl, err := serverUrl.Parse(server.ServerConfiguration.ConfigurationEndpoint)
	if err != nil {
		return nil, err
	}

	wire := stripTransmitterSupplied(reg, server.StrictSsf)

	// Warn-and-drop: when registering against a strict server (SSF §8.1.1.1)
	// the publisher-leg POST cannot carry operator-asserted iss/aud — they are
	// transmitter-owned. If the operator passed --iss/--aud and the strip
	// actually removed them, tell them so the silent omission isn't surprising.
	if server.StrictSsf {
		var dropped []string
		if reg.Iss != "" && wire.Iss == "" {
			dropped = append(dropped, "iss")
		}
		if len(reg.Aud) > 0 && len(wire.Aud) == 0 {
			dropped = append(dropped, "aud")
		}
		if reg.IssuerJWKSUrl != "" && wire.IssuerJWKSUrl == "" {
			dropped = append(dropped, "issuerJWKSUrl")
		}
		if len(dropped) > 0 {
			fmt.Printf("Warning: server %q is marked strict-ssf; dropping transmitter-owned value(s) %s from the registration request (SSF §8.1.1.1)\n", server.Alias, strings.Join(dropped, ", "))
		}
	}

	regBytes, err := json.MarshalIndent(&wire, "", " ")
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodPost, regUrl.String(), bytes.NewReader(regBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	bearer, err := serverBearer(&cli.Globals, server)
	if err != nil {
		return nil, err
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	} else {
		fmt.Println("No server credential detected. Run 'login " + server.Alias + "' or attempt anonymous request...")
	}

	client := getHttpClient(0)
	resp, err := client.Do(req)
	defer httpSupport.HandleRespClose(resp)
	if err != nil {
		return nil, err
	}
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("unexpected status response: %s (body: %s)", resp.Status, string(body))
	}

	// Accept aud as either a single string or a string array (RFC 7519 §4.1.3
	// allows both). Foreign SSF transmitters (e.g. the OpenID conformance
	// suite) return a single string; our model is []string. Normalize before
	// unmarshal so a string aud doesn't crash the parse.
	body = normalizeJWTAud(body)

	var config model.StreamConfiguration
	err = json.Unmarshal(body, &config)
	if err != nil {
		return nil, err
	}

	if streamAlias == "" {
		streamAlias = generateAlias(3)
		for _, exists := server.Streams[streamAlias]; exists; _, exists = server.Streams[streamAlias] {
			streamAlias = generateAlias(3)
		}
	}

	var audString string
	for i, v := range config.Aud {
		if i == 0 {
			audString = v
		} else {
			audString = audString + "," + v
		}
	}
	stream := Stream{
		Alias:        streamAlias,
		Id:           config.Id,
		Description:  typeDescription,
		ConnectAlias: connectAlias,
		Iss:          config.Iss,
		Aud:          audString,
		Endpoint:     config.Delivery.GetEndpointUrl(),
		Token:        config.Delivery.GetAuthorizationHeader(),
		IssJwksUrl:   config.IssuerJWKSUrl,
	}
	server.Streams[streamAlias] = stream

	jsonBytes, _ := json.MarshalIndent(stream, "", "  ")

	cli.GetOutputWriter().WriteBytes(jsonBytes, true)

	out := fmt.Sprintf("Stream defined:\n%s", string(jsonBytes))
	fmt.Println(out)
	err = cli.Data.Save(&cli.Globals)
	if err != nil {
		return nil, err
	}

	return &config, nil
}

type CreateStreamPollCmd struct {
	Receive    CreatePollReceiverCmd   `cmd:"" help:"Create a POLLING Receiver stream"`
	Publish    CreatePollPublisherCmd  `cmd:"" help:"Create a POLLING Publisher stream"`
	Connection CreatePollConnectionCmd `cmd:"" aliases:"c" help:"Create a polling stream connection between servers"`
}

type CreateStreamPushCmd struct {
	Receive    CreatePushReceiverCmd   `cmd:"" aliases:"r" help:"Create PUSH Receiver stream"`
	Publish    CreatePushPublisherCmd  `cmd:"" aliases:"p" help:"Create PUSH Publisher stream"`
	Connection CreatePushConnectionCmd `cmd:"" aliases:"c" help:"Create a push stream connection between servers"`
}

// CreateStreamSstpCmd provisions an SSTP pair (PRD #154 Q44, slice #170) with a
// single invocation. It is issued against the <client-alias> side (the SSTP HTTP
// client, role=initiator); that node's StreamService cascades the mirrored
// bootstrap to <server-alias> via the stored Server credentials (slice #161).
//
// Two input shapes:
//   - Symmetric flags (--iss/--iss-jwks-url/--aud/--events/--mode) build a
//     symmetric SstpPairBootstrap: identical business-plane inputs both
//     directions.
//   - --bootstrap-file <file> (JSON or YAML) supplies a full SstpPairBootstrap
//     for the asymmetric / multi-hop case (per-direction Primary/Inbound). It is
//     named --bootstrap-file (not --config) because the global --config flag
//     (GOSIGNALS_HOME) already owns that name.
//
// The two shapes are mutually exclusive.
type CreateStreamSstpCmd struct {
	ClientAlias   string   `arg:"" required:"" help:"Alias of the SSTP client (initiator) server to provision the pair against."`
	ServerAlias   string   `arg:"" required:"" help:"Alias of the SSTP server (responder) peer; its stored credentials cascade the mirrored half."`
	Name          string   `optional:"" help:"An alias name for the pair to be stored locally."`
	Description   string   `optional:"" help:"Human-facing label copied onto both halves of the pair."`
	BootstrapFile string   `name:"bootstrap-file" optional:"" help:"Path to a JSON/YAML file carrying a full (asymmetric) SstpPairBootstrap. Mutually exclusive with the symmetric flags."`
	Iss           string   `optional:"" help:"Issuer value for both directions (symmetric mode)."`
	IssJwksUrl    string   `optional:"" help:"Issuer JWKS URL for both directions (symmetric mode)."`
	Aud           []string `optional:"" sep:"," help:"Audience value(s) for both directions (symmetric mode)."`
	Events        []string `optional:"" sep:"," help:"Event uris (types) requested for both directions (symmetric mode)."`
	Mode          string   `optional:"" default:"" enum:"FORWARD,PUBLISH,IMPORT," help:"Route mode for both directions (symmetric mode): FORWARD, PUBLISH, or IMPORT (default PUBLISH)."`
}

func (p *CreateStreamSstpCmd) Run(cli *CLI) error {
	flagsUsed := p.Iss != "" || p.IssJwksUrl != "" || len(p.Aud) > 0 || len(p.Events) > 0 || p.Mode != ""
	if p.BootstrapFile != "" && flagsUsed {
		return errors.New("--bootstrap-file cannot be combined with the symmetric flags (--iss/--iss-jwks-url/--aud/--events/--mode); use one input mode")
	}

	var boot model.SstpPairBootstrap
	if p.BootstrapFile != "" {
		loaded, err := loadSstpBootstrapFile(p.BootstrapFile)
		if err != nil {
			return err
		}
		boot = *loaded
	} else {
		boot = model.SstpPairBootstrap{
			Description: p.Description,
			Primary: model.SstpDirection{
				Iss:        p.Iss,
				IssJwksUrl: p.IssJwksUrl,
				Aud:        p.Aud,
				Events:     p.Events,
				Mode:       p.Mode,
			},
			Inbound: model.SstpDirection{
				Iss:        p.Iss,
				IssJwksUrl: p.IssJwksUrl,
				Aud:        p.Aud,
				Events:     p.Events,
				Mode:       p.Mode,
			},
		}
	}

	// The issuing client side plays initiator; the named server alias is the
	// peer the StreamService cascades the mirror to.
	boot.Role = model.SstpRoleInitiator
	boot.PeerServerAlias = p.ServerAlias
	if p.Description != "" {
		boot.Description = p.Description
	}

	server, err := cli.Data.GetServer(p.ClientAlias)
	if err != nil {
		return err
	}

	jsonString, _ := json.MarshalIndent(boot, "", "  ")
	fmt.Println(fmt.Sprintf("Create SSTP pair on: %s\n%s", server.ServerConfiguration.ConfigurationEndpoint, string(jsonString)))
	if !ConfirmProceed("") {
		return nil
	}

	return cli.executeCreateSstpPair(p.Name, boot, server)
}

// loadSstpBootstrapFile reads an SstpPairBootstrap from a JSON or YAML file. A
// `.yaml`/`.yml` extension selects YAML; anything else is parsed as JSON.
func loadSstpBootstrapFile(path string) (*model.SstpPairBootstrap, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("unable to read --bootstrap-file %s: %w", path, err)
	}
	var boot model.SstpPairBootstrap
	ext := strings.ToLower(filepath.Ext(path))
	if ext == ".yaml" || ext == ".yml" {
		if err = yaml.Unmarshal(data, &boot); err != nil {
			return nil, fmt.Errorf("unable to parse YAML --bootstrap-file %s: %w", path, err)
		}
	} else {
		if err = json.Unmarshal(data, &boot); err != nil {
			return nil, fmt.Errorf("unable to parse JSON --bootstrap-file %s: %w", path, err)
		}
	}
	return &boot, nil
}

// executeCreateSstpPair POSTs an SstpPairBootstrap body to the client node's
// stream-configuration endpoint, authenticated with the node's bearer, parses
// the returned StreamStateRecord, stores a local stream alias, and prints the
// PairId, both pair SIDs, and the resolved EndpointUrls.
func (cli *CLI) executeCreateSstpPair(streamAlias string, boot model.SstpPairBootstrap, server *SsfServer) error {
	serverUrl, err := url.Parse(server.Host)
	if err != nil {
		return err
	}
	regUrl, err := serverUrl.Parse(server.ServerConfiguration.ConfigurationEndpoint)
	if err != nil {
		return err
	}

	bootBytes, err := json.MarshalIndent(&boot, "", " ")
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, regUrl.String(), bytes.NewReader(bootBytes))
	if err != nil {
		return err
	}
	bearer, err := serverBearer(&cli.Globals, server)
	if err != nil {
		return err
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	} else {
		fmt.Println("No server credential detected. Run 'login " + server.Alias + "' or attempt anonymous request...")
	}

	client := getHttpClient(0)
	resp, err := client.Do(req)
	defer httpSupport.HandleRespClose(resp)
	if err != nil {
		return err
	}
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("unexpected status response: %s (body: %s)", resp.Status, string(body))
	}

	var record model.StreamStateRecord
	if err = json.Unmarshal(body, &record); err != nil {
		return err
	}

	txSid := record.PairId
	if txSid == "" {
		txSid = record.StreamConfiguration.Id
	}
	rxSid := ""
	if record.SstpInbound != nil {
		rxSid = record.SstpInbound.Id
	}
	localEndpoint := ""
	peerPairId := ""
	if record.SstpMethod != nil {
		localEndpoint = record.SstpMethod.EndpointUrl
		peerPairId = record.SstpMethod.PeerPairId
	}

	if streamAlias == "" {
		streamAlias = generateAlias(3)
		for _, exists := server.Streams[streamAlias]; exists; _, exists = server.Streams[streamAlias] {
			streamAlias = generateAlias(3)
		}
	}
	stream := Stream{
		Alias:       streamAlias,
		Id:          txSid,
		Description: "SSTP Pair",
		Iss:         record.StreamConfiguration.Iss,
		Endpoint:    localEndpoint,
		IssJwksUrl:  record.StreamConfiguration.IssuerJWKSUrl,
	}
	server.Streams[streamAlias] = stream

	fmt.Println(fmt.Sprintf("SSTP pair created:\n  PairId:       %s\n  txSid:        %s\n  rxSid:        %s\n  EndpointUrl:  %s\n  PeerPairId:   %s", record.PairId, txSid, rxSid, localEndpoint, peerPairId))

	return cli.Data.Save(&cli.Globals)
}

type CreateStreamCmd struct {
	Push       CreateStreamPushCmd `cmd:"" help:"Create a SET PUSH Stream (RFC8935)"`
	Poll       CreateStreamPollCmd `cmd:"" help:"Create a SET Polling Stream (RFC8936)"`
	Sstp       CreateStreamSstpCmd `cmd:"" help:"Create an SSTP bidirectional pair (draft-hunt-secevent-sstp)"`
	Aud        []string            `optional:"" sep:"," help:"One or more audience values separated by commas"`
	Iss        string              `optional:"" help:"The event issuer value (e.g. scim.example.com)"`
	Name       string              `optional:"" short:"n" help:"An alias name for the stream to be created"`
	IssJwksUrl string              `optional:"" help:"The issuer JwksUrl value. Used for SET Event token validation."`
	Events     []string            `optional:"" default:"*" help:"The event uris (types) requested for a stream. Use '*' to match by wildcard."`
}

// bootstrapBearer returns the bearer to present on bootstrap-capable calls
// (create key / create iat). A configured client token wins; otherwise the
// shared bootstrap secret (I2SIG_BOOTSTRAP_TOKEN) is used. Returns "" when
// neither is available, in which case the now-non-anonymous server rejects the
// request.
func bootstrapBearer(clientToken string) string {
	if clientToken != "" {
		return clientToken
	}
	return os.Getenv("I2SIG_BOOTSTRAP_TOKEN")
}

type CreateKeyCmd struct {
	Alias    string `arg:"" required:"" help:"The alias of the server to issue the key (default is selected server)"`
	IssuerId string `arg:"" required:"" help:"The issuer value associated with the key (e.g. example.com)"`
	File     string `optional:"" default:"issuer.pem" help:"Specify the file where the issued PEM is to be stored (default is issuer.pem)"`
	Force    string `optional:"" help:"Force creation of the key even if it already exists (replace or rotate)."`
}

func (c *CreateKeyCmd) Run(g *Globals) error {
	server, err := g.Data.GetServer(c.Alias)
	if err != nil {
		return err
	}
	hostUrl, err := url.Parse(server.Host)
	if err != nil {
		return err
	}
	// An SSF issuer id can be a full URL with a path component (a path-bearing
	// local issuer, ADR 0023 / GH #188). url.JoinPath would leave its slashes
	// literal (and collapse "//"), so the /key/{keyName} route would capture only
	// the first segment. Percent-encode the issuer id so the whole value rides in
	// a single path segment: the server runs with UseEncodedPath() and the
	// CreateKey handler url.QueryUnescape's it back, so QueryEscape is the
	// matching pair. A slash-free issuer id (e.g. example.com) encodes to itself.
	certUrl := *hostUrl
	certUrl.Path = "/key/" + c.IssuerId
	certUrl.RawPath = "/key/" + url.QueryEscape(c.IssuerId)
	if c.Force != "" {
		q := certUrl.Query()
		q.Set("force", c.Force)
		certUrl.RawQuery = q.Encode()
	}
	req, _ := http.NewRequest(http.MethodPost, certUrl.String(), nil)
	if bearer := bootstrapBearer(server.ClientToken); bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	} else {
		fmt.Println(fmt.Sprintf("No authorization information for %s and no I2SIG_BOOTSTRAP_TOKEN set; request will be rejected.", server.Alias))
	}
	client := getHttpClient(0)
	defer client.CloseIdleConnections()
	resp, err := client.Do(req)
	defer httpSupport.HandleRespClose(resp)
	if err != nil {
		return err
	}
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("unexpected status response: %s (body: %s)", resp.Status, string(body))
	}

	if g.Data.Pems == nil {
		g.Data.Pems = map[string][]byte{}
	}
	g.Data.Pems[c.IssuerId] = body

	outputPath := "issuer.pem"
	if c.File != "" {
		outputPath = c.File
	}

	// file, err := os.OpenFile(cli.Output, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	err = os.WriteFile(outputPath, body, 0640)
	if err != nil {
		fmt.Println(err.Error())
	}
	fmt.Println("Certificate received (PEM):\n" + string(body))
	return nil
}

type CreateIatCmd struct {
	Alias string `arg:"" help:"The alias of a server to obtain an IAT from."`
	New   bool   `default:"false" help:"When NEW is set, a new project id will be used, otherwise the IAT will be from the current project"`
}

func (g *CreateIatCmd) Run(c *CLI) error {
	server, err := c.Data.GetServer(g.Alias)
	if err != nil {
		return err
	}
	hostUrl, err := url.Parse(server.Host)
	if err != nil {
		return err
	}
	iatUrl := hostUrl.JoinPath("/iat")
	req, _ := http.NewRequest(http.MethodGet, iatUrl.String(), nil)
	// The anonymous /iat door is gone: /iat now requires a key/admin/root bearer.
	// When a client token is present and --new is not set, reuse it so the IAT is
	// associated with the current project; otherwise fall back to the bootstrap
	// secret (I2SIG_BOOTSTRAP_TOKEN), which the server resolves to key scope.
	if !g.New && server.ClientToken != "" {
		req.Header.Set("Authorization", "Bearer "+server.ClientToken)
	} else if boot := os.Getenv("I2SIG_BOOTSTRAP_TOKEN"); boot != "" {
		req.Header.Set("Authorization", "Bearer "+boot)
	}
	client := getHttpClient(0)
	defer client.CloseIdleConnections()
	resp, err := client.Do(req)
	defer httpSupport.HandleRespClose(resp)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		msg := fmt.Sprintf("Received response: %s", resp.Status)
		fmt.Println(msg)
		return errors.New(msg)
	}
	regBytes, err := io.ReadAll(resp.Body)
	var tokenResponse model.RegisterResponse
	err = json.Unmarshal(regBytes, &tokenResponse)
	if err != nil {
		return err
	}
	fmt.Printf("IAT:\n%s", tokenResponse.Token)
	c.GetOutputWriter().WriteBytes([]byte(tokenResponse.Token), true)
	return nil
}

type CreateCmd struct {
	Stream CreateStreamCmd `cmd:"" aliases:"s" help:"Create a stream on a specified server."`
	Key    CreateKeyCmd    `cmd:"" help:"Obtain an issuer key from an i2goSignals server (returns a PEM)."`
	Iat    CreateIatCmd    `cmd:"" help:"Create/obtain an initial access token (IAT) from a server which allows a stream client to register."`
	Bundle CreateBundleCmd `cmd:"" help:"Export the SPIFFE trust bundle to a file."`
}

type CreateBundleCmd struct {
	//  Output string `short:"o" help:"The file path to write the SPIFFE trust bundle (PEM format)." type:"path" required:""`
}

func (b *CreateBundleCmd) Run(cli *CLI) error {
	if !tlsSupport.SpiffeEnabled() {
		return errors.New("SPIFFE is not enabled (SPIFFE_ENDPOINT_SOCKET not set)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	var err error
	source := spiffeSource
	if source == nil {
		source, err = tlsSupport.NewX509Source(ctx)
		if err != nil {
			return fmt.Errorf("failed to create X509 source: %w", err)
		}
		defer source.Close()
	}

	err = tlsSupport.ExportTrustBundle(source, cli.Output)
	if err != nil {
		return fmt.Errorf("failed to export trust bundle: %w", err)
	}

	fmt.Printf("SPIFFE trust bundle exported to %s\n", cli.Output)
	return nil
}

type ExitCmd struct {
}

func (e *ExitCmd) Run(globals *Globals) error {
	err := globals.Data.Save(globals)
	if err != nil {
		fmt.Println(err.Error())
		if ConfirmProceed("Abort exit? Y|[n] ") {
			return nil
		}
	}
	os.Exit(-1)
	return nil
}

type HelpCmd struct {
	Command []string `arg:"" optional:"" help:"Show help on command."`
}

// Run shows help.
func (h *HelpCmd) Run(realCtx *kong.Context) error {
	ctx, err := kong.Trace(realCtx.Kong, h.Command)
	if err != nil {
		return err
	}
	if ctx.Error != nil {
		return ctx.Error
	}
	// fmt.Printf("Args:\t%v\n", ctx.Args)
	// fmt.Printf("Command:\t%s\n", ctx.Command())
	err = ctx.PrintUsage(false)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintln(realCtx.Stdout)
	return nil
}

type ShowAuthorizationCmd struct {
	Alias string `arg:"" optional:"" help:"The alias of a stream, or defaults to currently selected stream"`
}

func (s *ShowAuthorizationCmd) Run(c *CLI) error {
	out := "Stream token: \n<undefined>"

	alias := s.Alias
	if s.Alias == "" {
		alias = c.Data.Selected
	}
	stream, _ := c.Data.GetStreamAndServer(alias)
	if stream == nil {
		return errors.New("stream alias not found")
	}
	config, err := c.Data.GetStreamConfig(alias)
	if err != nil {
		return err
	}
	if config != nil {
		authorization := config.Delivery.GetAuthorizationHeader()
		c.GetOutputWriter().WriteString(authorization, true)

		out = fmt.Sprintf("Stream authorization: \n%s", authorization)
		fmt.Println(out)
	}
	return nil
}

type ShowServerCmd struct {
	Alias string `arg:"" optional:"" help:"Specify a server alias, *, or blank to show the selected server"`
}

func (s *ShowServerCmd) Run(c *CLI) error {
	if len(c.Data.Servers) == 0 {
		fmt.Println("No servers defined.")
		return nil
	}

	switch s.Alias {
	case "":
		if c.Data.Selected == "" {
			return errors.New("no currently selected server")
		}
		s.Alias = c.Data.Selected
	case "*":
		output, _ := json.MarshalIndent(c.Data.Servers, "", "  ")
		fmt.Println("Servers locally configured:")
		fmt.Println(string(output))
		c.GetOutputWriter().WriteBytes(output, true)
		return nil
	default:
	}

	server, exists := c.Data.Servers[s.Alias]
	if exists {
		output, _ := json.MarshalIndent(server, "", "  ")
		fmt.Println("ServerUrl configured:")
		fmt.Println(string(output))
		c.GetOutputWriter().WriteBytes(output, true)
		return nil
	}
	return errors.New("server " + s.Alias + " not defined")
}

type ShowStreamCmd struct {
	Alias string `arg:"" optional:"" help:"Specify a stream alias, *, or blank to show all streams for the selected server"`
	Full  bool   `help:"Set true to show the full information" default:"false"`
}

func (s *ShowStreamCmd) Run(c *CLI) error {
	if len(c.Data.Servers) == 0 {
		fmt.Println("No servers defined. Please define a server and stream.")
		return nil
	}
	selectedServerName := c.Data.Selected

	outWriter := c.GetOutputWriter()
	switch s.Alias {
	case "":
		// Print Streams for the selected server
		if selectedServerName == "" {
			return errors.New("no currently selected server")
		}
		serverConfig, err := c.Data.GetServer(selectedServerName)
		if err != nil {
			return err
		}
		PrintServerStreamsInfo(serverConfig, !s.Full, outWriter)

	case "*":
		// Print all streams

		for _, server := range c.Data.Servers {
			PrintServerStreamsInfo(&server, !s.Full, outWriter)
		}

	default:
		// Print the stream identified by s.Alias
		stream, _ := c.Data.GetStreamAndServer(s.Alias)
		if stream == nil {
			// Try looking up by server alias
			serverConfig, _ := c.Data.GetServer(s.Alias)
			if serverConfig != nil {
				PrintServerStreamsInfo(serverConfig, !s.Full, nil)
				return nil
			}
			return errors.New(s.Alias + " not found.")
		}
		PrintStreamInfo(stream, false, outWriter)
	}
	outWriter.Close()
	return nil
}

type ShowCmd struct {
	Auth   ShowAuthorizationCmd `cmd:"" help:"Retrieve/generate an event authorization header for a stream"`
	Server ShowServerCmd        `cmd:"" help:"Show information about locally defined servers"`
	Stream ShowStreamCmd        `cmd:"" help:"Show locally defined streams"`
}

type GetStreamStatusCmd struct {
	Alias string `arg:"" optional:"" help:"Specify a stream alias to retrieve status (defaults to selected stream)."`
}

func (s *GetStreamStatusCmd) Run(cli *CLI) error {

	streamAlias := s.Alias

	if s.Alias == "" {
		streamAlias = cli.Data.Selected
	}

	stream, server := cli.Data.GetStreamAndServer(streamAlias)
	if stream == nil {
		return errors.New("Could not locate locally defined stream alias: " + streamAlias)
	}

	reqUrl := fmt.Sprintf("%s?stream_id=%s", server.ServerConfiguration.StatusEndpoint, stream.Id)

	req, err := http.NewRequest(http.MethodGet, reqUrl, nil)
	if err != nil {
		return err
	}
	bearer, err := serverBearer(&cli.Globals, server)
	if err != nil {
		return err
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	client := getHttpClient(0)
	resp, err := client.Do(req)
	defer httpSupport.HandleRespClose(resp)
	if err != nil {
		return err
	}
	bodyBytes, _ := io.ReadAll(resp.Body)
	var status model.StreamStatus
	_ = json.Unmarshal(bodyBytes, &status)

	cli.GetOutputWriter().WriteBytes(bodyBytes, true)

	fmt.Println("Status for " + streamAlias)
	fmt.Println(fmt.Sprintf("%s", bodyBytes))
	return nil
}

type GetStreamConfigCmd struct {
	Alias string `arg:"" optional:"" help:"Specify a stream alias, *, or blank to show all streams for the selected server"`
}

func (s *GetStreamConfigCmd) Run(cli *CLI) error {
	streamAlias := s.Alias
	if streamAlias == "" {
		return errors.New("please provide the alias of a stream to get configuration")
	}
	streamConfig, server := cli.Data.GetStreamAndServer(streamAlias)
	if streamConfig == nil {
		return errors.New("Could not locate locally defined stream alias: " + streamAlias)
	}

	client := getHttpClient(0)
	defer client.CloseIdleConnections()
	config, err := getStreamConfig(client, server, streamConfig)
	if err != nil {
		return err
	}
	fmt.Println("Stream configuration for: " + streamAlias)

	output, _ := json.MarshalIndent(config, "", "  ")
	cli.GetOutputWriter().WriteBytes(output, true)
	fmt.Println(fmt.Sprintf("%s", output))
	return nil
}

type GetStreamCmd struct {
	Config GetStreamConfigCmd `cmd:"" aliases:"c" help:"Retrieve live configuration for the identified stream"`
	Status GetStreamStatusCmd `cmd:"" aliases:"s" help:"Retrieve current status of the identified stream"`
}

func PrintServerStreamsInfo(server *SsfServer, brief bool, outWriter *OutputWriter) {
	if len(server.Streams) == 0 {
		fmt.Println("ServerUrl: " + server.Alias + "\nHas no streams defined.")
		return
	}
	for _, v := range server.Streams {
		PrintStreamInfo(&v, brief, outWriter)
	}
	if outWriter != nil {
		outWriter.Close()
	}
}

func PrintStreamInfo(config *Stream, brief bool, outWriter *OutputWriter) {
	configString, _ := json.MarshalIndent(config, "", " ")
	if brief {
		msg := fmt.Sprintf("Stream [%s]", config.Alias)
		fmt.Println(msg)
		if outWriter != nil {
			outWriter.WriteString(msg, false)
		}
		return
	}
	if outWriter != nil {
		outWriter.WriteBytes(configString, false)
	}
	fmt.Println(fmt.Sprintf("Stream [%s]:\n%s", config.Alias, configString))
}

type GetKeyCmd struct {
	Alias string `arg:"" help:"The alias of a stream or server, or URL to obtain the public key from"`
	Iss   string `optional:"" help:"The issuer to look for (e.g. iss.example.com"`
}

func (g *GetKeyCmd) Run(c *CLI) error {
	jwksUrl := g.Alias
	if !strings.Contains(g.Alias, "/") {
		// stream, server := c.Data.GetStreamAndServer(g.Alias)
		stream, _ := c.Data.GetStreamConfig(g.Alias)
		if stream != nil {
			jwksUrl = stream.IssuerJWKSUrl
		} else {
			if g.Iss == "" {
				return errors.New("invalid server alias and/or missing iss value")
			}
			server, err := c.Data.GetServer(g.Alias)
			if err != nil {
				return err
			}
			if server == nil {
				return errors.New(fmt.Sprintf("unable to locate server %s", g.Alias))
			}
			serverUrl, _ := url.Parse(server.Host)
			if g.Iss == "" {
				jwksLoc, _ := serverUrl.Parse("/jwks.json")
				jwksUrl = jwksLoc.String()
			} else {
				jwksLoc, _ := serverUrl.Parse(fmt.Sprintf("/jwks/%s", g.Iss))
				jwksUrl = jwksLoc.String()
			}
		}
	}

	jwks, err := goSet.GetJwks(jwksUrl)

	if err != nil {
		return err
	}
	rawKey := jwks.RawJWKS()
	fmt.Printf("Key returned:\n%s", rawKey)
	c.GetOutputWriter().WriteBytes(rawKey, true)
	return nil
}

type GetCmd struct {
	Stream        GetStreamCmd        `cmd:"" aliases:"s" help:"Get stream configurations or stream status"`
	Key           GetKeyCmd           `cmd:"" help:"Retrieves the issuer public key"`
	SubjectFilter GetSubjectFilterCmd `cmd:"" aliases:"sf" help:"Get a stream's subject-filter config (operator-tunable knobs)."`
}

type DeleteServerCmd struct {
	Alias string `arg:"" help:"The alias of a server to delete"`
}

func (d *DeleteServerCmd) Run(cli *CLI) error {
	if err := cli.Data.DeleteServer(d.Alias, &cli.Globals); err != nil {
		return err
	}
	fmt.Println(d.Alias + " deleted.")
	return nil
}

type DeleteStreamCmd struct {
	Alias string `arg:"" help:"The alias of a stream to delete"`
}

func (d *DeleteStreamCmd) Run(cli *CLI) error {
	client := getHttpClient(0)
	defer client.CloseIdleConnections()

	stream, server := cli.Data.GetStreamAndServer(d.Alias)
	if stream == nil {
		return errors.New(fmt.Sprintf("Stream %s not found, delete cancelled.", d.Alias))
	}

	reqUrl := fmt.Sprintf("%s?stream_id=%s", server.ServerConfiguration.ConfigurationEndpoint, stream.Id)
	req, err := http.NewRequest(http.MethodDelete, reqUrl, nil)
	if err != nil {
		return err
	}
	bearer, err := serverBearer(&cli.Globals, server)
	if err != nil {
		return err
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := client.Do(req)
	defer httpSupport.HandleRespClose(resp)
	if err != nil {
		return err
	}
	// SSF 1.0 §8.1.5 Stream Configuration Delete answers 204 No Content on
	// success; tolerate a 200 OK as well for transmitters that still return it.
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return errors.New(fmt.Sprintf("Error completing delete request: %s", resp.Status))
	}
	if _, ok := cli.Data.streamConfigs[stream.Alias]; ok {
		delete(cli.Data.streamConfigs, stream.Alias)
	}
	if _, ok := server.Streams[stream.Alias]; ok {
		delete(server.Streams, stream.Alias)
	}

	fmt.Println(d.Alias + " deleted.")
	return nil
}

type DeleteCmd struct {
	Stream DeleteStreamCmd `cmd:"" aliases:"s" help:"Delete a stream"`
	Server DeleteServerCmd `cmd:"" aliases:"r" help:"Delete local server definition"`
}

type SetStreamConfigCmd struct {
	Alias     string     `arg:"" optional:"" help:"Alias of stream to be modified"`
	Events    []string   `optional:"" short:"e" help:"Comma separated list of events to request. Or use +/- for delta to add or remove events" sep:"," `
	RJwksUrl  string     `optional:"" short:"r" help:"Set the receiver JWKS url"`
	IJwksUrl  string     `optional:"" short:"i" help:"Set the issuer JWKS url"`
	ResetJti  string     `optional:"" short:"j" xor:"reset" help:"Reset the stream to a particular JTI (and include all following events)"`
	ResetDate *time.Time `short:"d" xor:"reset" optional:"" type:"time.Time" help:"Reset stream to a specific date in RFC3339 format (e.g. 1985-04-12T23:20:50.52Z)"`
	Format    string     `optional:"" short:"f" help:"The sub_id type supported in the form of <format>:[<attr1>,<attr2>] - NOT CURRENTLY IMPLEMENTED"`
}

func (s *SetStreamConfigCmd) Run(cli *CLI) error {
	client := getHttpClient(0)
	defer client.CloseIdleConnections()

	streamAlias := s.Alias
	if streamAlias == "" {
		return errors.New("please provide the alias of a stream to get configuration")
	}
	streamConfig, server := cli.Data.GetStreamAndServer(streamAlias)
	if streamConfig == nil {
		return errors.New("Could not locate locally defined stream alias: " + streamAlias)
	}

	config, err := getStreamConfig(client, server, streamConfig)
	if err != nil {
		return err
	}
	/*
		fmt.Println("Stream configuration for " + streamAlias)
		jsonBytes, _ := json.MarshalIndent(config, "", "  ")
		fmt.Println(string(jsonBytes))
	*/

	// Update the configuration...
	if s.RJwksUrl != "" {
		if !strings.EqualFold(s.RJwksUrl, config.ReceiverJWKSUrl) {
			fmt.Println("Setting ReceiverJWKSUrl to " + s.RJwksUrl)
			config.ReceiverJWKSUrl = s.RJwksUrl
		}
	}
	if s.IJwksUrl != "" {
		if !strings.EqualFold(s.IJwksUrl, config.IssuerJWKSUrl) {
			fmt.Println("Setting IssuerJWKSUrl to " + s.IJwksUrl)
			config.IssuerJWKSUrl = s.IJwksUrl
		}
	}

	if s.ResetJti != "" {
		fmt.Println("Resetting stream to JTI: " + s.ResetJti)
		config.ResetJti = s.ResetJti
	}
	if s.ResetDate != nil {
		fmt.Println("Resetting stream to date: " + s.ResetDate.String())
		config.ResetDate = s.ResetDate
	}

	if len(s.Events) > 0 {
		config.EventsRequested = s.Events
		fmt.Println(fmt.Sprintf("Requesting events:\n%+q", config.EventsRequested))
	}
	if ConfirmProceed("Update stream configuration Y|[n]?") {

		reqBytes, err := json.MarshalIndent(config, "", " ")
		req, err := http.NewRequest(http.MethodPut, server.ServerConfiguration.ConfigurationEndpoint+"?stream_id="+config.Id, bytes.NewReader(reqBytes))
		if err != nil {
			return err
		}
		bearer, err := serverBearer(&cli.Globals, server)
		if err != nil {
			return err
		}
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		client := http.Client{}
		resp, err := client.Do(req)
		defer httpSupport.HandleRespClose(resp)
		if err != nil {
			return err
		}
		bodyBytes, _ := io.ReadAll(resp.Body)
		var configFinal model.StreamConfiguration
		err = json.Unmarshal(bodyBytes, &configFinal)
		if err != nil {
			return err
		}
		outBytes, _ := json.MarshalIndent(configFinal, "", " ")
		cli.Data.ResetStreamConfig(streamAlias) // This makes sure the next Config Get will not be cached
		cli.GetOutputWriter().WriteBytes(outBytes, true)
		fmt.Printf("Final configuration:\n%s", outBytes)
		return nil
	}

	fmt.Println("Request cancelled.")
	return nil
}

type SetStreamStatusCmd struct {
	Alias  string `arg:"" optional:"" help:"Specify a stream alias, *, or blank to show all streams for the selected server"`
	State  string `required:"" short:"m" enum:"active,pause,disabled,a,p,d" help:"Enter a valid new state (active,pause,inactive)"`
	Reason string `optional:"" short:"r" help:"Enter the reason for the state change request in quotes"`
}

func (s *SetStreamStatusCmd) Run(cli *CLI) error {
	setStatus := "A"
	switch s.State {
	case "a", "active":
		setStatus = model.StreamStateEnabled
	case "p", "pause":
		setStatus = model.StreamStatePause
	case "d", "disabled":
		setStatus = model.StreamStateDisable
	}

	var server *SsfServer
	var stream *Stream

	if s.Alias != "" {
		stream, server = cli.Data.GetStreamAndServer(s.Alias)
		// token = stream.Auth
	} else {
		server, _ = cli.Data.GetServer(cli.Data.Selected)
		// token = cli.StreamToken
	}

	if server == nil {
		return errors.New("please select or provide a valid stream")
	}

	updateStatus := model.UpdateStreamStatus{
		StreamId: stream.Id,
		Status:   setStatus,
		Subject:  nil,
		Reason:   cleanQuotes(s.Reason),
	}

	bodyBytes, err := json.MarshalIndent(updateStatus, "", " ")
	req, err := http.NewRequest(http.MethodPost, server.ServerConfiguration.StatusEndpoint+"?stream_id="+stream.Id, bytes.NewReader(bodyBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	bearer, err := serverBearer(&cli.Globals, server)
	if err != nil {
		return err
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	} else {
		fmt.Println(fmt.Sprintf("No client admin token for %s, attempting anonymous request.", server.Alias))
	}

	client := getHttpClient(0)
	resp, err := client.Do(req)
	defer httpSupport.HandleRespClose(resp)
	if err != nil {
		return err
	}
	bodyBytes, _ = io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status response: %s (body: %s)", resp.Status, string(bodyBytes))
	}
	var status model.StreamStatus
	_ = json.Unmarshal(bodyBytes, &status)

	fmt.Println("Returned status:")
	fmt.Println(string(bodyBytes))

	return nil
}

type SetStreamCmd struct {
	Status SetStreamStatusCmd `cmd:"" aliases:"s" help:"Set a new state for a steam"`
	Config SetStreamConfigCmd `cmd:"" aliases:"configuration,c" help:"Modify stream configuration"`
}

// SetKeyStatusCmd is a thin wrapper over POST /key/{keyName}/status: it sets the
// lifecycle status (active|suspended|revoked) of an issuer key. Unlike a delete,
// the key material and audit trail are retained (community ADR 0028). Omitting
// --kid applies the transition to every record under the keyName.
type SetKeyStatusCmd struct {
	Alias   string `arg:"" required:"" help:"The alias of the server holding the key."`
	KeyName string `arg:"" required:"" help:"The keyName / issuer whose key status is being changed."`
	Status  string `required:"" short:"m" enum:"active,suspended,revoked,a,s,r" help:"New status: active, suspended, or revoked."`
	Kid     string `optional:"" help:"Restrict the change to a single kid; omit to affect all records under the keyName."`
}

func (c *SetKeyStatusCmd) Run(cli *CLI) error {
	status := c.Status
	switch c.Status {
	case "a", "active":
		status = "active"
	case "s", "suspended":
		status = "suspended"
	case "r", "revoked":
		status = "revoked"
	}

	server, err := cli.Data.GetServer(c.Alias)
	if err != nil {
		return err
	}
	hostUrl, err := url.Parse(server.Host)
	if err != nil {
		return err
	}
	// Percent-encode the keyName into a single path segment (matches the
	// CreateKey addressing convention, ADR 0023): the server runs with
	// UseEncodedPath() and url.QueryUnescape's it back.
	statusUrl := *hostUrl
	statusUrl.Path = "/key/" + c.KeyName + "/status"
	statusUrl.RawPath = "/key/" + url.QueryEscape(c.KeyName) + "/status"

	reqBody := model.SetKeyStatusRequest{Status: status, Kid: c.Kid}
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, statusUrl.String(), bytes.NewReader(bodyBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	bearer, err := serverBearer(&cli.Globals, server)
	if err != nil {
		return err
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	} else {
		fmt.Println(fmt.Sprintf("No admin token for %s; request will likely be rejected.", server.Alias))
	}

	client := getHttpClient(0)
	resp, err := client.Do(req)
	defer httpSupport.HandleRespClose(resp)
	if err != nil {
		return err
	}
	respBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status response: %s (body: %s)", resp.Status, string(respBytes))
	}

	fmt.Println("Updated key status:")
	fmt.Println(string(respBytes))

	var parsed struct {
		Warning string `json:"warning"`
	}
	if err := json.Unmarshal(respBytes, &parsed); err == nil && parsed.Warning != "" {
		fmt.Println("WARNING: " + parsed.Warning)
	}
	return nil
}

type SetKeyCmd struct {
	Status SetKeyStatusCmd `cmd:"" help:"Set the lifecycle status (active|suspended|revoked) of an issuer key."`
}

type SetCmd struct {
	Stream        SetStreamCmd        `cmd:"" help:"Change settings on a stream"`
	Key           SetKeyCmd           `cmd:"" help:"Change the lifecycle status of an issuer key (revoke/suspend/reactivate)."`
	SubjectFilter SetSubjectFilterCmd `cmd:"" aliases:"sf" help:"Change a stream's subject-filter configuration."`
}

// PatchStreamConfigCmd issues a non-interactive PATCH against the transmitter's
// stream-configuration endpoint (SSF §8.1.1.3). It carries only the
// Receiver-Supplied fields the caller explicitly set; all other fields are
// omitted so the transmitter applies a true partial update. Transmitter-
// Supplied fields are stripped (see stripTransmitterSupplied).
type PatchStreamConfigCmd struct {
	Alias       string   `arg:"" help:"Alias of stream to be patched"`
	Description string   `optional:"" help:"Set the description"`
	Events      []string `optional:"" short:"e" sep:"," help:"Replace events_requested with this list"`
	RJwksUrl    string   `optional:"" short:"r" help:"Set the receiverJWKSUrl"`
	Format      string   `optional:"" short:"f" help:"Set the subject format"`
}

func (p *PatchStreamConfigCmd) Run(cli *CLI) error {
	return sendStreamMutation(cli, http.MethodPatch, p.Alias, p.Description, p.Events, p.RJwksUrl, p.Format, false)
}

type PatchStreamCmd struct {
	Config PatchStreamConfigCmd `cmd:"" aliases:"configuration,c" help:"PATCH a partial Receiver-Supplied stream config"`
}

type PatchCmd struct {
	Stream PatchStreamCmd `cmd:"" help:"Send a partial-update (PATCH) request to a transmitter"`
}

// ReplaceStreamConfigCmd issues a non-interactive PUT against the transmitter's
// stream-configuration endpoint (SSF §8.1.1.4). It sends the full
// Receiver-Supplied set: any fields not provided on the command line fall back
// to the locally-cached stream config so the replace is well-formed. Used by
// the conformance receiver-plan driver to exercise the replace path.
type ReplaceStreamConfigCmd struct {
	Alias       string   `arg:"" help:"Alias of stream to be replaced"`
	Description string   `optional:"" help:"Set the description (defaults to existing)"`
	Events      []string `optional:"" short:"e" sep:"," help:"Set events_requested (defaults to existing)"`
	RJwksUrl    string   `optional:"" short:"r" help:"Set the receiverJWKSUrl"`
	Format      string   `optional:"" short:"f" help:"Set the subject format"`
}

func (rp *ReplaceStreamConfigCmd) Run(cli *CLI) error {
	return sendStreamMutation(cli, http.MethodPut, rp.Alias, rp.Description, rp.Events, rp.RJwksUrl, rp.Format, true)
}

type ReplaceStreamCmd struct {
	Config ReplaceStreamConfigCmd `cmd:"" aliases:"configuration,c" help:"PUT a full Receiver-Supplied stream config"`
}

type ReplaceCmd struct {
	Stream ReplaceStreamCmd `cmd:"" help:"Send a full-replace (PUT) request to a transmitter"`
}

// sendStreamMutation builds and sends a PATCH or PUT against
// server.ConfigurationEndpoint?stream_id=<id> for the local alias's remote
// stream. The body is a map[string]any populated ONLY with fields the caller
// explicitly provided plus the required stream_id; this avoids serializing
// zero-valued struct fields (notably events_requested: null, which strict
// transmitters reject — the OpenID conformance suite's gson maps null into
// JsonNull and a JsonArray cast then throws ClassCastException). For PUT
// (full-replace) callers SHOULD pass every field they want set; missing
// fields will not be sent on the wire. No interactive prompt: this is meant
// to be driven from scripts.
func sendStreamMutation(cli *CLI, method, alias, description string, events []string, rJwks, format string, inheritFromCache bool) error {
	streamConfig, server := cli.Data.GetStreamAndServer(alias)
	if streamConfig == nil {
		return fmt.Errorf("stream alias %q not found", alias)
	}
	if server == nil || server.ServerConfiguration.ConfigurationEndpoint == "" {
		return fmt.Errorf("no configuration_endpoint known for server hosting stream %q", alias)
	}

	body := map[string]any{"stream_id": streamConfig.Id}
	// PUT (replace) seeds Receiver-Supplied fields from the cached config so
	// unset flags carry through, matching SSF §8.1.1.4 full-replace semantics.
	// PATCH (inheritFromCache=false) sends only explicitly-set fields.
	if inheritFromCache {
		cached, err := cli.Data.GetStreamConfig(alias)
		if err != nil {
			return fmt.Errorf("could not load cached stream config for %q: %w", alias, err)
		}
		if cached.Description != "" {
			body["description"] = cached.Description
		}
		if len(cached.EventsRequested) > 0 {
			body["events_requested"] = cached.EventsRequested
		}
		if cached.ReceiverJWKSUrl != "" {
			body["receiverJWKSUrl"] = cached.ReceiverJWKSUrl
		}
		if cached.Format != "" {
			body["format"] = cached.Format
		}
		if cached.Delivery != nil {
			body["delivery"] = cached.Delivery
		}
	}
	if description != "" {
		body["description"] = description
	}
	if len(events) > 0 {
		body["events_requested"] = events
	}
	if rJwks != "" {
		body["receiverJWKSUrl"] = rJwks
	}
	if format != "" {
		body["format"] = format
	}

	bodyBytes, err := json.MarshalIndent(body, "", " ")
	if err != nil {
		return err
	}

	reqUrl := server.ServerConfiguration.ConfigurationEndpoint + "?stream_id=" + streamConfig.Id
	req, err := http.NewRequest(method, reqUrl, bytes.NewReader(bodyBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	bearer, err := serverBearer(&cli.Globals, server)
	if err != nil {
		return err
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}

	client := getHttpClient(0)
	defer client.CloseIdleConnections()
	resp, err := client.Do(req)
	defer httpSupport.HandleRespClose(resp)
	if err != nil {
		return err
	}
	respBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("unexpected status response: %s (body: %s)", resp.Status, string(respBytes))
	}
	cli.Data.ResetStreamConfig(alias)
	fmt.Printf("%s %s ok (%s)\n", method, alias, resp.Status)
	if len(respBytes) > 0 {
		fmt.Println(string(respBytes))
	}
	return nil
}

func ConfirmProceed(msg string) bool {
	if msg != "" {
		fmt.Print(msg)
	} else {
		fmt.Print("Proceed Y|[n]? ")
	}

	reader := bufio.NewReader(os.Stdin)
	line, _ := reader.ReadString('\n')
	if line[0:1] == "Y" {
		return true
	}
	return false
}

type SelectCmd struct {
	Alias string `arg:"" help:"Specify the alias of the server or stream to work with"`
}

func (s *SelectCmd) Run(g *Globals) error {
	_, server := g.Data.GetStreamAndServer(s.Alias)
	if server != nil {
		g.Data.Selected = s.Alias
		return nil
	}
	return errors.New("server not found")
}

type PollCmd struct {
	Alias string `arg:"" help:"Specify the alias of a polling stream to receive events"`
	// Output            string   `short:"o" type:"path" help:"File to append results to (or new file name)"`
	AutoAck           bool     `default:"true" help:"Set to false to download current events without acknowledging events received"`
	MaxEvents         int32    `default:"100" short:"m" help:"Maximum events to retrieve per polling cycle"`
	TimeoutSecs       int      `default:"3600" short:"t" help:"Number of seconds to wait for results"`
	ReturnImmediately bool     `short:"i" default:"false" help:"If set true, returns immediately if no events"`
	Acks              []string `sep:"," help:"Comma separated list of JTIs to acknowledge'"`
	Loop              bool     `default:"true" short:"l" help:"By default, poll will keep looping unless set to false."`
}

func (p *PollCmd) Run(cli *CLI) error {
	stream, server := cli.Data.GetStreamAndServer(p.Alias)
	if server == nil || stream == nil {
		return errors.New("enter the Alias name for a stream defined locally. See Show Stream *")
	}

	pollParams := model.PollParameters{
		MaxEvents:         p.MaxEvents,
		ReturnImmediately: p.ReturnImmediately,
		Acks:              p.Acks,
		TimeoutSecs:       p.TimeoutSecs,
	}
	fmt.Println("Starting polling session. Use CTRL/C to stop...")
	outWriter := cli.GetOutputWriter()
	ctx := context.WithValue(context.Background(), "output", outWriter)
	c1, cancel := context.WithCancel(ctx)

	exitCh := make(chan struct{})
	go p.DoPolling(c1, server, stream, pollParams, exitCh)

	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, os.Interrupt)
	go func() {
		select {
		case <-signalCh:
			cancel()
			return
		}
	}()
	<-exitCh

	outWriter.Close()

	// fmt.Println("done.")
	return nil
}

func (p *PollCmd) DoPolling(ctx context.Context, server *SsfServer, stream *Stream, params model.PollParameters, exitCh chan struct{}) {
	var setErrs map[string]model.SetErrorType
	client := getHttpClient(0)
	defer client.CloseIdleConnections()

	var err error
	var outWriter *OutputWriter = nil
	outVal := ctx.Value("output")
	if outVal != nil {
		outWriter = outVal.(*OutputWriter)
	}

	// Get the stream configuration to get the issuer JWKS URL
	config, err := getStreamConfig(client, server, stream)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	if config.Delivery.GetMethod() != model.DeliveryPoll {
		fmt.Println("Selected stream is not a polling publisher")
		return
	}
	delivery := config.Delivery.PollTransmitMethod

	// Get the issuer public key
	jwks, err := goSet.GetJwks(config.IssuerJWKSUrl)
	if err != nil {
		fmt.Println("Error retrieving the issuer public key: " + err.Error())
		return
	}

	for {
		fmt.Println(fmt.Sprintf("Initiating polling to %s, stream %s...", server.Alias, stream.Alias))
		params.Acks = p.Acks

		pollResponse, err := p.DoPollRequest(ctx, client, params, delivery.EndpointUrl, stream.Token, exitCh)
		if err != nil {
			if strings.Contains(err.Error(), "context canceled") {
				exitCh <- struct{}{}
				return
			}
			fmt.Println("Polling error: " + err.Error())
			exitCh <- struct{}{}
			return
		}
		setCnt := len(pollResponse.Sets)
		fmt.Println(fmt.Sprintf("Received %d events for stream %s", setCnt, stream.Alias))

		p.Acks = []string{} // reset acks

		if setCnt > 0 {
			for jti, setString := range pollResponse.Sets {
				token, err := goSet.Parse(setString, jwks)

				if err != nil {
					if setErrs == nil {
						setErrs = map[string]model.SetErrorType{}
					}
					fmt.Println(fmt.Sprintf("Error parsing/validating token [%s]: %s", jti, err.Error()))
					setErrs[jti] = model.SetErrorType{
						Error:       "invalid_request",
						Description: "The SET could not be parsed: " + err.Error(),
					}
					continue
				}
				tokenBytes, _ := json.MarshalIndent(token, "", "  ")
				fmt.Println(fmt.Sprintf("Security Event: [%s]", jti))
				fmt.Println(string(tokenBytes))
				if outWriter != nil {
					outWriter.WriteBytes(tokenBytes, false)
				}
				if p.AutoAck {
					p.Acks = append(p.Acks, jti)
				}
			}
		}
		if !p.Loop {
			// Do one pass, but we may still need to ack
			p.DoAckOnly(ctx, client, delivery.EndpointUrl, stream.Token, exitCh)
			exitCh <- struct{}{}
			return
		}
		select {
		case <-ctx.Done():
			fmt.Println("Received cancel!")
			p.DoAckOnly(ctx, client, delivery.EndpointUrl, stream.Token, exitCh)
			exitCh <- struct{}{}
			return
		default:
		}
	}
}

func (p *PollCmd) DoPollRequest(ctx context.Context, client *http.Client, params model.PollParameters, endpoint string, token string, exitCh chan struct{}) (*model.PollResponse, error) {
	bodyBytes, err := json.MarshalIndent(params, "", " ")
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", token)

	resp, err := client.Do(req)
	select {
	case <-exitCh:
		fmt.Println("Exiting poll request.")
		return nil, nil
	default:

	}
	if err != nil || resp.StatusCode >= 400 {
		if err == nil {
			return nil, errors.New("Received http error: " + resp.Status)
		}
		return nil, err
	}
	var pollResponse model.PollResponse
	bodyBytes, err = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(bodyBytes, &pollResponse)
	if err != nil {
		return nil, err
	}

	return &pollResponse, nil
}

func (p *PollCmd) DoAckOnly(ctx context.Context, client *http.Client, endpoint string, token string, exitCh chan struct{}) {
	if p.AutoAck && len(p.Acks) > 0 {
		pollRequest := model.PollParameters{
			MaxEvents:         0,
			ReturnImmediately: true,
			Acks:              p.Acks,
		}
		pollResponse, err := p.DoPollRequest(ctx, client, pollRequest, endpoint, token, exitCh)
		if err != nil {
			fmt.Println("Error occurred performing polling acknowledgement: " + err.Error())
			return
		}
		if len(pollResponse.Sets) > 0 {
			fmt.Println(fmt.Sprintf("Warning, %d SETs were returned from a maxevents=0 request (ack only) to %s", len(pollResponse.Sets), endpoint))
		}
	}
	return

}

type GenerateCmd struct {
	Alias string `arg:"" optional:"" help:"The stream alias of a Push Receiver Stream to submit the event to, otherwise event is displayed to console"`
	Event string `help:"An event type URI (or the last portion of it) of the event to create"`
}

func (gen *GenerateCmd) Run(c *CLI) error {

	issuer := "gen.scim.example.com"
	audience := []string{"receiver.example.com"}
	var stream *Stream
	var server *SsfServer
	var config *model.StreamConfiguration
	var key *rsa.PrivateKey
	var err error
	var endpoint string
	var token string

	if gen.Alias != "" {
		stream, server = c.Data.GetStreamAndServer(gen.Alias)
		if server == nil || stream == nil {
			return errors.New("enter the Alias name for a push receiver stream")
		}
		config, err = c.Data.GetStreamConfig(gen.Alias)
		issuer = config.Iss
		if err != nil {
			return err
		}
		audience = config.Aud

		if config.Delivery.GetMethod() != model.ReceivePush {
			return errors.New("generate event currently requires a push event receiver stream to submit")
		}
		key, err = c.Data.GetKey(config.Iss)
		if err != nil {
			return err
		}
		endpoint = config.Delivery.GetEndpointUrl()
		token = stream.Token
	}

	genResource := resource.GenerateFakeUser(issuer)
	subjectIdentifier := goSet.NewScimSubjectIdentifier(genResource.Meta.Location)

	event := goSet.CreateSet(&goSet.EventSubject{
		SubjectIdentifier: *subjectIdentifier,
	}, issuer, audience)

	event.TransactionId = bson.NewObjectID().Hex()
	switch gen.Event {
	case "create:full":
		payload := resource.CreateFullEventPayload(genResource)
		event.AddEventPayload("urn:ietf:params:SCIM:event:prov:create:full", payload)
	case "create:notice":
		payload := resource.CreateNoticeEventPaylaod(genResource)
		event.AddEventPayload("urn:ietf:params:SCIM:event:prov:create:notice", payload)
	}
	if gen.Alias == "" {
		fmt.Println("Generated Event:")
		output := event.String()
		fmt.Println(output)
		c.GetOutputWriter().WriteString(output, true)
		return nil
	}

	client := getHttpClient(0)
	defer client.CloseIdleConnections()

	event.IssuedAt = jwt.NewNumericDate(time.Now())

	// Now we sign and deliver the event
	signString, err := event.JWS(jwt.SigningMethodRS256, key)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(signString))
	if token != "" && req != nil && stream != nil {
		req.Header.Set("Authorization", stream.Token)
	}

	req.Header.Set("Content-Type", "application/secevent+jwt")
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	defer httpSupport.HandleRespClose(resp)
	if err != nil {
		return err
	}

	if resp.StatusCode == http.StatusAccepted || resp.StatusCode == http.StatusOK {
		fmt.Println("Submitted.")
	}
	if resp.StatusCode == http.StatusBadRequest {
		var errorMsg model.SetDeliveryErr
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return errors.New("Error reading stream endpoint response: " + err.Error())
		}
		err = json.Unmarshal(body, &errorMsg)
		if err != nil {
			return errors.New("Error parsing stream push response: " + err.Error())
		}
		return errors.New(fmt.Sprintf("Error:\n\tDescription:\t%s\n\tError:\t%s", errorMsg.Description, errorMsg.ErrCode))
	}
	if resp.StatusCode > 400 {
		errMsg := fmt.Sprintf("HTTP Error: %s, POSTING to %s", resp.Status, endpoint)
		return errors.New(errMsg)
	}
	c.GetOutputWriter().WriteString(event.String(), true)
	return nil
}

func cleanQuotes(quoted string) string {
	if len(quoted) > 0 && quoted[0] == '"' {
		return quoted[1 : len(quoted)-1]
	}
	return quoted
}

func parseMode(param string) string {
	if param == "" {
		return ""
	}
	var mode string
	switch param {
	case "IMPORT", "I":
		mode = model.RouteModeImport
	case "FORWARD", "F":
		mode = model.RouteModeForward
	case "PUBLISH", "P":
		mode = model.RouteModePublish
	}
	return mode
}

// applyServerBearer resolves the active-session bearer for server (with silent
// refresh / fallback to a configured client token) and sets it on req. This is
// the standard CLI auth path used by every management call.
func applyServerBearer(cli *CLI, server *SsfServer, req *http.Request) error {
	bearer, err := serverBearer(&cli.Globals, server)
	if err != nil {
		return err
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	return nil
}

// tokenListEntry decodes the management /token list response. It embeds the
// server's TokenRecord (which carries last_redemption_ip for IATs) and decodes
// the live last_seen_ip the server joins onto STREAM-typed rows. These are the
// field names the server's TokenListEntry actually emits.
type tokenListEntry struct {
	model.TokenRecord
	LastSeenIP string `json:"last_seen_ip,omitempty"`
}

// usageIP answers "where is this token being used?" (ADR 0007): a STREAM
// token's live last-seen IP, or an IAT's last-redemption IP. Empty when the
// token has never been redeemed/connected.
func (e tokenListEntry) usageIP() string {
	if e.LastSeenIP != "" {
		return e.LastSeenIP
	}
	return e.LastRedemptionIP
}

// renderTokenTable formats token records as a tab-aligned table an operator can
// read. Columns: JTI, client, subject, type, scopes, issued, expires, state,
// usage IP. The usage-IP column is rendered blank until the server populates it
// (a later slice); the column always exists so scripts and humans see a stable
// shape.
func renderTokenTable(records []tokenListEntry) string {
	var buf bytes.Buffer
	w := tabwriter.NewWriter(&buf, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "JTI\tCLIENT\tSUBJECT\tTYPE\tSCOPES\tISSUED\tEXPIRES\tSTATE\tUSAGE IP")
	for _, rec := range records {
		issued := ""
		if !rec.IssuedAt.IsZero() {
			issued = rec.IssuedAt.UTC().Format(time.RFC3339)
		}
		expires := ""
		if !rec.ExpiresAt.IsZero() {
			expires = rec.ExpiresAt.UTC().Format(time.RFC3339)
		}
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			rec.JTI, rec.ClientID, rec.Subject, rec.Type,
			strings.Join(rec.Scopes, ","), issued, expires, rec.State(), rec.usageIP())
	}
	_ = w.Flush()
	return buf.String()
}

type TokenListCmd struct {
	Alias  string `arg:"" optional:"" help:"Alias of the server to query (default is the selected server)"`
	Type   string `help:"Filter by token type: IAT or STREAM" enum:"IAT,STREAM," default:""`
	Active string `help:"Filter by liveness: true (active) or false (revoked/expired)" enum:"true,false," default:""`
	Json   bool   `help:"Emit the raw JSON response instead of a table"`
}

func (t *TokenListCmd) Run(cli *CLI) error {
	server, err := cli.Data.GetServer(t.Alias)
	if err != nil {
		return err
	}

	// Project/client scope is derived server-side from the caller's bearer, never
	// from a query param. The only filters the server honors are type and active.
	q := url.Values{}
	if t.Type != "" {
		q.Set("type", t.Type)
	}
	if t.Active != "" {
		q.Set("active", t.Active)
	}
	reqUrl := server.Host + "/token"
	if len(q) > 0 {
		reqUrl += "?" + q.Encode()
	}

	req, err := http.NewRequest(http.MethodGet, reqUrl, nil)
	if err != nil {
		return err
	}
	if err = applyServerBearer(cli, server, req); err != nil {
		return err
	}

	client := getHttpClient(10 * time.Second)
	resp, err := client.Do(req)
	defer httpSupport.HandleRespClose(resp)
	if err != nil {
		return err
	}

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("error listing tokens: %s - %s", resp.Status, string(body))
	}

	if t.Json {
		fmt.Println(string(body))
		return nil
	}

	var records []tokenListEntry
	if err = json.Unmarshal(body, &records); err != nil {
		return fmt.Errorf("error parsing token list response: %w", err)
	}
	fmt.Print(renderTokenTable(records))
	return nil
}

type TokenRevokeCmd struct {
	Jti  string `arg:"" help:"The JTI of the token to revoke"`
	Json bool   `help:"Emit the raw JSON response instead of a confirmation message"`
}

func (t *TokenRevokeCmd) Run(cli *CLI) error {
	server, err := cli.Data.GetServer("")
	if err != nil {
		return err
	}

	reqUrl := server.Host + "/token/" + t.Jti
	req, err := http.NewRequest(http.MethodDelete, reqUrl, nil)
	if err != nil {
		return err
	}
	if err = applyServerBearer(cli, server, req); err != nil {
		return err
	}

	client := getHttpClient(10 * time.Second)
	resp, err := client.Do(req)
	defer httpSupport.HandleRespClose(resp)
	if err != nil {
		return err
	}

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("error revoking token: %s - %s", resp.Status, string(body))
	}

	if t.Json {
		if len(bytes.TrimSpace(body)) > 0 {
			fmt.Println(string(body))
		} else {
			fmt.Printf("{\"jti\":%q,\"revoked\":true}\n", t.Jti)
		}
		return nil
	}

	fmt.Printf("Token %s revoked.\n", t.Jti)
	return nil
}

type TokenIntrospectCmd struct {
	Token string `arg:"" help:"The token string to introspect"`
	Json  bool   `help:"Emit the raw JSON response instead of a table"`
}

func (t *TokenIntrospectCmd) Run(cli *CLI) error {
	server, err := cli.Data.GetServer("")
	if err != nil {
		return err
	}

	reqUrl := server.Host + "/introspect"
	data := url.Values{}
	data.Set("token", t.Token)

	req, err := http.NewRequest(http.MethodPost, reqUrl, strings.NewReader(data.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err = applyServerBearer(cli, server, req); err != nil {
		return err
	}

	client := getHttpClient(10 * time.Second)
	resp, err := client.Do(req)
	defer httpSupport.HandleRespClose(resp)
	if err != nil {
		return err
	}

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("error introspecting token: %s - %s", resp.Status, string(body))
	}

	fmt.Println(string(body))
	return nil
}

type TokenCmd struct {
	List       TokenListCmd       `cmd:"" help:"List issued tokens"`
	Revoke     TokenRevokeCmd     `cmd:"" help:"Revoke a token by JTI"`
	Introspect TokenIntrospectCmd `cmd:"" help:"Introspect a token (RFC7662)"`
}

// subjectFilterReviewWire mirrors the wire shape of the admin review endpoint
// (api_subject_filter_review.go) — just the policy fields the CLI prints. Kept
// local so the CLI is decoupled from the server's internal types.
type subjectFilterReviewWire struct {
	StreamId                   string             `json:"stream_id"`
	Mode                       string             `json:"mode,omitempty"`
	DefaultSubjects            string             `json:"default_subjects,omitempty"`
	EventSource                *model.EventSource `json:"event_source,omitempty"`
	SubjectRemovalGraceSeconds int                `json:"subject_removal_grace_seconds,omitempty"`
	PassthruNoLocalFilter      bool               `json:"passthru_no_local_filter,omitempty"`
}

// errSubjectFilteringDisabled is the sentinel returned when the admin review
// endpoint answers 404 — subject filtering is switched off server-wide. The
// CLI surfaces this as a plain operator message rather than a raw HTTP status.
var errSubjectFilteringDisabled = errors.New("subject filtering is disabled on this server")

// fetchSubjectFilterSettings issues a settings-only POST to the admin review
// endpoint (no subject body field) and decodes the policy bits.
func fetchSubjectFilterSettings(g *Globals, server *SsfServer, streamId string) (*subjectFilterReviewWire, error) {
	reqBody, err := json.Marshal(map[string]any{"stream_id": streamId})
	if err != nil {
		return nil, err
	}
	reviewUrl, err := url.JoinPath(server.Host, "/subject-filter/review")
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, reviewUrl, bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	bearer, err := serverBearer(g, server)
	if err != nil {
		return nil, err
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	req.Header.Set("Content-Type", "application/json")
	client := getHttpClient(0)
	defer client.CloseIdleConnections()
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer httpSupport.HandleRespClose(resp)
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusNotFound {
		// Subject filtering is disabled server-wide — surface the sentinel so
		// callers can render a plain operator message.
		return nil, errSubjectFilteringDisabled
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("subject-filter review request failed: %s: %s", resp.Status, string(respBody))
	}
	var wire subjectFilterReviewWire
	if err := json.Unmarshal(respBody, &wire); err != nil {
		return nil, fmt.Errorf("could not parse subject-filter review response: %w", err)
	}
	return &wire, nil
}

// formatSubjectFilterSettings renders the four subject-filter operator knobs.
// Defaults are shown as empty so an operator sees what is explicitly set
// versus what falls through to the server-wide default (matches the wire
// `omitempty` semantics — an empty field means "use the server default").
func formatSubjectFilterSettings(alias string, wire *subjectFilterReviewWire) string {
	es := "(unset)"
	if wire.EventSource != nil {
		es = wire.EventSource.Type
		if len(wire.EventSource.SourceStreamIds) > 0 {
			es = fmt.Sprintf("%s %v", es, wire.EventSource.SourceStreamIds)
		}
	}
	mode := wire.Mode
	if mode == "" {
		mode = "(unset)"
	}
	defaults := wire.DefaultSubjects
	if defaults == "" {
		defaults = "(unset)"
	}
	return fmt.Sprintf("Subject-filter settings for [%s]:\n  stream_id:                     %s\n  default_subjects:              %s\n  mode:                          %s\n  event_source:                  %s\n  subject_removal_grace_seconds: %d\n",
		alias, wire.StreamId, defaults, mode, es, wire.SubjectRemovalGraceSeconds)
}

// subjectFilterStatusWire mirrors the runtime-state portion of the admin
// review endpoint response (api_subject_filter_review.go) — the filter-table
// view a `get subject-filter status` operator sees. Kept local so the CLI is
// decoupled from the server's internal types; the JSON tags match the wire
// contract exactly.
type subjectFilterStatusWire struct {
	StreamId              string                     `json:"stream_id"`
	PassthruNoLocalFilter bool                       `json:"passthru_no_local_filter,omitempty"`
	Counts                *subjectFilterStatusCounts `json:"counts,omitempty"`
	Pending               []subjectFilterStatusEntry `json:"pending,omitempty"`
	Lookup                *subjectFilterStatusLookup `json:"lookup,omitempty"`
}

type subjectFilterStatusCounts struct {
	Total   int64 `json:"total"`
	Pending int64 `json:"pending"`
}

type subjectFilterStatusEntry struct {
	Subject      *goSet.SubjectIdentifier `json:"subject,omitempty"`
	CanonicalKey string                   `json:"canonical_key"`
	Kind         string                   `json:"kind"`
	EnforceAt    time.Time                `json:"enforce_at"`
}

type subjectFilterStatusLookup struct {
	Subject      *goSet.SubjectIdentifier `json:"subject"`
	Found        bool                     `json:"found"`
	Kind         string                   `json:"kind,omitempty"`
	CanonicalKey string                   `json:"canonical_key,omitempty"`
	EnforceAt    time.Time                `json:"enforce_at,omitempty"`
	Pending      bool                     `json:"pending,omitempty"`
	Delivers     bool                     `json:"delivers"`
}

// fetchSubjectFilterStatus issues a POST to the admin review endpoint and
// decodes the filter-table state. When subject is non-nil it rides in the body
// so the response carries a point-lookup result; otherwise the request is
// summary-only (counts + pending list).
func fetchSubjectFilterStatus(g *Globals, server *SsfServer, streamId string, subject *goSet.SubjectIdentifier) (*subjectFilterStatusWire, error) {
	body := map[string]any{"stream_id": streamId}
	if subject != nil {
		body["subject"] = subject
	}
	reqBody, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	reviewUrl, err := url.JoinPath(server.Host, "/subject-filter/review")
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, reviewUrl, bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	bearer, err := serverBearer(g, server)
	if err != nil {
		return nil, err
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	req.Header.Set("Content-Type", "application/json")
	client := getHttpClient(0)
	defer client.CloseIdleConnections()
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer httpSupport.HandleRespClose(resp)
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusNotFound {
		// Subject filtering is disabled server-wide — reuse the slice #107
		// sentinel so callers render a plain operator message.
		return nil, errSubjectFilteringDisabled
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("subject-filter review request failed: %s: %s", resp.Status, string(respBody))
	}
	var wire subjectFilterStatusWire
	if err := json.Unmarshal(respBody, &wire); err != nil {
		return nil, fmt.Errorf("could not parse subject-filter review response: %w", err)
	}
	return &wire, nil
}

// formatSubjectFilterStatus renders the runtime filter-table state for an
// operator: the aggregate counts, the pending-removal list, and an optional
// point-lookup result. A PASSTHRU stream keeps no local filter table — that is
// stated plainly rather than surfaced as an error or as empty counts.
func formatSubjectFilterStatus(alias string, wire *subjectFilterStatusWire) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Subject-filter status for [%s]:\n", alias)
	if wire.PassthruNoLocalFilter {
		b.WriteString("  This stream is PASSTHRU and keeps no local subject-filter table.\n")
	} else {
		total, pending := int64(0), int64(0)
		if wire.Counts != nil {
			total, pending = wire.Counts.Total, wire.Counts.Pending
		}
		fmt.Fprintf(&b, "  filter-table entries:  %d\n", total)
		fmt.Fprintf(&b, "  pending removals:      %d\n", pending)
		if len(wire.Pending) == 0 {
			b.WriteString("  pending-removal list:  (none)\n")
		} else {
			b.WriteString("  pending-removal list:\n")
			for _, e := range wire.Pending {
				fmt.Fprintf(&b, "    - %s  kind=%s  enforce-at=%s\n",
					e.CanonicalKey, e.Kind, e.EnforceAt.Format(time.RFC3339))
			}
		}
	}
	if wire.Lookup != nil {
		l := wire.Lookup
		b.WriteString("  point lookup:\n")
		fmt.Fprintf(&b, "    found:      %t\n", l.Found)
		if l.Found {
			fmt.Fprintf(&b, "    kind:       %s\n", l.Kind)
			fmt.Fprintf(&b, "    pending:    %t\n", l.Pending)
			if l.Pending {
				fmt.Fprintf(&b, "    enforce-at: %s\n", l.EnforceAt.Format(time.RFC3339))
			}
		}
		fmt.Fprintf(&b, "    delivers:   %t\n", l.Delivers)
	}
	return b.String()
}

// GetSubjectFilterConfigCmd retrieves a stream's four subject-filter operator
// knobs — defaultSubjects, subject-filter mode, event source, and the SSF §9.3
// removal grace seconds — and prints them (PRD #106 issue #107).
//
// `config` is the operator-tunable settings view: the knobs an operator sets.
// It is deliberately distinct from a future `status` sub-command, which
// surfaces runtime-derived filter-table state (counts, pending removals, point
// lookups). `config` answers "what policy is configured?"; `status` answers
// "what is the filter table doing right now?".
//
// It calls the existing PRD #97 /subject-filter/review endpoint settings-only
// (no subject in the body) and reuses the PRD #97 settings formatter — this is
// a CLI-only restructure, no server, wire, or authorization change.
type GetSubjectFilterConfigCmd struct {
	Alias string `arg:"" optional:"" help:"Stream alias whose subject-filter config to get (defaults to the selected stream)."`
}

func (g *GetSubjectFilterConfigCmd) Run(cli *CLI) error {
	alias := g.Alias
	if alias == "" {
		alias = cli.Data.Selected
	}
	stream, server := cli.Data.GetStreamAndServer(alias)
	if stream == nil {
		return errors.New("Could not locate locally defined stream alias: " + alias)
	}
	wire, err := fetchSubjectFilterSettings(&cli.Globals, server, stream.Id)
	if err != nil {
		// A 404 means subject filtering is switched off server-wide; surface a
		// plain operator message rather than a raw HTTP status.
		if errors.Is(err, errSubjectFilteringDisabled) {
			return errSubjectFilteringDisabled
		}
		return err
	}
	out := formatSubjectFilterSettings(alias, wire)
	fmt.Print(out)
	cli.GetOutputWriter().WriteString(out, true)
	return nil
}

// GetSubjectFilterStatusCmd retrieves a stream's runtime-derived subject-filter
// state — the filter-table view — and prints it (PRD #106 issue #108). With no
// subject it shows the summary: aggregate counts plus the pending-removal list.
// With a subject (positional JSON or format field flags) it adds a point-lookup
// result (found, kind, pending, delivers, enforce-at).
//
// `status` answers "what is the filter table doing right now?" — distinct from
// `config`, which shows the operator-tunable knobs. It calls the existing PRD
// #97 /subject-filter/review endpoint: settings-only when no subject, with the
// subject in the body for a point lookup.
//
// A PASSTHRU stream keeps no local filter table; that is reported plainly as a
// statement, not an error. A 404 (subject filtering disabled server-wide) is
// surfaced as the plain disabled message.
//
// The two positionals fill left-to-right under kong, so <alias> must be given
// explicitly whenever a positional subject is supplied.
type GetSubjectFilterStatusCmd struct {
	Alias       string `arg:"" optional:"" name:"alias" help:"Stream alias whose subject-filter status to get (defaults to the selected stream)."`
	SubjectJson string `arg:"" optional:"" name:"subject-json" help:"Optional SubjectIdentifier JSON literal for a point lookup. Mutually exclusive with the format field flags."`
	Email       string `optional:"" group:"Subject format flags" help:"Point-lookup subject in the email format."`
	PhoneNumber string `optional:"" group:"Subject format flags" help:"Point-lookup subject in the phone_number format."`
	Iss         string `optional:"" group:"Subject format flags" help:"Issuer half of an iss_sub-format point-lookup subject (requires --sub)."`
	Sub         string `optional:"" group:"Subject format flags" help:"Subject half of an iss_sub-format point-lookup subject (requires --iss)."`
	Id          string `optional:"" group:"Subject format flags" help:"Point-lookup subject in the opaque format."`
	Url         string `optional:"" group:"Subject format flags" help:"Point-lookup subject in the did format."`
	Username    string `optional:"" group:"Subject format flags" help:"Point-lookup subject in the username format."`
	ExternalId  string `optional:"" group:"Subject format flags" name:"external-id" help:"Point-lookup subject in the externalId format."`
	Account     string `optional:"" group:"Subject format flags" help:"Point-lookup subject in the account format."`
	Uri         string `optional:"" group:"Subject format flags" help:"Point-lookup subject in the uri format."`
}

// subjectArgs collects the format field flags into the pure subjectArgFlags
// struct so the shared subject-argument parser can be used without a kong
// dependency.
func (g *GetSubjectFilterStatusCmd) subjectArgs() subjectArgFlags {
	return subjectArgFlags{
		Email:       g.Email,
		PhoneNumber: g.PhoneNumber,
		Iss:         g.Iss,
		Sub:         g.Sub,
		Id:          g.Id,
		Url:         g.Url,
		Username:    g.Username,
		ExternalId:  g.ExternalId,
		Account:     g.Account,
		Uri:         g.Uri,
	}
}

func (g *GetSubjectFilterStatusCmd) Run(cli *CLI) error {
	alias := g.Alias
	if alias == "" {
		alias = cli.Data.Selected
	}
	stream, server := cli.Data.GetStreamAndServer(alias)
	if stream == nil {
		return errors.New("Could not locate locally defined stream alias: " + alias)
	}

	subject, err := parseSubjectArg(g.SubjectJson, g.subjectArgs())
	if err != nil {
		return err
	}

	review, err := fetchSubjectFilterStatus(&cli.Globals, server, stream.Id, subject)
	if err != nil {
		// A 404 means subject filtering is switched off server-wide; surface a
		// plain operator message rather than a raw HTTP status.
		if errors.Is(err, errSubjectFilteringDisabled) {
			return errSubjectFilteringDisabled
		}
		return err
	}
	out := formatSubjectFilterStatus(alias, review)
	fmt.Print(out)
	cli.GetOutputWriter().WriteString(out, true)
	return nil
}

// GetSubjectFilterCmd is the `get subject-filter` command group hung off the
// existing `get` verb (PRD #106). This slice ships the `config` sub-command
// only — the operator-tunable settings view. A `status` sub-command
// (runtime-derived filter-table state) is added in a later slice. The
// distinction is intentional: `config` = settings an operator sets; `status` =
// state the filter table derives at runtime.
type GetSubjectFilterCmd struct {
	Config GetSubjectFilterConfigCmd `cmd:"" help:"Get a stream's subject-filter config: the operator-tunable knobs (defaultSubjects, mode, event source, removal grace)."`
	Status GetSubjectFilterStatusCmd `cmd:"" help:"Get a stream's subject-filter status: filter-table counts, the pending-removal list, and an optional point lookup."`
}

// SetSubjectFilterConfigCmd changes a stream's subject-filter operator knobs
// through PRD #89's existing stream-update PUT path (PRD #106 issue #109). No
// new server endpoint is added: the JSON body PUT to /stream is a
// StreamStateRecord shape — the operator knobs ride at the top level alongside
// the embedded StreamConfiguration — and the server's StreamUpdate treats them
// as a partial update (empty/zero/omitted means "do not change").
//
// Each knob is individually optional; one call may change one knob or many.
// `--source-stream-ids` closes the gap that left EXPLICIT event sources
// unconfigurable from the CLI — it accepts raw stream SIDs, comma-separated or
// repeated, and is sent as the EXPLICIT event source's source stream IDs. The
// CLI rejects `--source-stream-ids` combined with a non-EXPLICIT event source
// and rejects `--event-source EXPLICIT` without `--source-stream-ids`;
// server-side mode/event-source validation is unchanged and still applies.
//
// After a successful update the command re-reads and displays the persisted
// settings so the operator sees what actually landed — in particular the
// server's WARN-and-ignore behaviour for a grace override set on a receiver
// stream (the persisted value comes back as 0). This reuses the slice #107
// `config` settings formatter.
type SetSubjectFilterConfigCmd struct {
	Alias           string   `arg:"" optional:"" help:"Stream alias to update (defaults to the selected stream)."`
	DefaultSubjects string   `optional:"" default:"" enum:"ALL,NONE," help:"Baseline policy (ALL or NONE). Omit to leave unchanged."`
	Mode            string   `optional:"" default:"" enum:"PASSTHRU,LOCAL,HYBRID," help:"Subject-filter mode for a receiver stream. Omit to leave unchanged."`
	EventSource     string   `optional:"" default:"" enum:"DIRECT,AUDIENCE,EXPLICIT," help:"Event source type for a transmitter stream. Omit to leave unchanged."`
	SourceStreamIds []string `optional:"" sep:"," help:"Source stream SIDs for an EXPLICIT event source (comma-separated or repeated)."`
	GraceSeconds    *int     `optional:"" help:"Per-transmitter-stream removal grace period override in seconds (SSF §9.3). 0 means immediate; omit to leave unchanged."`
}

func (s *SetSubjectFilterConfigCmd) Run(cli *CLI) error {
	alias := s.Alias
	if alias == "" {
		alias = cli.Data.Selected
	}
	stream, server := cli.Data.GetStreamAndServer(alias)
	if stream == nil {
		return errors.New("Could not locate locally defined stream alias: " + alias)
	}

	// CLI-side validation of the EXPLICIT / --source-stream-ids pairing,
	// performed before any HTTP request. Server-side mode/event-source
	// validation is unchanged and still applies.
	if len(s.SourceStreamIds) > 0 && s.EventSource != "" && s.EventSource != model.EventSourceExplicit {
		return errors.New("--source-stream-ids is only valid with --event-source EXPLICIT")
	}
	if s.EventSource == model.EventSourceExplicit && len(s.SourceStreamIds) == 0 {
		return errors.New("--event-source EXPLICIT requires --source-stream-ids")
	}

	// Build a partial-update body. The server's StreamUpdate reads it into a
	// StreamStateRecord and treats empty/zero/omitted fields as "no change".
	// The embedded StreamConfiguration is left untouched — only the
	// operator-knob fields are populated.
	body := map[string]any{
		"stream_id": stream.Id,
		// Echo the stream_id on the embedded configuration too so the server's
		// StreamUpdate authorization check finds it via configReq.Id.
		"id": stream.Id,
	}
	if s.DefaultSubjects != "" {
		body["default_subjects"] = s.DefaultSubjects
	}
	if s.Mode != "" {
		body["subject_filter_mode"] = s.Mode
	}
	if s.EventSource != "" {
		es := map[string]any{"type": s.EventSource}
		if len(s.SourceStreamIds) > 0 {
			es["source_stream_ids"] = s.SourceStreamIds
		}
		body["event_source"] = es
	}
	if s.GraceSeconds != nil {
		body["subject_removal_grace_seconds"] = *s.GraceSeconds
	}

	reqBytes, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPut,
		server.ServerConfiguration.ConfigurationEndpoint+"?stream_id="+stream.Id,
		bytes.NewReader(reqBytes))
	if err != nil {
		return err
	}
	bearer, err := serverBearer(&cli.Globals, server)
	if err != nil {
		return err
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	req.Header.Set("Content-Type", "application/json")
	client := getHttpClient(0)
	defer client.CloseIdleConnections()
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer httpSupport.HandleRespClose(resp)
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		// PRD #89 / #98 validation failures surface here with the server's
		// error message — e.g. an invalid LOCAL/HYBRID combination or a
		// negative grace value.
		return fmt.Errorf("stream update failed: %s: %s", resp.Status, strings.TrimSpace(string(respBody)))
	}
	cli.Data.ResetStreamConfig(alias)

	// Read back the post-update settings so the operator sees what actually
	// landed. This surfaces the server's WARN/ignore behavior for a grace
	// override set on a receiver stream — the persisted value comes back as 0.
	wire, err := fetchSubjectFilterSettings(&cli.Globals, server, stream.Id)
	if err != nil {
		// A 404 means subject filtering is switched off server-wide; surface a
		// plain operator message rather than a raw HTTP status.
		if errors.Is(err, errSubjectFilteringDisabled) {
			return errSubjectFilteringDisabled
		}
		return err
	}
	out := formatSubjectFilterSettings(alias, wire)
	fmt.Print(out)
	cli.GetOutputWriter().WriteString(out, true)
	return nil
}

// changeSubjectFilter performs an administrative SSF Add/Remove Subject from
// the CLI (PRD #106 issue #110). It is the shared body of `set subject-filter
// add` and `set subject-filter remove`: both resolve the alias, parse the
// subject through the shared subject-argument parser, and POST a
// { stream_id, subject, verified? } body to the SSF endpoint at endpointPath
// using the operator's admin token.
//
// The Add/Remove endpoints already accept ScopeStreamAdmin, so no new server
// API is involved. verified is only meaningful for Add — remove passes false
// and the `verified,omitempty` JSON tag keeps it off the wire. A 404 means
// subject filtering is disabled server-wide; it is surfaced as the plain
// errSubjectFilteringDisabled message.
func changeSubjectFilter(cli *CLI, alias, jsonArg string, flags subjectArgFlags, verified bool, endpointPath, verb string) error {
	if alias == "" {
		alias = cli.Data.Selected
	}
	stream, server := cli.Data.GetStreamAndServer(alias)
	if stream == nil {
		return errors.New("Could not locate locally defined stream alias: " + alias)
	}

	subject, err := parseSubjectArg(jsonArg, flags)
	if err != nil {
		return err
	}
	if subject == nil {
		return errors.New("a subject is required: supply a SubjectIdentifier JSON literal or the format field flags")
	}

	body := map[string]any{
		"stream_id": stream.Id,
		"subject":   subject,
	}
	if verified {
		body["verified"] = true
	}
	reqBody, err := json.Marshal(body)
	if err != nil {
		return err
	}

	endpointUrl, err := url.JoinPath(server.Host, endpointPath)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, endpointUrl, bytes.NewReader(reqBody))
	if err != nil {
		return err
	}
	bearer, err := serverBearer(&cli.Globals, server)
	if err != nil {
		return err
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	req.Header.Set("Content-Type", "application/json")

	client := getHttpClient(0)
	defer client.CloseIdleConnections()
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer httpSupport.HandleRespClose(resp)
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusNotFound {
		// Subject filtering is disabled server-wide — reuse the slice #107
		// sentinel so the operator sees a plain message, not a raw HTTP status.
		return errSubjectFilteringDisabled
	}
	// SSF Add returns 200; Remove returns 204 No Content.
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("subject %s request failed: %s: %s", verb, resp.Status, strings.TrimSpace(string(respBody)))
	}

	out := fmt.Sprintf("Subject %s on stream [%s].\n", verb, alias)
	fmt.Print(out)
	cli.GetOutputWriter().WriteString(out, true)
	return nil
}

// SetSubjectFilterAddCmd performs an administrative SSF Add Subject from the
// CLI (PRD #106 issue #110): it opts a subject into delivery on a stream by
// POSTing to the existing /add-subject endpoint with the operator's admin
// token. The subject is supplied as positional JSON or via the format field
// flags through the shared subject-argument parser. `--verified` sets the SSF
// Add Subject `verified` flag and is omitted by default.
type SetSubjectFilterAddCmd struct {
	Alias       string `arg:"" optional:"" name:"alias" help:"Stream alias to add the subject to (defaults to the selected stream)."`
	SubjectJson string `arg:"" optional:"" name:"subject-json" help:"SubjectIdentifier JSON literal. Mutually exclusive with the format field flags."`
	Verified    bool   `optional:"" help:"Set the SSF Add Subject verified flag (omitted by default)."`
	Email       string `optional:"" group:"Subject format flags" help:"Subject in the email format."`
	PhoneNumber string `optional:"" group:"Subject format flags" help:"Subject in the phone_number format."`
	Iss         string `optional:"" group:"Subject format flags" help:"Issuer half of an iss_sub-format subject (requires --sub)."`
	Sub         string `optional:"" group:"Subject format flags" help:"Subject half of an iss_sub-format subject (requires --iss)."`
	Id          string `optional:"" group:"Subject format flags" help:"Subject in the opaque format."`
	Url         string `optional:"" group:"Subject format flags" help:"Subject in the did format."`
	Username    string `optional:"" group:"Subject format flags" help:"Subject in the username format."`
	ExternalId  string `optional:"" group:"Subject format flags" name:"external-id" help:"Subject in the externalId format."`
	Account     string `optional:"" group:"Subject format flags" help:"Subject in the account format."`
	Uri         string `optional:"" group:"Subject format flags" help:"Subject in the uri format."`
}

func (s *SetSubjectFilterAddCmd) subjectArgs() subjectArgFlags {
	return subjectArgFlags{
		Email:       s.Email,
		PhoneNumber: s.PhoneNumber,
		Iss:         s.Iss,
		Sub:         s.Sub,
		Id:          s.Id,
		Url:         s.Url,
		Username:    s.Username,
		ExternalId:  s.ExternalId,
		Account:     s.Account,
		Uri:         s.Uri,
	}
}

func (s *SetSubjectFilterAddCmd) Run(cli *CLI) error {
	return changeSubjectFilter(cli, s.Alias, s.SubjectJson, s.subjectArgs(), s.Verified, "/add-subject", "added")
}

// SetSubjectFilterRemoveCmd performs an administrative SSF Remove Subject from
// the CLI (PRD #106 issue #110): it opts a subject out of delivery on a stream
// by POSTing to the existing /remove-subject endpoint with the operator's
// admin token. The subject is supplied as positional JSON or via the format
// field flags through the shared subject-argument parser. There is no
// `--verified` flag — verified is meaningful for Add only.
type SetSubjectFilterRemoveCmd struct {
	Alias       string `arg:"" optional:"" name:"alias" help:"Stream alias to remove the subject from (defaults to the selected stream)."`
	SubjectJson string `arg:"" optional:"" name:"subject-json" help:"SubjectIdentifier JSON literal. Mutually exclusive with the format field flags."`
	Email       string `optional:"" group:"Subject format flags" help:"Subject in the email format."`
	PhoneNumber string `optional:"" group:"Subject format flags" help:"Subject in the phone_number format."`
	Iss         string `optional:"" group:"Subject format flags" help:"Issuer half of an iss_sub-format subject (requires --sub)."`
	Sub         string `optional:"" group:"Subject format flags" help:"Subject half of an iss_sub-format subject (requires --iss)."`
	Id          string `optional:"" group:"Subject format flags" help:"Subject in the opaque format."`
	Url         string `optional:"" group:"Subject format flags" help:"Subject in the did format."`
	Username    string `optional:"" group:"Subject format flags" help:"Subject in the username format."`
	ExternalId  string `optional:"" group:"Subject format flags" name:"external-id" help:"Subject in the externalId format."`
	Account     string `optional:"" group:"Subject format flags" help:"Subject in the account format."`
	Uri         string `optional:"" group:"Subject format flags" help:"Subject in the uri format."`
}

func (s *SetSubjectFilterRemoveCmd) subjectArgs() subjectArgFlags {
	return subjectArgFlags{
		Email:       s.Email,
		PhoneNumber: s.PhoneNumber,
		Iss:         s.Iss,
		Sub:         s.Sub,
		Id:          s.Id,
		Url:         s.Url,
		Username:    s.Username,
		ExternalId:  s.ExternalId,
		Account:     s.Account,
		Uri:         s.Uri,
	}
}

func (s *SetSubjectFilterRemoveCmd) Run(cli *CLI) error {
	return changeSubjectFilter(cli, s.Alias, s.SubjectJson, s.subjectArgs(), false, "/remove-subject", "removed")
}

// SetSubjectFilterCmd is the `set subject-filter` command group hung off the
// existing `set` verb (PRD #106). `config` changes the operator-tunable knobs;
// `add` / `remove` perform administrative SSF Add/Remove Subject — all
// subject-filter writes share one parent group.
type SetSubjectFilterCmd struct {
	Config SetSubjectFilterConfigCmd `cmd:"" help:"Change a stream's subject-filter config knobs (defaultSubjects, mode, event source, source stream IDs, removal grace) via the existing stream-update path."`
	Add    SetSubjectFilterAddCmd    `cmd:"" help:"Add a subject to a stream's subject filter (administrative SSF Add Subject)."`
	Remove SetSubjectFilterRemoveCmd `cmd:"" help:"Remove a subject from a stream's subject filter (administrative SSF Remove Subject)."`
}
