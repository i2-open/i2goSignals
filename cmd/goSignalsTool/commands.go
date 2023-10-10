// nolint
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"

	"github.com/independentid/i2goSignals/internal/authUtil"
	"github.com/independentid/i2goSignals/internal/model"
	"github.com/independentid/i2goSignals/pkg/goScim/resource"

	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/independentid/i2goSignals/pkg/goSet"

	"github.com/alecthomas/kong"
	"github.com/golang-jwt/jwt/v4"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type AddServerCmd struct {
	Alias string `arg:"" help:"A unique name to identify the server"`
	Host  string `arg:"" required:"" help:"Http URL for a goSignals server"`
	Desc  string `help:"Description of project"`
	Email string `help:"Contact email for project"`
	Iat   string `help:"Registration Initial Access Auth if provided"`
	Token string `help:"Administration authorization token"`
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
		Alias:   as.Alias,
		Host:    serverUrl.String(),
		Streams: map[string]Stream{},
	}
	tryUrl, _ := serverUrl.Parse("/.well-known/sse-configuration")
	fmt.Println("Loading server configuration from: " + tryUrl.String())
	var resp *http.Response
	resp, err = http.Get(tryUrl.String())
	if err != nil {
		if strings.Contains(err.Error(), "gave HTTP response") {
			tryUrl.Scheme = "http"
			serverUrl.Scheme = "http"
			fmt.Println("Warning: HTTPS not supported trying HTTP at: " + tryUrl.String())
			resp, err = http.Get(tryUrl.String())
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

	if as.Iat != "" {
		server.IatToken = as.Iat
	} else if as.Token == "" {
		// Load tokens and register client
		iatUrl, _ := serverUrl.Parse("/iat")
		fmt.Println("Obtaining authorization...")
		resp, err = http.Get(iatUrl.String())
		if resp.StatusCode != http.StatusOK {
			fmt.Println("Error: unable to obtain registration IAT token")
			return err
		}
		regBytes, err := io.ReadAll(resp.Body)
		var registration model.RegisterResponse
		err = json.Unmarshal(regBytes, &registration)
		if err != nil {
			return err
		}
		server.IatToken = registration.Token
	}

	if as.Token != "" {
		server.ClientToken = as.Token
	} else {
		as.Desc = cleanQuotes(as.Desc)
		regUrl, _ := serverUrl.Parse("/register")
		clientReg := model.RegisterParameters{
			Scopes:      []string{authUtil.ScopeStreamAdmin, authUtil.ScopeStreamMgmt},
			Email:       as.Email,
			Description: as.Desc,
		}
		regBytes, _ := json.Marshal(&clientReg)
		req, err := http.NewRequest(http.MethodPost, regUrl.String(), bytes.NewReader(regBytes))
		req.Header.Set("Authorization", "Bearer "+server.IatToken)
		client := http.Client{}
		resp, err = client.Do(req)
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusOK {
			return errors.New("Unexpected status response: " + resp.Status)
		}
		var clientResponse model.RegisterResponse
		regBytes, err = io.ReadAll(resp.Body)
		err = json.Unmarshal(regBytes, &clientResponse)
		server.ClientToken = clientResponse.Token
	}

	c.Data.Servers[as.Alias] = server
	c.Data.Selected = as.Alias
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

	// Should override be allow if destAlias is set?

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
	Auth     string `group:"man" help:"An authorization header used to poll for events. Required u.nless Connect specified"`
	Connect  string `short:"c" group:"auto" xor:"man,auto" help:"The Alias of a stream which is publishing events using polling"`
	Mode     string `optional:"" default:"IMPORT" enum:"IMPORT,FORWARD,PUBLISH,I,F,P" help:"What should the receiver to with received events"`
}

func (p *CreatePollReceiverCmd) Run(cli *CLI) error {
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
		delivery.PushTransmitMethod = &model.PushTransmitMethod{
			Method:              model.DeliveryPush,
			EndpointUrl:         connectingConfig.Delivery.PushReceiveMethod.EndpointUrl,
			AuthorizationHeader: connectingConfig.Delivery.PushReceiveMethod.AuthorizationHeader,
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
		delivery.PollReceiveMethod = &model.PollReceiveMethod{
			Method:              model.ReceivePoll,
			EndpointUrl:         connectingConfig.Delivery.PollTransmitMethod.EndpointUrl,
			AuthorizationHeader: connectingConfig.Delivery.PollTransmitMethod.AuthorizationHeader,
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

func calculateEvents(requested []string, supported []string) []string {
	var delivered []string
	if len(requested) == 0 {
		return []string{}
	}
	if requested[0] == "*" {
		delivered = supported
		return delivered
	}

	for _, reqUri := range requested {
		compUri := "(?i)" + reqUri
		if strings.Contains(reqUri, "*") {
			compUri = strings.Replace(compUri, "*", ".*", -1)
		}

		for _, eventUri := range supported {
			match, err := regexp.MatchString(compUri, eventUri)
			if err != nil {
				continue
			} // ignore bad input
			if match {
				delivered = append(delivered, eventUri)
			}
		}
	}
	return delivered
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
	_, err = cli.executeCreateRequest(pubName, *regPublisherStreamRequest, serverPub, "Push Publisher to "+rcvName, rcvName)
	if err != nil {
		return errors.New(fmt.Sprintf("Error creating push publisher stream on %s: %s", serverPub.Alias, err.Error()))
	}
	fmt.Printf("... %s created.", pubName)
	return nil
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

	regBytes, err := json.MarshalIndent(&reg, "", " ")
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodPost, regUrl.String(), bytes.NewReader(regBytes))
	if err != nil {
		return nil, err
	}
	if server.ClientToken != "" {
		req.Header.Set("Authorization", "Bearer "+server.ClientToken)
	} else {
		fmt.Println("No server client token detected. Attempting anonymous request...")
	}

	client := http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	body, _ := io.ReadAll(resp.Body)

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

type CreateStreamCmd struct {
	Push       CreateStreamPushCmd `cmd:"" help:"Create a SET PUSH Stream (RFC8935)"`
	Poll       CreateStreamPollCmd `cmd:"" help:"Create a SET Polling Stream (RFC8936)"`
	Aud        []string            `optional:"" sep:"," help:"One or more audience values separated by commas"`
	Iss        string              `optional:"" help:"The event issuer value (e.g. scim.example.com)"`
	Name       string              `optional:"" short:"n" help:"An alias name for the stream to be created"`
	IssJwksUrl string              `optional:"" help:"The issuer JwksUrl value. Used for SET Event token validation."`
	Events     []string            `optional:"" default:"*" help:"The event uris (types) requested for a stream. Use '*' to match by wildcard."`
}

type CreateKeyCmd struct {
	Alias    string `arg:"" required:"" help:"The alias of the server to issue the key (default is selected server)"`
	IssuerId string `arg:"" required:"" help:"The issuer value associated with the key (e.g. example.com)"`
	File     string `optional:"" default:"issuer.pem" help:"Specify the file where the issued PEM is to be stored (default is issuer.pem)"`
}

func (c *CreateKeyCmd) Run(g *Globals) error {
	server, err := g.Data.GetServer(c.Alias)
	if err != nil {
		return err
	}
	baseUrl := fmt.Sprintf("%sjwks/%s", server.Host, c.IssuerId)
	req, _ := http.NewRequest(http.MethodPost, baseUrl, nil)
	if server.ClientToken != "" {
		req.Header.Set("Authorization", "Bearer "+server.ClientToken)
	} else {
		fmt.Println(fmt.Sprintf("No authorization information for %s, attempting anonymous request.", server.Alias))
	}
	client := http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	body, _ := io.ReadAll(resp.Body)

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

type CreateCmd struct {
	Stream CreateStreamCmd `cmd:"" aliases:"s"`
	Key    CreateKeyCmd    `cmd:"" help:"Obtain an issuer key from an i2goSignals server"`
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
	req.Header.Set("Authorization", "Bearer "+server.ClientToken)
	client := http.Client{}
	resp, err := client.Do(req)
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

	client := http.Client{}
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
	Stream GetStreamCmd `cmd:"" aliases:"s" help:"Get stream configurations or stream status"`
	Key    GetKeyCmd    `cmd:"" help:"Retrieves the issuer public key"`
}

type DeleteStreamCmd struct {
	Alias string `arg:"" help:"The alias of a stream to delete"`
}

func (d *DeleteStreamCmd) Run(cli *CLI) error {
	client := http.Client{}
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
	req.Header.Set("Authorization", "Bearer "+server.ClientToken)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
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
}

type SetStreamConfigCmd struct {
	Alias     string     `arg:"" optional:"" help:"Specify a stream alias, *, or blank to show all streams for the selected server"`
	Events    []string   `optional:"" short:"e" help:"Comma separated list of events to request. Or use +/- for delta to add or remove events" sep:"," `
	RJwksUrl  string     `optional:"" short:"r" help:"Set the receiver JWKS url"`
	IJwksUrl  string     `optional:"" short:"i" help:"Set the issuer JWKS url"`
	ResetJti  string     `optional:"" short:"j" xor:"reset" help:"Reset the stream to a particular JTI (and include all following events)"`
	ResetDate *time.Time `short:"d" xor:"reset" optional:"" type:"time.Time" help:"Reset stream to a specific date in RFC3339 format (e.g. 1985-04-12T23:20:50.52Z)"`
	Format    string     `optional:"" short:"f" help:"The sub_id type supported in the form of <format>:[<attr1>,<attr2>] - NOT CURRENTLY IMPLEMENTED"`
}

func (s *SetStreamConfigCmd) Run(cli *CLI) error {
	client := http.Client{}
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
	fmt.Println("Stream configuration for " + streamAlias)
	jsonBytes, _ := json.MarshalIndent(config, "", "  ")
	fmt.Println(string(jsonBytes))

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
		switch s.Events[0][0:0] {
		case "+", "-":
			config.EventsRequested = config.EventsDelivered
			for _, value := range s.Events {
				defaultAddMode := true
				switch value[0:0] {
				case "+":
					config.EventsRequested = append(config.EventsRequested, value[1:])
					defaultAddMode = true
				case "-":
					defaultAddMode = false
					removeEvent := value[1:]
					config.EventsRequested = removeValue(config.EventsRequested, removeEvent)
				default:
					if defaultAddMode {
						config.EventsRequested = append(config.EventsRequested, value)
					} else {
						config.EventsRequested = removeValue(config.EventsRequested, value)
					}
				}
			}
		default:
			config.EventsRequested = s.Events
		}
		fmt.Println(fmt.Sprintf("Requesting events:\n%+q", config.EventsRequested))

	}
	if ConfirmProceed("Update stream configuration Y|[n]?") {

		reqBytes, err := json.MarshalIndent(config, "", " ")
		req, err := http.NewRequest(http.MethodPut, server.ServerConfiguration.ConfigurationEndpoint+"?stream_id="+config.Id, bytes.NewReader(reqBytes))
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+server.ClientToken)
		client := http.Client{}
		resp, err := client.Do(req)
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

func removeValue(events []string, value string) []string {
	for i, other := range events {
		if strings.EqualFold(other, value) {
			return append(events[:i], events[i+1:]...)
		}
	}
	return events
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
		Status:  setStatus,
		Subject: nil,
		Reason:  cleanQuotes(s.Reason),
	}

	bodyBytes, err := json.MarshalIndent(updateStatus, "", " ")
	req, err := http.NewRequest(http.MethodPost, server.ServerConfiguration.StatusEndpoint+"?stream_id="+stream.Id, bytes.NewReader(bodyBytes))
	if err != nil {
		return err
	}
	if server.ClientToken != "" {
		req.Header.Set("Authorization", "Bearer "+server.ClientToken)
	} else {
		fmt.Println(fmt.Sprintf("No client admin token for %s, attempting anonymous request.", server.Alias))
	}

	client := http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	bodyBytes, _ = io.ReadAll(resp.Body)
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

type SetCmd struct {
	Stream SetStreamCmd `cmd:"" help:"Change settings on a stream"`
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
	client := http.Client{}
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

func (p *PollCmd) DoPollRequest(ctx context.Context, client http.Client, params model.PollParameters, endpoint string, token string, exitCh chan struct{}) (*model.PollResponse, error) {
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

func (p *PollCmd) DoAckOnly(ctx context.Context, client http.Client, endpoint string, token string, exitCh chan struct{}) {
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
			return errors.New("enter the Alias name for a push receiver stream.")
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
		endpoint = config.Delivery.PushReceiveMethod.EndpointUrl
		token = stream.Token
	}

	genResource := resource.GenerateFakeUser(issuer)
	subjectIdentifier := goSet.NewScimSubjectIdentifier(genResource.Meta.Location)

	event := goSet.CreateSet(&goSet.EventSubject{
		SubjectIdentifier: *subjectIdentifier,
	}, issuer, audience)

	event.TransactionId = primitive.NewObjectID().Hex()
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

	client := http.Client{}
	defer client.CloseIdleConnections()

	event.IssuedAt = jwt.NewNumericDate(time.Now())

	// Now we sign and deliver the event
	signString, err := event.JWS(jwt.SigningMethodRS256, key)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(signString))
	if token != "" {
		req.Header.Set("Authorization", stream.Token)
	}

	req.Header.Set("Content-Type", "application/secevent+jwt")
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
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
