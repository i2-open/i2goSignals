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
	"i2goSignals/internal/model"
	"i2goSignals/internal/providers/dbProviders/mongo_provider"
	"i2goSignals/pkg/goScim/resource"
	"regexp"

	"i2goSignals/pkg/goSet"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/alecthomas/kong"
	"github.com/golang-jwt/jwt/v4"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type AddServerCmd struct {
	Alias string `arg:"" help:"A unique name to identify the server"`
	Host  string `arg:"" required:"" help:"Http URL for a goSignals server"`
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
			Scheme:      "https",
			Opaque:      "",
			User:        nil,
			Host:        as.Host,
			Path:        "",
			RawPath:     "",
			OmitHost:    false,
			ForceQuery:  false,
			RawQuery:    "",
			Fragment:    "",
			RawFragment: "",
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
}

func (p *CreatePollPublisherCmd) Run(cli *CLI) error {
	c := cli.Create.Stream

	reg := model.RegisterParameters{
		Audience:      c.Aud,
		Issuer:        c.Iss,
		Method:        model.DeliveryPoll,
		EventUris:     c.Events,
		IssuerJWKSUrl: c.IssJwksUrl,
	}
	jsonString, _ := json.MarshalIndent(reg, "", "  ")
	server, err := cli.Data.GetServer(p.Alias)
	if err != nil {
		return err
	}
	out := fmt.Sprintf("Create publish POLL stream on: %s/register\n%s", server.Host, jsonString)
	fmt.Println(out)

	if !ConfirmProceed("") {
		return nil
	}

	return cli.executeCreateRequest(c.Name, reg, server, "Poll Publisher", "")
}

type CreatePushPublisherCmd struct {
	Alias     string `arg:"" optional:"" help:"The alias of the server to create the stream on (default is selected server)"`
	EventUrl  string `short:"e" optional:"" help:"Provide the endpoint where events may be delivered using SET Push. Required if DestAlias not provided."`
	Token     string `optional:"" help:"Provide the authorization token used to submit events at the endpoint url. Required if DestAlias not provided."`
	DestAlias string `optional:"" help:"The Alias of a stream which is publishing events. Specify in serverAlias.StreamAlias form."`
}

func (p CreatePushPublisherCmd) Run(cli *CLI) error {
	c := cli.Create.Stream

	eventUrl := p.EventUrl
	eventAuthorization := p.Token

	if p.DestAlias != "" {
		parts := strings.Split(p.DestAlias, ".")
		if len(parts) != 2 {
			return errors.New("specify destAlias in `.` form. For example:  goSignals1.Xv1")
		}

		server, err := cli.Data.GetServer(parts[0])
		if err != nil {
			return err
		}
		stream, exist := server.Streams[parts[1]]
		if !exist {
			return errors.New("Could not find a stream identified by " + parts[1] + " for server " + parts[0])
		}
		eventUrl = stream.Endpoint
		eventAuthorization = stream.Token
	}

	if eventUrl == "" || eventAuthorization == "" {
		return errors.New("either --url and --token parameters or --destAlias parameters must be specified")
	}

	reg := model.RegisterParameters{
		Audience:      c.Aud,
		Issuer:        c.Iss,
		Method:        model.DeliveryPush,
		EventUrl:      eventUrl,
		EventAuth:     eventAuthorization,
		EventUris:     c.Events,
		IssuerJWKSUrl: c.IssJwksUrl,
	}
	jsonString, _ := json.MarshalIndent(reg, "", "  ")
	server, err := cli.Data.GetServer(p.Alias)
	if err != nil {
		return err
	}
	out := fmt.Sprintf("Create publish PUSH stream on: %s/register\n%s", server.Host, jsonString)
	fmt.Println(out)

	if !ConfirmProceed("") {
		return nil
	}

	return cli.executeCreateRequest(c.Name, reg, server, "Push Publisher", "")
}

type CreatePollReceiverCmd struct {
	Alias       string `arg:"" optional:"" help:"The alias of the server to create the stream on (default is selected server)"`
	EventUrl    string `short:"e" help:"The event publishers polling endpoint URL. Required unless SourceAlias specified."`
	Token       string `help:"An authorization token used to poll for events. Required unless SourceAlias specified"`
	SourceAlias string `optional:"" help:"The Alias of a stream which is publishing events. Specify in serverAlias.StreamAlias form."`
	Mode        string `optional:"" default:"IMPORT" enum:"IMPORT,FORWARD,REPUBLISH,I,F,R" help:"What should the receiver to with received events"`
}

func (p *CreatePollReceiverCmd) Run(cli *CLI) error {
	c := cli.Create.Stream
	var mode string
	switch p.Mode {
	case "IMPORT", "I":
		mode = model.RouteModeImport
	case "FORWARD", "F":
		mode = model.RouteModeForward
	case "REPUBLISH", "R", "P":
		mode = model.RouteModePublish
	}
	var inbound = true

	eventUrl := p.EventUrl
	eventAuthorization := p.Token

	if p.SourceAlias != "" {
		parts := strings.Split(p.SourceAlias, ".")
		if len(parts) != 2 {
			return errors.New("specify sourceAlias in `.` form. For example:  goSignals1.Xv1")
		}

		server, err := cli.Data.GetServer(parts[0])
		if err != nil {
			return err
		}
		stream, exist := server.Streams[parts[1]]
		if !exist {
			return errors.New("Could not find a stream identified by " + parts[1] + " for server " + parts[0])
		}
		eventUrl = stream.Endpoint
		eventAuthorization = stream.Token
	}

	if eventUrl == "" || eventAuthorization == "" {
		return errors.New("either --url and --token parameters or --sourceAlias parameters must be specified")
	}

	reg := model.RegisterParameters{
		Audience:      c.Aud,
		Issuer:        c.Iss,
		Inbound:       &inbound,
		Method:        model.DeliveryPoll,
		RouteMode:     mode,
		EventUrl:      eventUrl,
		EventAuth:     eventAuthorization,
		EventUris:     c.Events,
		IssuerJWKSUrl: c.IssJwksUrl,
	}
	jsonString, _ := json.MarshalIndent(reg, "", "  ")
	server, err := cli.Data.GetServer(p.Alias)
	if err != nil {
		return err
	}
	out := fmt.Sprintf("Create receiver POLL stream on: %s/register\n%s", server.Host, jsonString)
	fmt.Println(out)

	if !ConfirmProceed("") {
		return nil
	}

	return cli.executeCreateRequest(c.Name, reg, server, "Poll Receiver", "")
}

type CreatePushReceiverCmd struct {
	Alias string `arg:"" optional:"" help:"The alias of the server to create the stream on (default is selected server)"`
	Mode  string `optional:"" default:"IMPORT" enum:"IMPORT,FORWARD,REPUBLISH,I,F,R" help:"What should the receiver to with received events"`
}

func (p *CreatePushReceiverCmd) Run(cli *CLI) error {
	c := cli.Create.Stream
	var mode string
	switch p.Mode {
	case "IMPORT", "I":
		mode = model.RouteModeImport
	case "FORWARD", "F":
		mode = model.RouteModeForward
	case "REPUBLISH", "R", "P":
		mode = model.RouteModePublish
	}
	var inbound = true

	reg := model.RegisterParameters{
		Audience:      c.Aud,
		Issuer:        c.Iss,
		Inbound:       &inbound,
		Method:        model.DeliveryPush,
		RouteMode:     mode,
		EventUris:     c.Events,
		IssuerJWKSUrl: c.IssJwksUrl,
	}
	jsonString, _ := json.MarshalIndent(reg, "", "  ")
	server, err := cli.Data.GetServer(p.Alias)
	if err != nil {
		return err
	}
	out := fmt.Sprintf("Create receiver PUSH stream  on: %s/register\n%s", server.Host, jsonString)

	fmt.Println(out)

	if !ConfirmProceed("") {
		return nil
	}

	return cli.executeCreateRequest(c.Name, reg, server, "Push Receiver", "")
}

type CreatePollConnectionCmd struct {
	SourceAlias string `arg:"" help:"The alias of the publishing server or existing stream alias."`
	DestAlias   string `arg:"" help:"The alias of receiving server."`
	Mode        string `optional:"" default:"IMPORT" enum:"IMPORT,FORWARD,REPUBLISH,I,F,R" help:"What should the receiver to with received events"`
}

func createRegRequestFromParams(method string, modeParam string, inbound bool, cli *CLI, config *model.StreamConfiguration) *model.RegisterParameters {
	reg := &model.RegisterParameters{
		Method: method,
	}
	if modeParam != "" {
		var mode string
		switch modeParam {
		case "IMPORT", "I":
			mode = model.RouteModeImport
		case "FORWARD", "F":
			mode = model.RouteModeForward
		case "REPUBLISH", "R", "P":
			mode = model.RouteModePublish
		}
		reg.RouteMode = mode
	}
	if inbound {
		reg.Inbound = &inbound
	}

	if config != nil {
		reg.EventUris = config.EventsDelivered
		reg.Audience = config.Aud
		reg.Issuer = config.Iss
		reg.IssuerJWKSUrl = config.IssuerJWKSUrl
	}

	// command parameters always override existing configuration
	streamParams := cli.Create.Stream

	if len(streamParams.Events) > 0 && streamParams.Events[0] != "*" {
		supportedEvents := mongo_provider.GetSupportedEvents()
		if config != nil {
			supportedEvents = config.EventsDelivered
		}
		reg.EventUris = calculateEvents(streamParams.Events, supportedEvents)
	}

	if len(streamParams.Aud) > 0 {
		reg.Audience = streamParams.Aud
	}

	if streamParams.Iss != "" {
		reg.Issuer = streamParams.Iss
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
	// In this request, the PUSH Server is created first
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

	var regReceiveStreamRequest, regPublisherStreamRequest *model.RegisterParameters

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
		regReceiveStreamRequest = createRegRequestFromParams(model.DeliveryPoll, p.Mode, true, cli, streamConfig)
		regReceiveStreamRequest.EventUrl = streamPub.Endpoint
		regReceiveStreamRequest.EventAuth = streamPub.Token
		regReceiveStreamRequest.IssuerJWKSUrl = streamPub.IssJwksUrl
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
		regPublisherStreamRequest = createRegRequestFromParams(model.DeliveryPoll, "", false, cli, nil)
		fmt.Printf("Creating publishing and receiver poll streams on %s and %s based on the following:", serverPub.Alias, serverRcv.Alias)
		jsonBytes, _ := json.MarshalIndent(regPublisherStreamRequest, "", " ")
		fmt.Println(string(jsonBytes))
		if !ConfirmProceed("") {
			return nil
		}
	}

	if regPublisherStreamRequest != nil {
		fmt.Println("Creating publisher stream...")
		err := cli.executeCreateRequest(pubName, *regPublisherStreamRequest, serverPub, "Poll Publisher Connection to "+rcvName, rcvName)
		if err != nil {
			return errors.New(fmt.Sprintf("Error creating polling publisher stream on %s: %s", serverPub.Alias, err.Error()))
		}
		fmt.Printf("... %s created.", pubName)
		streamPub, _ = cli.Data.GetStreamAndServer(pubName)
	}
	if regReceiveStreamRequest == nil {
		// if this is null it is because the publisher was created in the previous block (rather than pre-existing)
		streamConfig, _ := cli.Data.GetStreamConfig(pubName)
		// Now, build the receiver stream based on the new publisher stream
		regReceiveStreamRequest = createRegRequestFromParams(model.DeliveryPoll, p.Mode, true, cli, streamConfig)
		regReceiveStreamRequest.EventUrl = streamPub.Endpoint
		regReceiveStreamRequest.EventAuth = streamPub.Token
		regReceiveStreamRequest.IssuerJWKSUrl = streamPub.IssJwksUrl
	}

	fmt.Println("Creating polling receiver stream...")
	err := cli.executeCreateRequest(rcvName, *regReceiveStreamRequest, serverRcv, "Poll Receivers Connection from "+pubName, pubName)
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

	var regReceiveStreamRequest, regPublisherStreamRequest *model.RegisterParameters

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
		regPublisherStreamRequest = createRegRequestFromParams(model.DeliveryPush, "", false, cli, streamConfig)
		regPublisherStreamRequest.EventUrl = streamRcv.Endpoint
		regPublisherStreamRequest.EventAuth = streamRcv.Token
		regPublisherStreamRequest.IssuerJWKSUrl = streamRcv.IssJwksUrl
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
		regReceiveStreamRequest = createRegRequestFromParams(model.DeliveryPush, p.Mode, true, cli, nil)
		fmt.Printf("Creating publishing and receiver push streams on %s and %s based on the following:\n", serverPub.Alias, serverRcv.Alias)
		jsonBytes, _ := json.MarshalIndent(regPublisherStreamRequest, "", " ")
		fmt.Println(string(jsonBytes))
		if !ConfirmProceed("") {
			return nil
		}
	}

	if regReceiveStreamRequest != nil {
		fmt.Println("Creating push receiver stream...")
		err := cli.executeCreateRequest(rcvName, *regReceiveStreamRequest, serverRcv, "Push Receiver Connection from "+pubName, pubName)
		if err != nil {
			return errors.New(fmt.Sprintf("Error creating polling publisher stream on %s: %s", serverPub.Alias, err.Error()))
		}
		fmt.Printf("... %s created.", rcvName)
		streamRcv, _ = cli.Data.GetStreamAndServer(rcvName)
	}
	if regPublisherStreamRequest == nil {
		streamConfig, _ := cli.Data.GetStreamConfig(rcvName)
		// Now, build the receiver stream based on the new publisher stream
		regPublisherStreamRequest = createRegRequestFromParams(model.DeliveryPush, "", false, cli, streamConfig)
		regPublisherStreamRequest.EventUrl = streamRcv.Endpoint
		regPublisherStreamRequest.EventAuth = streamRcv.Token
		regPublisherStreamRequest.IssuerJWKSUrl = streamRcv.IssJwksUrl
	}

	fmt.Println("Creating push publisher stream...")
	err := cli.executeCreateRequest(pubName, *regPublisherStreamRequest, serverPub, "Push Publisher to "+rcvName, rcvName)
	if err != nil {
		return errors.New(fmt.Sprintf("Error creating push publisher stream on %s: %s", serverPub.Alias, err.Error()))
	}
	fmt.Printf("... %s created.", pubName)
	return nil
}

func (cli *CLI) executeCreateRequest(streamAlias string, reg model.RegisterParameters, server *SsfServer, typeDescription string, connectAlias string) error {

	serverUrl, err := url.Parse(server.Host)
	if err != nil {
		return err
	}
	requestUrl, err := serverUrl.Parse("/register")
	if err != nil {
		return err
	}

	regBytes, err := json.MarshalIndent(&reg, "", " ")
	if err != nil {
		return err
	}

	resp, err := http.Post(requestUrl.String(), "application/json", bytes.NewReader(regBytes))
	if err != nil {
		return err
	}
	body, _ := io.ReadAll(resp.Body)

	var registration model.RegisterResponse
	err = json.Unmarshal(body, &registration)
	if err != nil {
		return err
	}

	if streamAlias == "" {

		streamAlias = generateAlias(3)
		for _, exists := server.Streams[streamAlias]; exists; _, exists = server.Streams[streamAlias] {
			streamAlias = generateAlias(3)
		}

	}

	req, err := http.NewRequest(http.MethodGet, server.ServerConfiguration.ConfigurationEndpoint, nil)
	req.Header.Set("Authorization", "Bearer "+registration.Token)
	client := http.Client{}
	resp, err = client.Do(req)
	if err != nil {
		return err
	}

	bodyBytes, _ := io.ReadAll(resp.Body)
	var config model.StreamConfiguration
	_ = json.Unmarshal(bodyBytes, &config)

	stream := Stream{
		Alias:        streamAlias,
		Token:        registration.Token,
		Id:           config.Id,
		Endpoint:     registration.PushUrl,
		Description:  typeDescription,
		Iss:          config.Iss,
		Aud:          strings.Join(config.Aud[:], ","),
		IssJwksUrl:   config.IssuerJWKSUrl,
		ConnectAlias: connectAlias,
	}
	server.Streams[streamAlias] = stream

	SessionGlobals.StreamToken = registration.Token
	jsonBytes, _ := json.MarshalIndent(stream, "", "  ")

	cli.GetOutputWriter().WriteBytes(jsonBytes, true)

	out := fmt.Sprintf("Stream defined:\n%s", string(jsonBytes))
	fmt.Println(out)
	err = cli.Data.Save(&cli.Globals)
	if err != nil {
		return err
	}

	return nil
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

type CreateIssuerKeyCmd struct {
	Alias    string `arg:"" help:"The alias of the server to issue the key (default is selected server)"`
	IssuerId string `arg:"" help:"The issuer value associated with the key (e.g. example.com)"`
	File     string `optional:"" default:"issuer.pem" help:"Specify the file where the issued PEM is to be stored (default is issuer.pem)"`
}

func (c *CreateIssuerKeyCmd) Run(g *Globals) error {
	server, err := g.Data.GetServer(c.Alias)
	if err != nil {
		return err
	}
	baseUrl := fmt.Sprintf("%sjwks/%s", server.Host, c.IssuerId)
	req, _ := http.NewRequest(http.MethodPost, baseUrl, nil)
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
	Stream CreateStreamCmd    `cmd:"" aliases:"s"`
	Key    CreateIssuerKeyCmd `cmd:"" help:"Obtain an issuer key from an i2goSignals server"`
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
	err = ctx.PrintUsage(false)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintln(realCtx.Stdout)
	return nil
}

type ShowTokenCmd struct {
	Alias string `arg:"" optional:"" help:"The alias of a stream, or defaults to currently selected stream"`
}

func (s *ShowTokenCmd) Run(c *CLI) error {
	out := "Stream token: \n<undefined>"

	if s.Alias == "" {
		if c.StreamToken != "" {
			c.GetOutputWriter().WriteString(c.StreamToken, true)
			out = fmt.Sprintf("Stream token: \n%s", c.StreamToken)
			fmt.Println(out)
			return nil
		}
	}

	stream, _ := c.Data.GetStreamAndServer(s.Alias)
	if stream != nil {
		c.GetOutputWriter().WriteString(c.StreamToken, true)

		out = fmt.Sprintf("Stream token: \n%s", c.StreamToken)
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
		fmt.Println("Server configured:")
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
	Token  ShowTokenCmd  `cmd:"" help:"Show the current stream access token"`
	Server ShowServerCmd `cmd:"" help:"Show information about locally defined servers"`
	Stream ShowStreamCmd `cmd:"" help:"Show locally defined streams"`
}

type GetStreamStatusCmd struct {
	Alias string `arg:"" optional:"" help:"Specify a stream alias, *, or blank to show all streams for the selected server"`
}

func (s *GetStreamStatusCmd) Run(cli *CLI) error {

	streamAlias := s.Alias
	if streamAlias == "" {
		return errors.New("please provide the alias of a stream to get status")
	}

	streamConfig, server := cli.Data.GetStreamAndServer(streamAlias)
	if streamConfig == nil {
		return errors.New("Could not locate locally defined stream alias: " + streamAlias)
	}

	req, err := http.NewRequest(http.MethodGet, server.ServerConfiguration.StatusEndpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+streamConfig.Token)
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
		fmt.Println("Server: " + server.Alias + "\nHas no streams defined.")
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
		stream, server := c.Data.GetStreamAndServer(g.Alias)

		if stream != nil {
			jwksUrl = stream.IssJwksUrl
		} else {
			if g.Iss == "" || server == nil {
				return errors.New("invalid server alias and/or missing iss value")
			}
			jwksUrl = fmt.Sprintf("%s/jwks/%s", server.Host, g.Iss)
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
		req, err := http.NewRequest(http.MethodPost, server.ServerConfiguration.ConfigurationEndpoint, bytes.NewReader(reqBytes))
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+streamConfig.Token)
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
	State  string `required:"" short:"m" enum:"active,pause,inactive,a,p,i" help:"Enter a valid new state (active,pause,inactive)"`
	Reason string `optional:"" short:"r" help:"Enter the reason for the state change request in quotes"`
}

func (s *SetStreamStatusCmd) Run(cli *CLI) error {
	setStatus := "A"
	switch s.State {
	case "a", "active":
		setStatus = "A"
	case "p", "pause":
		setStatus = "P"
	case "i", "inactive":
		setStatus = "I"
	}

	var server *SsfServer
	var stream *Stream
	var token string
	if s.Alias != "" {
		stream, server = cli.Data.GetStreamAndServer(s.Alias)
		token = stream.Token
	} else {
		server, _ = cli.Data.GetServer(cli.Data.Selected)
		token = cli.StreamToken
	}

	if server == nil || token == "" {
		return errors.New("please select or provide a valid stream")
	}

	updateStatus := model.UpdateStreamStatus{
		Status:  setStatus,
		Subject: nil,
		Reason:  s.Reason,
	}

	bodyBytes, err := json.MarshalIndent(updateStatus, "", " ")
	req, err := http.NewRequest(http.MethodPost, server.ServerConfiguration.StatusEndpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	client := http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	bodyBytes, _ = io.ReadAll(resp.Body)
	var status model.StreamStatus
	_ = json.Unmarshal(bodyBytes, &status)

	fmt.Println("Returned status:")
	fmt.Println(json.MarshalIndent(status, "", "  "))

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
	_, exists := g.Data.Servers[s.Alias]
	if exists {
		g.Data.Selected = s.Alias
		fmt.Println("Server: " + s.Alias + " selected.")
		g.StreamToken = ""
		return nil
	}
	stream, server := g.Data.GetStreamAndServer(s.Alias)
	if stream != nil {
		g.Data.Selected = server.Alias
		g.StreamToken = stream.Token
		fmt.Println(fmt.Sprintf("Server: %s, Stream: %s selected.", server.Alias, stream.Alias))
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

	// Get the issuer public key
	jwks, err := goSet.GetJwks(config.IssuerJWKSUrl)
	if err != nil {
		fmt.Println("Error retrieving the issuer public key: " + err.Error())
		return
	}

	for {
		fmt.Println(fmt.Sprintf("Initiating polling to %s, stream %s...", server.Alias, stream.Alias))
		params.Acks = p.Acks

		pollResponse, err := p.DoPollRequest(ctx, client, params, stream, exitCh)
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
			p.DoAckOnly(ctx, client, stream, exitCh)
		}
		select {
		case <-ctx.Done():
			fmt.Println("Received cancel!")
			p.DoAckOnly(ctx, client, stream, exitCh)
			exitCh <- struct{}{}
			return
		default:
		}
	}
}

func (p *PollCmd) DoPollRequest(ctx context.Context, client http.Client, params model.PollParameters, stream *Stream, exitCh chan struct{}) (*model.PollResponse, error) {
	bodyBytes, err := json.MarshalIndent(params, "", " ")
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, stream.Endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+stream.Token)

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

func (p *PollCmd) DoAckOnly(ctx context.Context, client http.Client, stream *Stream, exitCh chan struct{}) {
	if p.AutoAck && len(p.Acks) > 0 {
		pollRequest := model.PollParameters{
			MaxEvents:         0,
			ReturnImmediately: true,
			Acks:              p.Acks,
		}
		pollResponse, err := p.DoPollRequest(ctx, client, pollRequest, stream, exitCh)
		if err != nil {
			fmt.Println("Error occurred performing polling acknowledgement: " + err.Error())
			return
		}
		if len(pollResponse.Sets) > 0 {
			fmt.Println(fmt.Sprintf("Warning, %d SETs were returned from a maxevents=0 request (ack only) to %s", len(pollResponse.Sets), stream.Alias))
		}
	}
	return

}

type GenerateCmd struct {
	Event string `arg:"" help:"An event type URI (or the last portion of it) of the event to create"`
	Alias string `arg:"" optional:"" help:"The stream alias to submit the event to, otherwise event is displayed to console"`
}

func (gen *GenerateCmd) Run(c *CLI) error {

	issuer := "gen.scim.example.com"
	audience := []string{"receiver.example.com"}
	var stream *Stream
	var server *SsfServer
	var config *model.StreamConfiguration
	var key *rsa.PrivateKey
	var err error
	if gen.Alias != "" {
		stream, server = c.Data.GetStreamAndServer(gen.Alias)
		if server == nil || stream == nil {
			return errors.New("enter the Alias name for a stream defined locally. See Show Stream *")
		}
		config, err = c.Data.GetStreamConfig(gen.Alias)
		issuer = config.Iss
		if err != nil {
			return err
		}
		audience = config.Aud

		pushDelivery := config.Delivery.PushDeliveryMethod
		if pushDelivery == nil {
			return errors.New("generate event currently requires a push event stream to submit")
		}
		key, err = c.Data.GetKey(config.Iss)
		if err != nil {
			return err
		}
	}

	genResource := resource.GenerateFakeUser(issuer)
	subjectIdentifier := goSet.NewScimSubjectIdentifier(genResource.Meta.Location)
	event := goSet.SecurityEventToken{}
	event.SubjectId = subjectIdentifier
	event.Issuer = issuer
	event.Audience = audience
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
	req, err := http.NewRequest(http.MethodPost, stream.Endpoint, strings.NewReader(signString))
	req.Header.Set("Authorization", "Bearer "+stream.Token)
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
		fmt.Println(fmt.Sprintf("Error:\n\tDescription:\t%s\n\tError:\t%s", errorMsg.Description, errorMsg.ErrCode))
		return nil
	}
	if resp.StatusCode > 400 {
		errMsg := fmt.Sprintf("HTTP Error: %s, POSTING to %s", resp.Status, stream.Endpoint)
		return errors.New(errMsg)
	}
	c.GetOutputWriter().WriteString(event.String(), true)
	return nil
}
