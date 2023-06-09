// nolint
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"i2goSignals/internal/model"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/alecthomas/kong"
)

type AddServerCmd struct {
	Alias string `arg:"" help:"A unique name to identify the server"`
	Host  string `arg:"" required:"" help:"Add a new goSignals server"`
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
	fmt.Println("Attempting to read configuration at: " + tryUrl.String())
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
	_ = cmd.Run(&c.Globals)
	return c.Data.Save(&c.Globals)
}

type AddCmd struct {
	Server AddServerCmd `cmd:"" help:"Add a server to be configured."`
}

type EventUris struct {
	Events []string `optional:"" default:"*" help:"The event uris (types) requested for a stream"`
}

type CreateStreamPublishPollCmd struct {
	Alias string `arg:"" optional:"" help:"The alias of the server to create the stream on (default is selected server)"`
}

func (p *CreateStreamPublishPollCmd) Run(cli *CLI) error {
	c := cli.Create.Stream

	reg := model.RegisterParameters{
		Audience:  c.Aud,
		Issuer:    c.Iss,
		EventUris: c.Publish.Events,
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

	return cli.executeCreateRequest(c.Name, reg, server, "Poll Publisher")
}

type CreateStreamPublishPushCmd struct {
	Alias     string `arg:"" optional:"" help:"The alias of the server to create the stream on (default is selected server)"`
	EventUrl  string `short:"e" optional:"" help:"Provide the endpoint where events may be delivered using SET Push. Required if DestAlias not provided."`
	Token     string `optional:"" help:"Provide the authorization token used to submit events at the endpoint url. Required if DestAlias not provided."`
	DestAlias string `optional:"" help:"The Alias of a stream which is publishing events. Specify in serverAlias.StreamAlias form."`
}

func (p CreateStreamPublishPushCmd) Run(cli *CLI) error {
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
		Audience:  c.Aud,
		Issuer:    c.Iss,
		Method:    model.DeliveryPush,
		EventUrl:  eventUrl,
		EventAuth: eventAuthorization,
		EventUris: c.Publish.Events,
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

	return cli.executeCreateRequest(c.Name, reg, server, "Push Publisher")
}

type CreateStreamPublisherCmd struct {
	Push CreateStreamPublishPushCmd `cmd:"" help:"Create a publishing push stream"`
	Poll CreateStreamPublishPollCmd `cmd:"" help:"Create a publishing poll stream"`
	// RcvJwksUrl string                     `optional:"" help:"The issuer JwksUrl value. Used for SET Event token validation."`
	EventUris
}

type CreateReceiverPollCmd struct {
	Alias       string `arg:"" optional:"" help:"The alias of the server to create the stream on (default is selected server)"`
	EventUrl    string `short:"e" help:"The event publishers polling endpoint URL. Required unless SourceAlias specified."`
	Token       string `help:"An authorization token used to poll for events. Required unless SourceAlias specified"`
	SourceAlias string `optional:"" help:"The Alias of a stream which is publishing events. Specify in serverAlias.StreamAlias form."`
}

func (p *CreateReceiverPollCmd) Run(cli *CLI) error {
	c := cli.Create.Stream
	var mode string
	switch c.Receive.Mode {
	case "IMPORT", "I":
		mode = model.RouteModeImport
	case "FORWARD", "F":
		mode = model.RouteModeForward
	case "REPUBLISH", "R", "P":
		mode = model.RouteModePublish
	}
	var inbound bool = true

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
		EventUris:     c.Receive.Events,
		IssuerJWKSUrl: c.Receive.IssJwksUrl,
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

	return cli.executeCreateRequest(c.Name, reg, server, "Poll Receiver")
}

type CreateReceiverPushCmd struct {
	Alias string `arg:"" optional:"" help:"The alias of the server to create the stream on (default is selected server)"`
}

func (p *CreateReceiverPushCmd) Run(cli *CLI) error {
	c := cli.Create.Stream
	var mode string
	switch c.Receive.Mode {
	case "IMPORT", "I":
		mode = model.RouteModeImport
	case "FORWARD", "F":
		mode = model.RouteModeForward
	case "REPUBLISH", "R", "P":
		mode = model.RouteModePublish
	}
	var inbound bool = true

	reg := model.RegisterParameters{
		Audience:      c.Aud,
		Issuer:        c.Iss,
		Inbound:       &inbound,
		Method:        model.DeliveryPush,
		RouteMode:     mode,
		EventUris:     c.Receive.Events,
		IssuerJWKSUrl: c.Receive.IssJwksUrl,
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

	return cli.executeCreateRequest(c.Name, reg, server, "Push Receiver")
}

func (cli *CLI) executeCreateRequest(streamAlias string, reg model.RegisterParameters, server *SsfServer, typeDescription string) error {
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
		Alias:       streamAlias,
		Token:       registration.Token,
		Id:          config.Id,
		Endpoint:    registration.PushUrl,
		Description: typeDescription,
	}
	server.Streams[streamAlias] = stream

	SessionGlobals.StreamToken = registration.Token
	jsonBytes, _ := json.MarshalIndent(stream, "", "  ")
	out := fmt.Sprintf("Stream defined:\n%s", string(jsonBytes))
	fmt.Println(out)

	fmt.Println("\nThe stream token has been cached for future requests.  Save the token for use in future sessions")

	return nil
}

type CreateStreamReceiverCmd struct {
	Poll       CreateReceiverPollCmd `cmd:"" help:"Create a polling receiver stream"`
	Push       CreateReceiverPushCmd `cmd:"" help:"Create a push receiver Stream and endpoint"`
	IssJwksUrl string                `optional:"" help:"The issuer JwksUrl value. Used for SET Event token validation."`
	Mode       string                `optional:"" default:"IMPORT" enum:"IMPORT,FORWARD,REPUBLISH,I,F,R" help:"What should the receiver to with received events"`
	EventUris
}

type CreateStreamCmd struct {
	Receive CreateStreamReceiverCmd  `cmd:"" help:"Create a receiver stream"`
	Publish CreateStreamPublisherCmd `cmd:"" help:"Create a publisher stream"`
	Aud     []string                 `default:"example.com" sep:"," help:"One or more audience values separated by commas"`
	Iss     string                   `optional:"" help:"The event issuer value (default: DEFAULT" default:"DEFAULT"`
	Name    string                   `optional:"" short:"n" help:"An alias name for the stream to be created"`
}

type CreateCmd struct {
	Stream CreateStreamCmd `cmd:"" help:"Create a stream"`
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

type ListStreamsCmd struct {
	Ids []string `sep:"," optional:"" help:"Specify 1 or more stream identifiers to list"`
}

type ListCmd struct {
	Streams ListStreamsCmd `cmd:"" help:"List all streams or one or more specific streams"`
}

type VersionCmd struct{}

type ShowTokenCmd struct {
}

func (s *ShowTokenCmd) Run(g *Globals) error {
	out := "Stream token: \n<undefined>"
	if g.StreamToken != "" {
		out = fmt.Sprintf("Stream token: \n%s", g.StreamToken)
	}
	fmt.Println(out)
	return nil
}

type ShowServerCmd struct {
	Alias string `arg:"" optional:"" help:"Specify a server alias, *, or blank to show the selected server"`
}

func (s *ShowServerCmd) Run(g *Globals) error {
	if len(g.Data.Servers) == 0 {
		fmt.Println("No servers defined.")
		return nil
	}
	switch s.Alias {
	case "":
		if g.Data.Selected == "" {
			return errors.New("no currently selected server")
		}
		s.Alias = g.Data.Selected
	case "*":
		output, _ := json.MarshalIndent(g.Data.Servers, "", "  ")
		fmt.Println("Servers locally configured:")
		fmt.Println(string(output))
		return nil
	default:
	}

	server, exists := g.Data.Servers[s.Alias]
	if exists {
		output, _ := json.MarshalIndent(server, "", "  ")
		fmt.Println("Server configured:")
		fmt.Println(string(output))
		return nil
	}
	return errors.New("server " + s.Alias + " not defined")
}

type ShowCmd struct {
	Token  ShowTokenCmd  `cmd:"" help:"Show the current stream access token"`
	Server ShowServerCmd `cmd:"" help:"Show information about locally defined servers"`
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
	Alias string `arg:"" help:"Specify the alias of the server to work with"`
}

func (s *SelectCmd) Run(g *Globals) error {
	_, exists := g.Data.Servers[s.Alias]
	if exists {
		g.Data.Selected = s.Alias
		fmt.Println(s.Alias + " selected.")
		return nil
	}
	return errors.New("server not found")
}
