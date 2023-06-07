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
			fmt.Println("Warning: HTTPS not supported trying HTTP at:" + tryUrl.String())
			resp, err = http.Get(tryUrl.String())
			if err != nil {
				return err
			}
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

	c.Data.Save(&c.Globals)
	return nil
}

type AddCmd struct {
	Server AddServerCmd `cmd:"" help:"Add a server to be configured."`
}

type EventUris struct {
	Events []string `optional:"" default:"*" help:"The event uris (types) requested for a stream"`
}

type CreateStreamPublisherCmd struct {
}

type CreatePollReceiverCmd struct {
	Source string `required:"" help:"The event publishers polling endpoint URL"`
	Token  string `required:"" help:"An authorization token used to poll for events"`
}

func (p *CreatePollReceiverCmd) Run(c *CreateCmd) error {
	jsonString, _ := json.MarshalIndent(c, "", "  ")
	out := fmt.Sprintf("POLL Receiver Command\n%s", jsonString)
	fmt.Println(out)
	return nil
}

type CreatePushReceiverCmd struct {
}

func (p *CreatePushReceiverCmd) Run(cli *CLI) error {
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
	out := fmt.Sprintf("Create Push Receiver Stream Request:\n%s", jsonString)
	fmt.Println(out)

	if !ConfirmProceed() {
		return nil
	}

	server, err := cli.Data.GetCurrentServer()
	if err != nil {
		return err
	}
	out = fmt.Sprintf("To be created on: %s/register", server.Host)
	serverUrl, err := url.Parse(server.Host)

	if err != nil {
		return err
	}

	requestUrl, err := serverUrl.Parse("/register")
	if err != nil {
		return err
	}

	fmt.Println("Registration URL: " + requestUrl.String())

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

	SessionGlobals.StreamToken = registration.Token
	jsonString, _ = json.MarshalIndent(registration, "", "  ")
	out = fmt.Sprintf("Create Registration Response:\n%s", jsonString)
	fmt.Println(out)

	fmt.Println("\nThe stream token has been cached for future requests.  Save the token for use in future sessions")

	return nil
}

type CreateStreamReceiverCmd struct {
	Poll       CreatePollReceiverCmd `cmd:"" help:"Create a polling receiver stream"`
	Push       CreatePushReceiverCmd `cmd:"" help:"Create a push receiver Stream and endpoint"`
	IssJwksUrl string                `optional:"" help:"The issuer JwksUrl value. Used for SET Event token validation."`
	Mode       string                `optional:"" default:"IMPORT" enum:"IMPORT,FORWARD,REPUBLISH,I,F,R" help:"What should the receiver to with received events"`
	EventUris
}

type CreateStreamCmd struct {
	Receive CreateStreamReceiverCmd  `cmd:"" short:"r" help:"Create a receiver stream"`
	Publish CreateStreamPublisherCmd `cmd:"" short:"p" help:"Create a publisher stream"`
	Aud     []string                 `default:"example.com" sep:"," help:"One or more audience values separated by commas"`
	Iss     string                   `optional:"" help:"The event issuer value (default: DEFAULT" default:"DEFAULT"`
}

type CreateCmd struct {
	Stream CreateStreamCmd `cmd:"" help:"Create a stream"`
}

type ExitCmd struct {
	Arg string `help:"Test exit param"`
}

func (e *ExitCmd) Run(globals *Globals) error {
	fmt.Println("Exiting...")
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

func (l *ListStreamsCmd) Run(globals *Globals) error {

	return nil
}

type ListCmd struct {
	Streams ListStreamsCmd `cmd:"" help:"List all streams or one or more specific streams"`
}

type VersionCmd struct{}

func (v *VersionCmd) Run(realCtx *kong.Context) error {
	fmt.Println("i2GoSignals client version ABC")
	return nil
}

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

func ConfirmProceed() bool {
	fmt.Print("Proceed Y|[N]? ")
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
