// nolint
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"i2goSignals/internal/model"
	"io"
	"net/http"
	"net/url"
	"os"

	"github.com/alecthomas/kong"
)

type AttachCmd struct {
	DetachKeys string `help:"Override the key sequence for detaching a container"`
	NoStdin    bool   `help:"Do not attach STDIN"`
	SigProxy   bool   `help:"Proxy all received signals to the process" default:"true"`

	Container string `help:"Container ID to attach to."`
}

func (a *AttachCmd) Run(globals *Globals) error {
	fmt.Printf("Config: %s\n", globals.Config)
	fmt.Printf("Attaching to: %v\n", a.Container)
	fmt.Printf("SigProxy: %v\n", a.SigProxy)
	return nil
}

type ExitCmd struct {
	Arg string `help:"Test exit param"`
}

func (e *ExitCmd) Run(globals *Globals) error {
	fmt.Println("Exiting...")
	os.Exit(-1)
	return nil
}

type ListStreamsCmd struct {
	Ids []string `sep:"," optional:"" help:"Specify 1 or more stream identifiers to list"`
}

func (l *ListStreamsCmd) Run(globals *Globals) error {
	if globals.Server == "" {
		globals.Server = SessionGlobals.Server
	}
	output := fmt.Sprintf("server: %s\nauthz: %s\nstreams: %v", globals.Server, globals.Authorization, l.Ids)
	fmt.Println(output)
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

	server := GetServer(&cli.Globals)

	out = fmt.Sprintf("To be created on: %s/register", server)
	serverUrl, err := url.ParseRequestURI(server)
	if err == nil && serverUrl.Host == "" {
		serverUrl, err = url.ParseRequestURI("http://" + server)
	}
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

type VersionCmd struct{}

func (v *VersionCmd) Run(realCtx *kong.Context) error {
	fmt.Println("i2GoSignals client version ABC")
	return nil
}

func GetServer(g *Globals) string {
	if g.Server != "" {
		SessionGlobals.Server = g.Server
		return g.Server
	}
	if SessionGlobals.Server == "" {
		SessionGlobals.Server = "localhost:8888"
	}
	return SessionGlobals.Server
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

type ShowCmd struct {
	Token ShowTokenCmd `cmd:"" help:"Show the current stream access token"`
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
