// nolint
package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/alecthomas/kong"
)

type Globals struct {
	Config      string     `help:"Location of client config files" default:"~/.goSignals/config.json" type:"path"`
	Server      string     `help:"The URL of an i2goServer or use an environment variable GOSIGNALS_URL" env:"GOSIGNALS_URL"`
	StreamToken string     `help:"A token used to manage a stream"`
	Data        ConfigData `kong:"-"`
	// Output      string     `help:"To redirect output to a file" type:"path" `
	// Authorization string     `help:"The authorization token to use to access an i2goSignals server"`
}

type CLI struct {
	Globals
	Add      AddCmd      `cmd:"" help:"Define a new server to be managed"`
	Create   CreateCmd   `cmd:"" help:"Create an issuer KEY, or STREAM."`
	Select   SelectCmd   `cmd:"" help:"Select a defined server or stream/server to perform operations against"`
	Get      GetCmd      `cmd:"" help:"Get information from SSF servers"`
	Generate GenerateCmd `cmd:"" help:"Generate an event for testing"`
	Poll     PollCmd     `cmd:"" help:"Activate a polling client stream with a server identified by <alias>."`
	Set      SetCmd      `cmd:"" help:"Set configuration items on server"`
	Show     ShowCmd     `cmd:"" help:"Show locally configured information"`
	Exit     ExitCmd     `cmd:"" help:"Exit the shell"`
	Help     HelpCmd     `cmd:"" help:"Show help on a command"`
	List     ListCmd     `cmd:"" help:"List all streams or one or more specific streams"`
	Version  VersionCmd  `cmd:"" short:"v" help:"Show the goSignals client version information"`
}

var SessionGlobals Globals

func main() {

	configNotLoaded := true

	cli := &CLI{}

	cli.Data = ConfigData{
		Servers: map[string]SsfServer{},
	}

	parser, err := kong.New(cli,
		kong.Name("goSignals"),
		kong.Description("i2goSignals client administration tool"),
		kong.ConfigureHelp(kong.HelpOptions{
			Compact:      true,
			Summary:      true,
			Tree:         true,
			NoAppSummary: false,
		}),
		kong.UsageOnError(),
		kong.Writers(os.Stdout, os.Stdout),

		kong.NoDefaultHelp(),
		kong.Bind(&cli.Globals),
		kong.Exit(func(int) {}),
	)

	// ctx.FatalIfErrorf(err)
	if err != nil {
		fmt.Println(err.Error())
	}
	oneCommand := false
	var initialArgs []string
	if len(os.Args) > 1 {
		initialArgs = os.Args[1:]
		oneCommand = true
	}

	for true {
		var args []string
		if len(initialArgs) > 0 {
			args = initialArgs
			initialArgs = []string{}
		} else {
			fmt.Print("goSignals> ")
			reader := bufio.NewReader(os.Stdin)
			line, _ := reader.ReadString('\n')
			line = line[0 : len(line)-1]
			args = strings.Split(line, " ")
		}

		var ctx *kong.Context
		ctx, err = parser.Parse(args)
		// ctx.Bind(&cli.Globals)
		// ctx.Bind(args)
		if configNotLoaded {
			_ = cli.Data.Load(&cli.Globals)
			configNotLoaded = false
		}
		if err != nil {

			parser.Errorf("%s", err.Error())
			if err, ok := err.(*kong.ParseError); ok {
				log.Println(err.Error())
				_ = err.Context.PrintUsage(false)
			}
			continue
		}

		err = ctx.Run(&cli.Globals)

		if err != nil {
			parser.Errorf("%s", err)
			continue
		}
		if oneCommand {
			return
		}
	}

}
