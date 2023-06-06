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
	Config        string `help:"Location of client config files" default:"~/.docker" type:"path"`
	Server        string `help:"The URL of an i2goServer or use an environment variable GOSIGNALS_URL" env:"GOSIGNALS_URL"`
	Authorization string `help:"The authorization token to use to access an i2goSignals server"`
	StreamToken   string `help:"A token used to manage a stream"`
}

type CLI struct {
	Globals
	Attach  AttachCmd      `cmd:"" help:"Attach local standard input, output, and error streams to a running container"`
	Create  CreateCmd      `cmd:"" help:"Create a PUBLISHER or RECEIVER stream."`
	Show    ShowCmd        `cmd:"" help:"Show configured values"`
	Exit    ExitCmd        `cmd:"" help:"Exit the shell"`
	Help    HelpCmd        `cmd:"" help:"Show help on a command"`
	List    ListStreamsCmd `cmd:"" help:"List all streams or one or more specific streams"`
	Version VersionCmd     `cmd:"" short:"v" help:"Show the goSignals client version information"`
}

var SessionGlobals Globals

func main() {

	cli := &CLI{}

	SessionGlobals = Globals{Server: "localhost:8888"}

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

	initialArgs := []string{}
	if len(os.Args) > 1 {
		initialArgs = os.Args[1:]
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
	}

}
