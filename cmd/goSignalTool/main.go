package main

import (
	"flag"
)

var receiverSSF string
var publisherSSF string
var command string
var sid string

func main() {
	flag.StringVar(&receiverSSF, "receiver", "localhost:8881", "The url of a goSignals server acting as receiver")
	flag.StringVar(&publisherSSF, "publisher", "localhost:8880", "The URL of the event publisher")
	flag.StringVar(&command, "command", "reg", "A command: [reg|status|pause|stop|start|update]")
	flag.StringVar(&command, "cmd", "reg", "A command: [reg|status|pause|stop|start|update]")
	flag.StringVar(&sid, "sid", "", "A stream identifier to manage (required for STOP|PAUSE|START|UPDATE")
	flag.Parse()
	flag.Arg(1)
}
