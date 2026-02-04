# goSSFserver

This is a Go implementation of the SSF server, designed to facilitate secure and efficient data exchange between different systems.

This server is intended to:
* Be used for SSF inter-operability testing
* Used as an SSF implementation for those generators who can drop events into Mongo
* Used as a test generator of events

This server does not implement extended functionality (e.g. receivers) available in the goSignals.server package.