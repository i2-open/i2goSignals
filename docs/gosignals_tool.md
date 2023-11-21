# GoSignals Administration Tool

i2goSignals includes a command-line administration tool called `goSignals` which can be used to administer and configure
streams on an i2goSignals server or an SSF compliant server. 

The following table lists currently available commands in the goSignals tool.  Note that commands marked "works with SSF Servers" indicates commands that should work with an SSF compliant server.

| Command                                        | Works with<BR>SSF Servers | Description                                                                                                                    |
|------------------------------------------------|---------------------------|--------------------------------------------------------------------------------------------------------------------------------|
| <BR>**Defining Servers**                       |                           | <BR>Commands which are used to define i2goSignals and SSF servers to be administered                                           |
| [add server](#adding-a-server)                 | Yes                       | Add an SSF or i2goSignals server to be administered. Calls and queries the SSF well-known endpoint and generates a local alias |
| show server                                    | Yes                       | Shows a currently defined server and any known associated streams                                                              |
| <BR>**Key and Token Management**               |                           | <BR>Generating and obtaining signing keys and initial access tokens                                                            |
| create key                                     | No                        | Generate a key pair which can be used by a transmitter. i2goSignals provides a JWKS_URL endpoint for the public key            |
| get key                                        | N/A                       | Returns a public key from a specified URL or i2goSignals server                                                                |
| create iat                                     | No                        | Issues a new initial access token (IAT) which can be used to create streams within an identified project                       |
| <BR>**Stream Management**                      |                           | <BR>Creating and managing streams                                                                                              |
| [create stream](#creating-streams)             |                           |                                                                                                                                |
| create stream push publisher                   | Yes                       | Configures a transmission stream on i2goSignals using RFC8935 (HTTP SET Push)                                                  |
| create stream push receiver                    | No                        | Configure i2goSignals to receive events from a transmitter using RFC8935 (HTTP Set Push)                                       |
| create stream poll publisher                   | Yes                       | Create a transmission stream on i2goSignals server which can be polled by a receiver using RFC8936                             |
| create stream poll receiver                    | No                        | Enable i2goSignals to receive events using RFC8936 HTTP SET Polling                                                            |
| delete stream                                  | Yes                       | Deletes a specified stream                                                                                                     |
| [set stream config](#setting-stream-config)    | Yes                       | Updates the configuration of an identified stream                                                                              |
| [get stream config](#get-stream-configuration) | Yes                       | Returns the current stream configuration for a specified stream identifier                                                     |
| get stream status                              | Yes                       | Returns the current status for a specified stream identifier                                                                   |
| set stream status                              | Yes                       | Updates the status (e.g. disable) of an identified stream                                                                      |
| <BR>**Utilities**                              |                           | <BR>Testing and integration utilities                                                                                          | 
| poll                                           | Yes                       | Actively polls an SSF Polling endpoint for events. Runs a single or continuous poll to stdout or file                          |
| generate                                       | No                        | Generates one or more SCIM events which can be sent to a configured i2goSignals receiver stream                                |
| <BR>**goSignals Tool**                         |
| help                                           | n/a                       | Provides help on goSignals commands                                                                                            |
| exit                                           | n/a                       | Exit the goSignals utility                                                                                                     |                       

## Starting goSignals Admin Tool

GoSignals tool may be run in the goSignals shell by simply executing goSignals  without parameters, or a command can be provided in addition to the tool name.

```shell
goSignals
goSignals> add server go1 http://go ...
```

or 
```shell
gosignals add server go1 http://goSignals1.example.com:8888 --iat=eyJhbGciOiJSUzI1...p9aw6935efcgEKmA
```
> [!NOTE]
> When starting `goSignals`, the tool will attempt to load and store session information from `~/.goSignals/config.json`. To override this use the --config option or set the environment
> variable `GOSIGNALS_HOME`.

------------
# GoSignals Commands

## Adding A Server

Adding a server allows the configuration tool to contact and load SSF server information from a running server. The information gathered is used in subsequent requests such as stream management. Loaded
information is stored in the local session store.

> ```
> Arguments:
> <alias>   A unique name to identify the server
> <host>    Http URL for a goSignals server
> Flags:
> --server-url=STRING          The URL of an i2goServer or use an environment variable GOSIGNALS_URL ($GOSIGNALS_URL)
> -o, --output=STRING          To redirect output to a file
> -a, --append-output          When true, output to file (--output) will be appended
> 
>       --desc=STRING          Description of project
>       --email=STRING         Contact email for project
>       --iat=STRING           Registration Initial Access Auth if provided
>       --token=STRING         Administration authorization token
> ```

Example:
```shell
goSignals> add server go1 http://goSignals1:8888 --iat=eyJhbGciOiJSUzI1...p9aw6935efcgEKmA
```

If successful the response will be similar to:
```
ServerUrl configured:
{
  "Alias": "go1",
  "Host": "http://gosignals1:8888",
  "ClientToken": "eyJhbGciOiJ...eaa59gJ1VPKg",
  "IatToken": "eyJhbGciOiJSUzI1...p9aw6935efcgEKmA",
  "ProjectId": "",
  ...<<snip>>...
  "ServerConfiguration": {
    "issuer": "DEFAULT",
    "jwks_uri": "http://goSignals1:8888/jwks.json",
    "delivery_methods_supported": [
      "urn:ietf:rfc:8936",
      "urn:ietf:rfc:8935",
      "urn:ietf:rfc:8936:receive",
      "urn:ietf:rfc:8935:receive"
    ],
    "configuration_endpoint": "http://goSignals1:8888/stream",
    "status_endpoint": "http://goSignals1:8888/status",
    "add_subject_endpoint": "http://goSignals1:8888/add-subject",
    "remove_subject_endpoint": "http://goSignals1:8888/remove-subject",
    "verification_endpoint": "http://goSignals1:8888/verification",
    "supported_scopes": {
      "add_subject_endpoint": [
        "stream"
      ],
      "client_registration_endpoint": [
        "reg"
      ],
      "configuration_endpoint": [
        "admin",
        "stream"
      ],
     ...<<snip>>...
    },
    "client_registration_endpoint": "http://goSignals1:8888/registration"
  }
}
```

### What Add Server Does

`add Server` connects with server URL provided and interrogates the `/.well-known/ssf-configuration` data to determine
endpoints and capabilities. In the case of **i2goSignals** servers, the command will register the **gosignals** as a
an administrative client enabling management of streams.

When a request is made with an alias and URL (e.g. `add server goserver1 http://gosignals1.example.com`), the **gosignals**  
administration tool connects to the SSF or i2goSignals server and retrieves the `/.well-known/ssf-configuration` information. 

If neither `--iat` nor `--token` parameters are provided, the goSignals tool will attempt to obtain an Initial Access Token from
the server at the endpoint `/iat` (for i2goSignals servers only). 

> [!Note]
> For SSF servers, you would need to obtain a token
> from the SSF server's token provider and provide it with the `--token` parameter.

If the `--iat` parameter is provided, the **gosignals** tool will use that token to attempt to register to obtain a client token using 
the endpoint identified in the server configuration as `client_registration_endpoint` (e.g. `/registration`). In response
i2goSignals server will return an administration token (client authorization token) to be used in subsequent requests.

> [!Note]
> While an IAT is not needed, IATs may be used to bootstrap multiple servers in a project to obtain unique client tokens. 
> Each client then registers to obtain a unique client token. For example, in an i2scim.io cluster, servers are configured
> with the same IAT. As each node is started, the node will auto-register to obtain its own client token. This allows each
> node to have their own outbound and inbound streams. The administrative client that issued the IAT will also have the
> ability to manage any streams created by the cluster nodes.

If the `--token` parameter is provided, the admin client will just query the SSF configuration data and return the response.
The token parameter is typically used with SSF servers where the authorization token is retrieved by some means defined by
the SSF service provider.

When registering with an i2goSignals server, the `--desc` and `--email` parameters can be used to provide additional contact or use data.

## Show Server

The `show server` command is used to show the configuration and streams for a previously added server. The command has one
parameter which is the server alias.

For example:
`show server go1`

Returns something like:
```
{
  "Alias": "go1",
  "Host": "http://gosignals1:8888",
  "ClientToken": "eyJhbGciOiJSUzI1NiIsImtpZCI...a59gJ1VPKg",
  "IatToken": "eyJhbGciOiJSUzI1NiIsImtpZCI6Ik...FnAaIuO3nQ",
  "ProjectId" : "6525f6d786b",
  "Streams": {
    "BPo": {
      "alias": "BPo",
      "id": "6525f6d786b849e69ca1a77f",
      "description": "Poll Publisher",
      "token": "Bearer eyJhbGciOiJSUzI1NiIsIm...nb8SGpBgMdg",
      "endpoint": "http://goSignals1:8888/poll/6525f6d786b849e69ca1a77f",
      "iss": "cluster.scim.example.com",
      "aud": "cluster.example.com",
      "issJwksUrl": "http://goSignals1:8888/jwks/cluster.scim.example.com"
    },
    "rMy": {
      "alias": "rMy",
      "id": "6525f6a386b849e69ca1a77d",
      "description": "Poll Publisher",
      "token": "Bearer eyJhbGciOiJSUzI1NiIsImt...0Xgh4mrxIW2tvQ",
      "endpoint": "http://goSignals1:8888/poll/6525f6a386b849e69ca1a77d",
      "iss": "cluster.scim.example.com",
      "aud": "cluster.example.com",
      "issJwksUrl": "http://goSignals1:8888/jwks/cluster.scim.example.com"
    },
    "sQs": {
      "alias": "sQs",
      "id": "6525f54e86b849e69ca1a779",
      "description": "Push Receiver",
      "token": "Bearer eyJhbGciOiJSUzI1NiIsIm...1BcnxBULhAj3gA",
      "endpoint": "http://goSignals1:8888/events/6525f54e86b849e69ca1a779",
      "iss": "cluster.scim.example.com",
      "aud": "cluster.example.com,monitor.example.com,partner.scim.example.com",
      "issJwksUrl": ""
    }
  },
  "ServerConfiguration": {
    "issuer": "DEFAULT",
    "jwks_uri": "http://goSignals1:8888/jwks.json",
    "delivery_methods_supported": [
      "urn:ietf:rfc:8936",
      "urn:ietf:rfc:8935",
      "urn:ietf:rfc:8936:receive",
      "urn:ietf:rfc:8935:receive"
    ],
    "configuration_endpoint": "http://goSignals1:8888/stream",
    "status_endpoint": "http://goSignals1:8888/status",
    "add_subject_endpoint": "http://goSignals1:8888/add-subject",
    "remove_subject_endpoint": "http://goSignals1:8888/remove-subject",
    "verification_endpoint": "http://goSignals1:8888/verification",
    "supported_scopes": {
      "add_subject_endpoint": [
        "stream"
      ],
      "client_registration_endpoint": [
        "reg"
      ],
      "configuration_endpoint": [
        "admin",
        "stream"
      ],
      "events": [
        "event"
      ],
      "poll": [
        "event"
      ],
      "remove_subject_endpoint": [
        "stream"
      ],
      "status_endpoint": [
        "stream"
      ],
      "verification_endpoint": [
        "event",
        "stream"
      ]
    },
    "client_registration_endpoint": "http://goSignals1:8888/registration"
  }
}
```

In the above JSON structure, the `Streams` object holds the current set of known streams. Note this currently does not
include streams created by other means.  `ServerConfiguration` contains the SSF Configuration returned by the server.

> [!Caution]
> The information returned in many responses includes access tokens that should be kept confidential. They are persisted
> in the goSignals tool configuration file (typically `~/.goSignals/config.json`).

## Creating Streams

> ```
> Create a stream on a specified server.
> 
> Flags:
> --config=STRING       Location of client config files ($GOSIGNALS_HOME)
> --server-url=STRING   The URL of an i2goServer or use an environment variable GOSIGNALS_URL ($GOSIGNALS_URL)
> -o, --output=STRING   To redirect output to a file
> -a, --append-output   When true, output to file (--output) will be appended
> 
>     --aud=AUD,...     One or more audience values separated by commas
>     --iss=STRING      The event issuer value (e.g. scim.example.com)
> -n, --name=STRING     An alias name for the stream to be created
> --iss-jwks-url=STRING The issuer JwksUrl value. Used for SET Event token validation.
> --events=*,...        The event uris (types) requested for a stream. Use '*' to match by wildcard.
> 
> Commands:
> push                  Create a SET PUSH Stream (RFC8935)
>   receive | publish     Create PUSH Receiver|Publisher stream
>     <alias>               The alias of the server to create the stream on (default is selected server)
>   connection (c)        Create a push stream connection between servers
>     <source-alias>        The alias of the publishing server.
>     <dest-alias>          The alias of receiving server or existing stream alias.
> 
> poll                  Create a SET Polling Stream (RFC8936)
>   receive | punlidsh    Create a POLLING Receiver|Publisher stream
>     <alias>               The alias of the server to create the stream on (default is selected server)
>   connection (c)        Create a polling stream connection between servers
>     <source-alias>    The alias of the publishing server or existing stream alias.
>     <dest-alias>      The alias of receiving server.
> ```

Parameters Used to Create Streams:

| Parameter         | Description                                                                                                                                  | Default                                          |
|-------------------|----------------------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------|
| `--name`, `-n`    | Optional local alias name for the stream created.                                                                                            | generated value                                  |
| `--aud`           | A string containing one or more audience values separated by comma (e.g. `aud.example.com`)                                                  | none                                             |
| `--iss`           | A string containing the issuer (e.g. `iss.example.com`). Note value usually corresponds to the key id (`kid`) for the signing key for events | none                                             |
| `--iss-jwks-url`  | A url for the public key for signed events                                                                                                   | none                                             |
| `--events`        | A comma separated list of event URIs that are being requested. Note: i2goSignals servers accepts `*` as a wildcard to select multiple events | *                                                |
| `--mode`          | For i2goSignals servers mode informs the server what it does with events.  See below.                                                        | `IMPORT` for receiver<BR>`PUBLISH` for publisher |
| `--event-url`     | Used to tell Push Publishers where to deliver events using RFC8935. For Poll receivers, indicates where to retrieve events using RFC8936     | none                                             |
| `--auth`          | The authorization header value to use when communicating with a polling or push endpoint (i.e. `--event-url`)                                | none                                             |
| `--connect`, `-c` | Partially automates stream creation by providing the local alias for the stream being connected to.                                          | none                                             |      

> [!Tip]
> For more information on the meaning of terms like iss, aud, and event URIs, see the [JWT Specification](https://datatracker.ietf.org/doc/html/rfc7519), 
> and the [Security Event Token Specification](https://datatracker.ietf.org/doc/html/rfc8417). 


#### Stream Event Handling Modes

In order to move events received by an i2goSignal receiver stream to an outbound publisher stream, the following `mode` values are defined for a receiver or transmitter stream. 

For a _publisher_ stream, the supported `--mode` values are:
`PUBLISH` or `P` (default)
 : Events routed to this transmitter (e.g. due to a match in audience and issuer) are signed and delivered to the identified receiver.

`FORWARD` or `F`
 : Events are forwarded as received to the specified receiver. This may be because the server is forwarding an already signed event.

For a _receiver_ stream, the supported `--mode` values are:
`IMPORT` or `I` (default) 
: Received events are stored in the database and no further action is taken. This may be because the event will be picked up directly from the database.

`FORWARD` or `F` 
: The event is to be forwarding to one or more matching outbound publisher streams. Forwarding indicates the received event is to be sent as-is.

`PUBLISH` or `P` 
: The same as `FORWARD`, except that events will be re-signed by the server (e.g. an internally signed event needs to be signed with an externally visible key)

### What Create Stream Does
The `create stream` command is used to create either a _publisher_ or _receiver_ stream on an i2goSignals server; or, a _publisher_ stream on an SSF server. A
stream consists of a number of configuration settings which determines what event types may flow, to where, and how.  When there are multiple streams, each stream has its
own set of events that are delivered. For example, if 2 streams are configured to receive the same set of events, than each stream will receive its own copy.

As an example, we have a transmitter that supports RFC8935 which is SET Transfer Using HTTP Push. The transmitter needs a receiver to receive the events (e.g. for forwarding to multiple
receivers). In this case, the following command is issued:

```shell
gosignals create stream push receive go1 \n
  --mode=FORWARD \n
  --aud=cluster.example.com,monitor.example.com,partner.scim.example.com \n 
  --iss=cluster.scim.example.com \n
  --events=* \n
  --iss-jwks-url=http://goSignals1:8888/jwks/cluster.scim.example.com
```

When entered, the goSignals tool will display the request it is about to send and will ask: `Proceed Y|[n]?`

When the request is successful, the tool will respond with the following which summarizes the configured stream. The information
provided is intended for a Transmitter to be manually configured, or, semi-automatically by providing the output to the server (such as with i2scim.io).

```json
{
 "alias": "sQs",
 "id": "6525f54e86b849e69ca1a779",
 "description": "Push Receiver",
 "token": "Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6IkRFRkFVTFQiLCJ0eXAiOiJqd3QifQ.eyJzaWQiOlsiNjUyNWY1NGU4NmI4NDllNjljYTFhNzc5Il0sInByb2plY3RfaWQiOiJBa0NVIiwicm9sZXMiOlsiZXZlbnQiXSwiaXNzIjoiREVGQVVMVCIsImF1ZCI6WyJERUZBVUxUIl0sImV4cCI6MTcwNDc2MjQ0NiwiaWF0IjoxNjk2OTg2NDQ2LCJqdGkiOiIyV2IxUUNoNTBjc2RBVUIyTFZtOTlnYzFYazMifQ.Tk5M7yn64kkfxr_ds9CJXMcifvefxxftq4e_gX9-KZzViUyd1SBNofz-_Dfzh5zIMsl0XBiLXLRofQU_yhsh_yGKGz6_9TlOzmwA3tNclJEeaCySOvtyUZ39D773u60Ss3ydXvTUtai8WE5PV5Qmu3wvyTSiABrTIbTv260MOLuk1hisPYQmpNE06BMCv3LIeBaMggZrJKJRTkCmgxHlgdVUh4BAPRlqiKG0jiCED1z6PHsMUaocT_1gVQEuchRdGgZTRBglMCAVSQibBLqOA6d1BrLGVGUKOMtJNj4tb59TrKpM--QCqAksNM02Kj1nOiiac7tR1BcnxBULhAj3gA",
 "endpoint": "http://goSignals1:8888/events/6525f54e86b849e69ca1a779",
 "iss": "cluster.scim.example.com",
 "aud": "cluster.example.com,monitor.example.com,partner.scim.example.com",
 "issJwksUrl": ""
}
```

In the above JSON structure, a unique local alias `sQs` is assigned. This can be used in goSignals commands to update and retrieve the current stream configuration.

## Get Stream Configuration

To retrieve the current stream configuration from an SSF or i2goSignals server, use the `get stream config` command. 

> [!Note]
> In the current implementation, the stream must have a local alias (i.e. was created by the create stream command). At this
> time, SSF does not have a way to list available streams. This will be added in a future update.

```shell
gosignals get stream config sQs
```
For which the response is:
```
Stream configuration for: sQs
{
  "stream_id": "6525f54e86b849e69ca1a779",
  "iss": "cluster.scim.example.com",
  "aud": [
    "cluster.example.com",
    "monitor.example.com",
    "partner.scim.example.com"
  ],
  "events_supported": [
    "urn:ietf:params:SCIM:event:feed:add",
    "urn:ietf:params:SCIM:event:feed:remove",
    "urn:ietf:params:SCIM:event:prov:create:full",
    "urn:ietf:params:SCIM:event:prov:put:full",
    "urn:ietf:params:SCIM:event:prov:patch:full",
    "urn:ietf:params:SCIM:event:prov:create:notice",
    "urn:ietf:params:SCIM:event:prov:patch:notice",
    "urn:ietf:params:SCIM:event:prov:put:notice",
    "urn:ietf:params:SCIM:event:prov:delete",
    "urn:ietf:params:SCIM:event:prov:activate",
    "urn:ietf:params:SCIM:event:prov:deactivate",
    "urn:ietf:params:SCIM:event:sig:authMethod",
    "urn:ietf:params:SCIM:event:sig:pwdReset",
    "urn:ietf:params:SCIM:event:misc:asyncResp"
  ],
  "events_requested": [
    "*"
  ],
  "events_delivered": [
    "urn:ietf:params:SCIM:event:feed:add",
    "urn:ietf:params:SCIM:event:feed:remove",
    "urn:ietf:params:SCIM:event:prov:create:full",
    "urn:ietf:params:SCIM:event:prov:put:full",
    "urn:ietf:params:SCIM:event:prov:patch:full",
    "urn:ietf:params:SCIM:event:prov:create:notice",
    "urn:ietf:params:SCIM:event:prov:patch:notice",
    "urn:ietf:params:SCIM:event:prov:put:notice",
    "urn:ietf:params:SCIM:event:prov:delete",
    "urn:ietf:params:SCIM:event:prov:activate",
    "urn:ietf:params:SCIM:event:prov:deactivate",
    "urn:ietf:params:SCIM:event:sig:authMethod",
    "urn:ietf:params:SCIM:event:sig:pwdReset",
    "urn:ietf:params:SCIM:event:misc:asyncResp"
  ],
  "delivery": {
    "method": "urn:ietf:rfc:8935:receive",
    "endpoint_url": "http://goSignals1:8888/events/6525f54e86b849e69ca1a779",
    "authorization_header": "Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6IkRFRkFVTFQiLCJ0eXAiOiJqd3QifQ.eyJzaWQiOlsiNjUyNWY1NGU4NmI4NDllNjljYTFhNzc5Il0sInByb2plY3RfaWQiOiJBa0NVIiwicm9sZXMiOlsiZXZlbnQiXSwiaXNzIjoiREVGQVVMVCIsImF1ZCI6WyJERUZBVUxUIl0sImV4cCI6MTcwNDc2MjQ0NiwiaWF0IjoxNjk2OTg2NDQ2LCJqdGkiOiIyV2IxUUNoNTBjc2RBVUIyTFZtOTlnYzFYazMifQ.Tk5M7yn64kkfxr_ds9CJXMcifvefxxftq4e_gX9-KZzViUyd1SBNofz-_Dfzh5zIMsl0XBiLXLRofQU_yhsh_yGKGz6_9TlOzmwA3tNclJEeaCySOvtyUZ39D773u60Ss3ydXvTUtai8WE5PV5Qmu3wvyTSiABrTIbTv260MOLuk1hisPYQmpNE06BMCv3LIeBaMggZrJKJRTkCmgxHlgdVUh4BAPRlqiKG0jiCED1z6PHsMUaocT_1gVQEuchRdGgZTRBglMCAVSQibBLqOA6d1BrLGVGUKOMtJNj4tb59TrKpM--QCqAksNM02Kj1nOiiac7tR1BcnxBULhAj3gA"
  },
  "min_verification_interval": 15,
  "format": "opaque",
  "issuerJWKSUrl": "http://goSignals1:8888/jwks/cluster.scim.example.com",
  "route_mode": "FW"
}
```

## Setting Stream Config

> ```
> Modify stream configuration
>
> Arguments:
> [<alias>]    Alias of stream to be modified.
>
> Flags:
>
> -e, --events=EVENTS,...        Comma separated list of events to request. Or use +/- for delta to add or remove events
> -r, --r-jwks-url=STRING        Set the receiver JWKS url
> -i, --i-jwks-url=STRING        Set the issuer JWKS url
> -j, --reset-jti=STRING         Reset the stream to a particular JTI (and include all following events)
> -d, --reset-date=RESET-DATE    Reset stream to a specific date in RFC3339 format (e.g. 1985-04-12T23:20:50.52Z)
> -f, --format=STRING            The sub_id type supported in the form of <format>:[<attr1>,<attr2>] - NOT CURRENTLY IMPLEMENTED
> ```

The `events` parameter provides the ability to change the `events_requested` for the stream. For i2goSignals servers, a `+`
means add an event while keeping the others, while "-" means remove the specified events. Otherwise, if + or - is not
used, the specified events replaces all existing events configured.  Note that an SSF service provider is not obliged
to issue all requested events. This will be shown in the `events_delivered` value in the stream configuration.

i2goSignal streams also support a reset feature that allows streams to be reset to a specified date (`reset-date`) or
a specified `jti` value. Once set, the server will look in its database and attempt to provide all events eligible for
the stream as of the specified date or jti value.

When the update is accepted, goSignals will show the updated configuration provided by the SSF or i2goSignals server.




