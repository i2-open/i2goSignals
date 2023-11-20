# GoSignals Administration Tool

i2goSignals includes a command-line administration tool called `goSignals` which can be used to administer and configure
streams on an i2goSignals server or an SSF compliant server. 

The following table lists currently available commands in the goSignals tool.  Note that commands marked "works with SSF Servers" indicates commands that should work with an SSF compliant server.

| Command                          | Works with<BR>SSF Servers | Description                                                                                                                   |
|----------------------------------|---------------------------|-------------------------------------------------------------------------------------------------------------------------------|
| <BR>**Defining Servers**         |                           | <BR>Commands which are used to define i2goSignals and SSF servers to be administered                                          |
| [add server](#adding-a-server)   | Yes                       | Add an SSF or i2goSignals server to be administered. Calls and queries the SSF well-known endpoint and generates a local alias |
| show server                      | Yes                       | Shows a currently defined server and any known associated streams                                                             |
| <BR>**Key and Token Management** |                           | <BR>Generating and obtaining signing keys and initial access tokens                                                           |
| create key                       | No                        | Generate a key pair which can be used by a transmitter. i2goSignals provides a JWKS_URL endpoint for the public key           |
| get key                          | N/A                       | Returns a public key from a specified URL or i2goSignals server                                                               |
| create iat                       | No                        | Issues a new initial access token (IAT) which can be used to create streams within an identified project                      |
| <BR>**Stream Management**        |                           | <BR>Creating and managing streams                                                                                             |
| create stream push publisher     | Yes                       | Configures a transmission stream on i2goSignals using RFC8935 (HTTP SET Push)                                                 |
| create stream push receiver      | No                        | Configure i2goSignals to receive events from a transmitter using RFC8935 (HTTP Set Push)                                      |
| create stream poll publisher     | Yes                       | Create a transmission stream on i2goSignals server which can be polled by a receiver using RFC8936                            |
| create stream poll receiver      | No                        | Enable i2goSignals to receive events using RFC8936 HTTP SET Polling                                                           |
| delete stream                    | Yes                       | Deletes a specified stream                                                                                                    |
| set stream config                | Yes                       | Updates the configuration of an identified stream                                                                             |
| get stream config                | Yes                       | Returns the current stream configuration for a specified stream identifier                                                    |
| get stream status                | Yes                       | Returns the current status for a specified stream identifier                                                                  |
| set stream status                | Yes                       | Updates the status (e.g. disable) of an identified stream                                                                     |
| <BR>**Utilities**                |                           | <BR>Testing and integration utilities                                                                                         | 
| poll                             | Yes                       | Actively polls an SSF Polling endpoint for events. Runs a single or continuous poll to stdout or file                         |
| generate                         | No                        | Generates one or more SCIM events which can be sent to a configured i2goSignals receiver stream                               |
| <BR>**goSignals Tool**           |
| help                             | n/a                       | Provides help on goSignals commands                                                                                           |
| exit                             | n/a                       | Exit the goSignals utility                                                                                                    |                       

## Installation

To install the server, clone the repository and enter the go install command as follows:

```shell
git clone https://github.com/i2-open/i2goSignals.git
cd i2goSignals
go install cmd/goSignals

goSignals
goSignals>
```

> [!NOTE]
> When starting `goSignals`, the tool will attempt to load and store session information from `~/.goSignals/config.json`. To override this use the --config option or set the environment
> variable `GOSIGNALS_HOME`.

------------
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

--------
## Creating Streams

> ```
> Create a stream on a specified server.
> 
> Flags:
> --config=STRING          Location of client config files ($GOSIGNALS_HOME)
> --server-url=STRING      The URL of an i2goServer or use an environment variable GOSIGNALS_URL ($GOSIGNALS_URL)
> -o, --output=STRING          To redirect output to a file
> -a, --append-output          When true, output to file (--output) will be appended
> 
>       --aud=AUD,...            One or more audience values separated by commas
>       --iss=STRING             The event issuer value (e.g. scim.example.com)
> -n, --name=STRING            An alias name for the stream to be created
> --iss-jwks-url=STRING    The issuer JwksUrl value. Used for SET Event token validation.
> --events=*,...           The event uris (types) requested for a stream. Use '*' to match by wildcard.
> 
> Commands:
> push                  Create a SET PUSH Stream (RFC8935)
> receive (r)         Create PUSH Receiver stream
> [<alias>]         The alias of the server to create the stream on (default is selected server)
> publish (p)         Create PUSH Publisher stream
> [<alias>]         The alias of the server to create the stream on (default is selected server)
> connection (c)      Create a push stream connection between servers
> <source-alias>    The alias of the publishing server.
> <dest-alias>      The alias of receiving server or existing stream alias.
> 
> poll                  Create a SET Polling Stream (RFC8936)
> receive             Create a POLLING Receiver stream
> [<alias>]         The alias of the server to create the stream on (default is selected server)
> publish             Create a POLLING Publisher stream
> [<alias>]         The alias of the server to create the stream on (default is selected server)
> connection (c)      Create a polling stream connection between servers
> <source-alias>    The alias of the publishing server or existing stream alias.
> <dest-alias>      The alias of receiving server.
> ```
