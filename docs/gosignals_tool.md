# GoSignals Administration Tool

i2goSignals includes a command-line administration tool called `goSignals` which can be used to administer and configure
streams on an i2goSignals server or an SSF compliant server. 

The following table lists currently available commands in the goSignals tool.  Note that commands marked "works with SSF Servers" indicates commands that should work with an SSF compliant server.

| Command                          | Works with<BR>SSF Servers | Description                                                                                                                   |
|----------------------------------|---------------------------|-------------------------------------------------------------------------------------------------------------------------------|
| <BR>**Defining Servers**         |                           | <BR>Commands which are used to define i2goSignals and SSF servers to be administered                                          |
| add server                       | Yes                       | Add an SSF or i2goSignals server to be administered. Calls and queries the SSF well-known endpoint and generates a local alias |
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


