# GoSignals Security Model

## Shared Signals Framework and GoSignals
The current model is based on the OpenID SSF specification which essentially enables clients to register to receive events. 
The client may be given an Initial Access Token (IAT) which permits the registration, when successful, the client receives
a permanent token which it uses to pick up events, and/or to manage its stream.  Of particualr note, the SSF endpoints
use a common endpoint which no direct stream identifier.  The stream identifier is usually encoded in the access token.

## GoSignals Command Line 
At present, GoSignals only has a command line utility.  It accepts IATs, but if not, it will try to get an IAT.  From
the goSignalsServer perspective, each IAT starts a new project under which one or more streams can be created. 

```shell
goSignals> add server go1 http://localhost:8888
```

To start the process the gosignals command `add server` command is used with the optional parameter --iat which is used to specify a
previously issued access token.  The command line utility will register the client with the goSignals server and in return
will receive an administrative access token.  The command line utility will store the server and token information in 
its local configuration file. If an alias is specified, that alias can be used to refer to the server in the future.  If
an alias is not specified, an alias is automatically generated.

## Docker Compose Set Up

In the demo scenario, there are 2 SCIM servers configured to run as replicas with synchronization being carried out via
goSignals. In the scenario, both SCIM servers in the cluster use goSignals1:8888 as the common events server. 
This is so that when one server issues an event, the replica SCIM server can receive it and synchronize.

In order for the SCIM servers to auto-register, they need an IAT token.  To do this, the service `scimSsfSetup` runs the
goSignals command line utility and does the following goSignals commands:
```shell
add server gosignals1 http://goSignals1:8888
add server gosignals2 http://goSignals2:8889
create iat gosignals1 --output=/scim/iat1.txt
create iat gosignals2 --output=/scim/iat2.txt
exit
```

When complete, the shell script takes iat1.txt and creates the file registration-iat.env which is picked up by services
`scim_cluster1` and `scim_cluster2`.  When these services start they will auto-register with goSignals1.

## Limitations

The current goSignals command line only knows about streams that is has configured to facilitate a demo. 
At present the `show server` command only shows the locally known information and streams.  For example, you might chose to 
create a push receiver on goSignals2 and a push publisher on goSignals1 using the `create push connection` command. If you specify
the same audience as the SCIM cluster, you fill find that goSignals1 starts automatically forwarding events to goSignals2.
You can monitor the events by creating a poll publisher on goSignals2 and then using the poll command to display incoming events
to the command line utility.

## Admin UI Issues

The current command line stores local state and tokens in a local configuration file. The use of tokens for stream management 
is influenced by the SSF specification itself.  When building the admin UI, we need to implement more traditional access control
and API design so we can do things like list all streams.