Demonstration steps

Start gosignalstool

```
add server go1 localhost:/8888
add server go2 localhost:/8889
create key go1 cluster.scim.example.com --file=config/cluster-scim-example-com.pem

copy config/cluster-scim-example-com.pem /config/scim/data1/issuer.pem
copy config/cluster-scim-example-com.pem /config/scim/data2/issuer.pem
```

Create feed to allow both SCIM servers to publish to go1 using a shared stream...

```
create stream push receive go1 --mode=FORWARD --aud=cluster.example.com,monitor.example.com,partner.scim.example.com --iss=cluster.scim.example.com --events=* --iss-jwks-url=http://goSignals1:8888/jwks/cluster.scim.example.com
```
Copy output to pubStream.json in each of /config/scim/data1 and /config/scim/data2

Now that the SCIM to goSignals stream has been created, the events need to be sent back to the other nodes for replication to take place. A
polling publisher stream is creating on goSignals to publish events back to each scim server.  Separate streams are used to ensure each server
sees all of the events.   Note: if the SCIM servers shared a common database, then only one stream would be needed for the cluster.

Create feed to allow SCIM1 to receive from go1
BPo rMy
```
create stream poll publish go1 --mode=FORWARD --aud=cluster.example.com --iss=cluster.scim.example.com --events=*:prov:*:full,*:prov:delete --iss-jwks-url=http://goSignals1:8888/jwks/cluster.scim.example.com
```
Copy output to receiveStream.json in /config/scim/data1

Create feed to allow SCIM2 to receive from go1
```
create stream poll publish go1 --mode=FORWARD --aud=cluster.example.com --iss=cluster.scim.example.com --events=*:prov:*:full,*:prov:delete --iss-jwks-url=http://goSignals1:8888/jwks/cluster.scim.example.com
```
Copy output to receiveStream.json in /config/scim/data2

Now connect the two gosignals servers to simulate sending events to another organization.

```
create stream push connection go1 go2 --mode=FORWARD --aud=partner.scim.example.com,monitor.example.com --iss=cluster.scim.example.com --events=* --iss-jwks-url=http://goSignals1:8888/jwks/cluster.scim.example.com
```

To simulate a receiver (monitor.example.com) on goSignals 2 receiving events, a poll publisher is set up that can receive events
```
create stream poll publish go2 --mode=F --aud=monitor.example.com --iss=cluster.scim.example.com --events=* --iss-jwks-url=http://goSignals1:8888/jwks/cluster.scim.example.com
```
