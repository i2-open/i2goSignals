Demonstration steps

Start gosignals tool

add server go1 localhost:/8888
add server go2 localhost:/8889
create key go1 cluster.scim.example.com --file=config/cluster-scim-example-com.pem

copy pem file to i2scim directory

Create feed to allow SCIM to publish to go1
create stream receive push go1 --mode=FORWARD --aud=cluster.example.com,monitor.example.com,partner.scim.example.com --iss=cluster.scim.example.com --events=* --iss-jwks-url=http://goSignals1:8888/jwks/cluster.scim.example.com
Copy output to pubStream.json

Create feed to allow SCIM1 to receive from go1
create stream publish poll go1 --aud=cluster.example.com --iss=cluster.scim.example.com --events=* --iss-jwks-url=http://goSignals1:8888/jwks/cluster.scim.example.com
Create feed to allow SCIM2 to receive from go1
create stream publish poll go1 --aud=cluster.example.com --iss=cluster.scim.example.com --events=* --iss-jwks-url=http://goSignals1:8888/jwks/cluster.scim.example.com
Copy output to receiveStream.json

Now connect the two gosignals server
create stream receive push go2 --mode=FORWARD --aud=partner.scim.example.com,monitor.example.com --iss=cluster.scim.example.com --events=* --iss-jwks-url=http://goSignals1:8888/jwks/cluster.scim.example.com
create stream publish push go1 --aud=partner.scim.example.com,monitor.example.com --iss=cluster.scim.example.com --events=* --dest-alias=go2.saF --iss-jwks-url=http://goSignals1:8888/jwks/cluster.scim.example.com

create stream publish poll go2 --aud=monitor.example.com --iss=cluster.scim.example.com --events=* --iss-jwks-url=http://goSignals1:8888/jwks/cluster.scim.example.com
