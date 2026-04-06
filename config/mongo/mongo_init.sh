#!/bin/bash
echo "sleeping for 15 seconds"
sleep 15
echo mongo_init.sh time now: `date +"%T" `

# Wait for certificates to be available from the helper
until [ -f /certs/mongo.pem ]; do
  echo "Waiting for /certs/mongo.pem..."
  sleep 2
done

# Initialize replica set using TLS
mongosh --tls --tlsCAFile /certs/ca.pem --tlsCertificateKeyFile /certs/mongo.pem -u root -p dockTest --host mongo1:30001 <<EOF
  var cfg = {
    "_id": "dbrs",
    "version": 1,
    "members": [
      {
        "_id": 0,
        "host": "mongo1:30001"
      },
      {
        "_id": 1,
        "host": "mongo2:30002"
      },
      {
        "_id": 2,
        "host": "mongo3:30003"
      }
    ]
  };
  rs.initiate(cfg,{ force: true });
  
  // Wait for primary to be elected
  while (!rs.isMaster().ismaster) {
    print("Waiting for primary...");
    sleep(2000);
  }

  // Create SPIFFE user for goSignals workload
  // Note: The username must match the Subject of the X.509-SVID certificate
  db.getSiblingDB("\$external").runCommand(
    {
      createUser: "CN=spiffe://cluster.i2gosignals.internal/workload/gosignals-node",
      roles: [
           { role: "readWrite", db: "goSignals1" },
           { role: "readWrite", db: "goSignals2" },
           { role: "dbAdmin", db: "goSignals1" },
           { role: "dbAdmin", db: "goSignals2" }
      ],
      writeConcern: { w: "majority" }
    }
  );
  
  rs.status();
EOF