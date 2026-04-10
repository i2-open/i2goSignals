
if [ -s /scim/registration-iat.env ]; then
    echo "Registration IAT file already exists, skipping token generation"
    exit 0
fi

echo "Generating IAT tokens"
echo ""

export GOSIGNALS_HOME=/scim/config.json
# Use go run to ensure we're using the latest source code in the dev environment.
# This avoids issues with host-built binaries (e.g. Darwin vs Linux).
go run /app/cmd/goSignals </scim/scripts/auto-reg.gosignals
if [ ! -f "/scim/iat1.txt" ]; then
        echo "Error: IAT and Key Generation failed."
        exit 1
fi

echo ""
echo "Creating .env file for SCIM servers"

cp /scim/scripts/scim-template.env /scim/scim_cluster.env
echo "scim.signals.ssf.authorization=BEARER $(cat /scim/iat1.txt)" >>/scim/scim_cluster.env

echo ""

if [ -f "/scim/spire-bundle.pem" ]; then
    echo "Configuring for SPIFFE cert bundle"
    cp /scim/spire-bundle.pem /scim/ca-bundle.pem
    if [ -f "$CA_CERT" ]; then
        cat "$CA_CERT" >> /scim/ca-bundle.pem
    fi
    cp /scim/ca-bundle.pem /scim/data1
    cp /scim/ca-bundle.pem /scim/data2
    echo "scim.signals.ssf.trust.certs.path=/scim/ca-bundle.pem" >>/scim/scim_cluster.env
elif [ -f "$CA_CERT" ]; then
    echo "Configuring CA cert bundle"
    cp "$CA_CERT" /scim/ca-bundle.pem
    cp /scim/ca-bundle.pem /scim/data1
    cp /scim/ca-bundle.pem /scim/data2
    echo "scim.signals.ssf.trust.certs.path=/scim/ca-bundle.pem" >>/scim/scim_cluster.env
fi

echo ""
echo "Moving issuer key to each server"

if [ -s /scim/cluster-scim-issuer.pem ]; then
  cp -f /scim/cluster-scim-issuer.pem /scim/data1
  cp -f /scim/cluster-scim-issuer.pem /scim/data2
else
  echo " ERROR: no issuer key was generated."
  exit 1
fi

echo "Installation completed."

