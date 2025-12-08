
if [ -s /scim/registration-iat.env ]; then
    echo "Registration IAT file already exists, skipping token generation"
    exit 0
fi

echo "Generating IAT tokens"
echo ""

export GOSIGNALS_HOME=/scim/config.json
/app/goSignals </scim/scripts/auto-reg.gosignals
if [[ ! -f "/scim/iat1.txt" ]]; then
        echo "Error: IAT and Key Generation failed."
        exit 1
        # Handle the error, e.g., exit or log
fi

echo ""
echo "Creating .env file for SCIM servers"

cp /scim/scripts/scim-template.env /scim/scim_cluster.env
echo "scim.signals.ssf.authorization=BEARER $(cat /scim/iat1.txt)" >>/scim/scim_cluster.env

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

