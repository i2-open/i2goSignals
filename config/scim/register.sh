
if [ -s /scim/registration-iat.env ]; then
    echo "Registration IAT file already exists, skipping token generation"
    exit 0
fi

echo "Generating IAT tokens"
echo ""

export GOSIGNALS_HOME=/scim/config.json
/app/goSignals </scim/auto-reg.gosignals
if [[ ! -f "/scim/iat1.txt" ]]; then
        echo "Error: IAT Generation failed."
        exit 1
        # Handle the error, e.g., exit or log
fi

echo ""
echo "Creating .env file for SCIM servers"
echo "export scim.signals.ssf.authorization=BEARER $(cat /scim/iat1.txt)" >/scim/registration-iat.env