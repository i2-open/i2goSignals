#!/bin/bash

echo "Building command tool"
go build ./cmd/goSignals
go install ./cmd/goSignals

export GOSIGNALS_HOME=/scim/config.json
echo "Attempting to obtain IAT tokens from goSignals"
goSignals </scim/auto-reg.gosignals