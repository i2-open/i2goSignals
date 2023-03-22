package dbProviders

import (
	"encoding/json"
	"i2goSignals/internal/model"
)

type DbProviderInterface interface {
	Name(token string) string
	Check() error
	GetPublicTransmitterJWKS(issuer string) *json.RawMessage
	Close() error
	RegisterStream(request model.RegisterParameters) *model.RegisterResponse
}
