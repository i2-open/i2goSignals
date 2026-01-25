package config

import (
	"github.com/i2-open/i2goSignals/internal/logger"
	"github.com/kelseyhightower/envconfig"
)

var configLog = logger.Sub("CONFIG")

type Config struct {
	MongoUrl string `envconfig:"MONGO_URL"`
}

func GetEnvConfig() Config {
	var cfg Config
	err := envconfig.Process("", &cfg)
	if err != nil {
		configLog.Error("Error occurred reading configuration", "error", err)
		return Config{}
	}
	return cfg
}
