package config

import (
	"log"

	"github.com/kelseyhightower/envconfig"
)

type Config struct {
	MongoUrl string `envconfig:"MONGO_URL"`
}

func GetEnvConfig() Config {
	var cfg Config
	err := envconfig.Process("", &cfg)
	if err != nil {
		log.Println("Error occurred reading configuration: " + err.Error())
		return Config{}
	}
	return cfg
}
