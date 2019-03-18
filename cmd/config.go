package main

import (
	"github.com/joho/godotenv"
	"github.com/kelseyhightower/envconfig"
	"github.com/pkg/errors"
)

type Config struct {
	Port            int    `default:8080`
	ForwardTo       string `required:"true"`
	AcceptOriginPtn string `required:"true" default:"^https?\:\/{2}localhost"`
	AuthConfigFile  string `default:"./config.yml"`
	SessionName     string `default:"demo"`
	CertFile        string
	KeyFile         string
}

func loadConfig() (*Config, error) {
	godotenv.Load()

	var c Config
	err := envconfig.Process("apx", &c)

	if err != nil {
		return nil, errors.WithStack(err)
	}
	return &c, nil
}
