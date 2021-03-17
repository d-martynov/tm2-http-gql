package main

import (
	"github.com/BurntSushi/toml"
	tm2rabbit "github.com/CortexTechnology/tm2-rabbit-base"
	"io/ioutil"
)

type Config struct {
	App      AppConfig
	RabbitMq tm2rabbit.RabbitMqConfig
}

type AppConfig struct {
	AuthPublicKey string
}

func GetConfig() Config {
	var configFile, err = ioutil.ReadFile("config.toml")
	if err != nil {
		panic("Unable to read config file: " + err.Error())
	}

	var conf Config
	if _, err := toml.Decode(string(configFile), &conf); err != nil {
		panic("Unable to parse config")
	}

	return conf
}
