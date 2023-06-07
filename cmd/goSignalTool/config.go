package main

import (
	"encoding/json"
	"errors"
	"i2goSignals/internal/model"
	"os"
	"path/filepath"
)

type SsfServer struct {
	Alias string
	Host  string
	// Authorization string
	Streams             map[string]Stream
	ServerConfiguration *model.TransmitterConfiguration
}

type Stream struct {
	Id    string
	Alias string
	Token string
}

type ConfigData struct {
	Selected string
	Servers  map[string]SsfServer
}

func (c *ConfigData) GetCurrentServer() (*SsfServer, error) {
	if c.Selected == "" || len(c.Servers) == 0 {
		return nil, errors.New("no servers defined, use 'add server'")
	}

	server := c.Servers[c.Selected]
	return &server, nil
}

func (c *ConfigData) Load(g *Globals) error {
	if _, err := os.Stat(g.Config); os.IsNotExist(err) {
		return nil // No existing configuration
	}

	configBytes, err := os.ReadFile(g.Config)
	if err != nil {
		return nil
	}
	err = json.Unmarshal(configBytes, c)
	return err
}

func (c *ConfigData) Save(g *Globals) error {

	configPath := g.Config

	configDir := filepath.Dir(configPath)
	if _, err := os.Stat(configDir); os.IsNotExist(err) {
		// path/to/whatever does not exist
		os.Mkdir(configDir, 0770)
	}
	out, err := json.MarshalIndent(c, "", " ")
	if err != nil {
		return err
	}

	return os.WriteFile(configPath, out, 0660)
}
