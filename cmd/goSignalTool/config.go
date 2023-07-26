package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"i2goSignals/internal/model"
	"io"
	"net/http"
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
	Id          string
	Description string
	Alias       string
	Token       string
	Endpoint    string
}

type ConfigData struct {
	Selected      string
	Servers       map[string]SsfServer
	Pems          map[string][]byte
	keys          map[string]*rsa.PrivateKey            `json:"-"` // don't persist
	streamConfigs map[string]*model.StreamConfiguration `json:"-"`
}

func (c *ConfigData) GetKey(issuerId string) (*rsa.PrivateKey, error) {
	key := c.keys[issuerId]
	if key != nil {
		return key, nil
	}

	var pemBytes []byte
	pemBytes = c.Pems[issuerId]
	block, _ := pem.Decode(pemBytes)

	pkcs8PrivateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key = pkcs8PrivateKey.(*rsa.PrivateKey)
	c.keys[issuerId] = key // cache the result

	return key, nil
}

/*
GetStream returns either the specified stream by alias or nil
*/
func (c *ConfigData) GetStream(alias string) (*Stream, *SsfServer) {
	for _, server := range c.Servers {
		for k, stream := range server.Streams {
			if k == alias {
				return &stream, &server

			}
		}
	}
	return nil, nil
}

func (c *ConfigData) GetStreamConfig(streamAlias string) (*model.StreamConfiguration, error) {
	config := c.streamConfigs[streamAlias]
	if config != nil {
		return config, nil
	}
	client := http.Client{}
	stream, server := c.GetStream(streamAlias)
	if stream == nil {
		return nil, errors.New("stream alias not defined")
	}
	defer client.CloseIdleConnections()
	config, err := getStreamConfig(client, server, stream)
	if err != nil {
		return nil, err
	}
	c.streamConfigs[streamAlias] = config
	return config, nil
}

func getStreamConfig(client http.Client, server *SsfServer, stream *Stream) (*model.StreamConfiguration, error) {
	fmt.Println("Retrieving stream configuration...")
	req, err := http.NewRequest(http.MethodGet, server.ServerConfiguration.ConfigurationEndpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+stream.Token)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	bodyBytes, _ := io.ReadAll(resp.Body)
	var config model.StreamConfiguration
	_ = json.Unmarshal(bodyBytes, &config)
	return &config, nil
}

/*
GetServer returns either the specified server alias, or the currently selected server if alias is ""
*/
func (c *ConfigData) GetServer(alias string) (*SsfServer, error) {
	if alias != "" {
		server, exists := c.Servers[alias]
		if !exists {
			errMsg := fmt.Sprintf("specified alias '%s' is not defined", alias)
			return nil, errors.New(errMsg)
		}
		return &server, nil
	}

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
	if c.Pems == nil {
		c.Pems = map[string][]byte{}
	}
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
