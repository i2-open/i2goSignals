package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/i2-open/i2goSignals/internal/model"
)

type SsfServer struct {
	Alias               string
	Host                string
	ClientToken         string // Used to administer streams (scope admin) within a project
	IatToken            string // Used to register new client in the same project
	ProjectId           string
	Streams             map[string]Stream
	ServerConfiguration *model.TransmitterConfiguration
}

type Stream struct {
	Alias        string `json:"alias"`
	Id           string `json:"id"`
	Description  string `json:"description"`
	Token        string `json:"token"`
	Endpoint     string `json:"endpoint"`
	Iss          string `json:"iss"`
	Aud          string `json:"aud"` // Note this is a comma separated list because of the way i2scim consumes it
	IssJwksUrl   string `json:"issJwksUrl"`
	ConnectAlias string `json:"connectAlias,omitempty"`
}

type ConfigData struct {
	Selected      string
	Servers       map[string]SsfServer
	Pems          map[string][]byte
	keys          map[string]*rsa.PrivateKey            `json:"-"` // parsed keys - don't persist
	streamConfigs map[string]*model.StreamConfiguration `json:"-"` // don't store (cached)
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
GetStreamAndServer returns either the specified stream, server, or server and stream when using <server>.<stream> notation
*/
func (c *ConfigData) GetStreamAndServer(alias string) (*Stream, *SsfServer) {
	if strings.Contains(alias, ".") {
		parts := strings.Split(alias, ".")
		server, exists := c.Servers[parts[0]]
		if !exists {
			return nil, nil
		}
		stream, exists := server.Streams[parts[1]]
		if !exists {
			return nil, &server
		}
		return &stream, &server
	}
	for ks, server := range c.Servers {
		if ks == alias {
			return nil, &server
		}
		for k, stream := range server.Streams {
			if k == alias {
				return &stream, &server

			}
		}
	}
	return nil, nil
}

func (c *ConfigData) ResetStreamConfig(streamAlias string) {
	if c.streamConfigs == nil {
		c.streamConfigs = map[string]*model.StreamConfiguration{}
	}
	_, exist := c.streamConfigs[streamAlias]
	if exist {
		c.streamConfigs[streamAlias] = nil
	}
}
func (c *ConfigData) GetStreamConfig(streamAlias string) (*model.StreamConfiguration, error) {
	if c.streamConfigs == nil {
		c.streamConfigs = map[string]*model.StreamConfiguration{}
	}
	config := c.streamConfigs[streamAlias]
	if config != nil {
		return config, nil
	}
	client := http.Client{}
	stream, server := c.GetStreamAndServer(streamAlias)
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

	req, err := http.NewRequest(http.MethodGet, server.ServerConfiguration.ConfigurationEndpoint+"?stream_id="+stream.Id, nil)
	if err != nil {
		return nil, err
	}
	if server.ClientToken != "" {
		req.Header.Set("Authorization", "Bearer "+server.ClientToken)
	} else if stream.Token != "" {
		req.Header.Set("Authorization", "Bearer "+stream.Token)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New(fmt.Sprintf("Error retrieving configuration for %s: %s", stream.Alias, resp.Status))
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
	if g.Config == "" {
		g.Config = ".goSignals/config.json"
		usr, err := user.Current()
		if err == nil {
			g.Config = filepath.Join(usr.HomeDir, g.Config)
		}
	}
	// fmt.Println("Loading from " + g.Config)

	// Default all the maps to empty
	if c.Pems == nil {
		c.Pems = map[string][]byte{}
		c.Servers = map[string]SsfServer{}
		c.keys = map[string]*rsa.PrivateKey{}
		c.streamConfigs = map[string]*model.StreamConfiguration{}
	}

	if _, err := os.Stat(g.Config); os.IsNotExist(err) {
		return nil // No existing configuration
	}

	configBytes, err := os.ReadFile(g.Config)
	if err != nil {
		fmt.Println("Error reading configuration: " + err.Error())
		return nil
	}
	if len(configBytes) == 0 {
		return nil
	}
	err = json.Unmarshal(configBytes, c)
	if err != nil {
		fmt.Println("Error parsing stored configuration: " + err.Error())
	}
	return err
}

func (c *ConfigData) Save(g *Globals) error {

	configPath := g.Config
	if configPath == "" {
		configPath = ".goSignals/config.json"
		usr, err := user.Current()
		if err == nil {
			configPath = filepath.Join(usr.HomeDir, configPath)
		}
	}
	configDir := filepath.Dir(configPath)
	if _, err := os.Stat(configDir); os.IsNotExist(err) {
		// path/to/whatever does not exist
		err = os.Mkdir(configDir, 0770)
		if err != nil {
			return err
		}
	}
	out, err := json.MarshalIndent(c, "", " ")
	if err != nil {
		return err
	}
	err = os.WriteFile(configPath, out, 0660)
	if err != nil {
		fmt.Println("Error saving configuration: " + err.Error())
	}
	return err
}
