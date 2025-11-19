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
	"time"

	"github.com/i2-open/i2goSignals/internal/model"
)

var ConfigFile = "config.json"

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
	// Ensure cache map is initialized
	if c.keys == nil {
		c.keys = map[string]*rsa.PrivateKey{}
	}
	// Return from cache if present
	if key := c.keys[issuerId]; key != nil {
		return key, nil
	}

	// Validate PEM storage
	if c.Pems == nil {
		return nil, errors.New("no PEMs loaded; configuration not initialized")
	}
	pemBytes, ok := c.Pems[issuerId]
	if !ok || len(pemBytes) == 0 {
		return nil, fmt.Errorf("no PEM found for issuer '%s'", issuerId)
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil || len(block.Bytes) == 0 {
		return nil, errors.New("invalid or corrupt PEM data")
	}

	pkcs8PrivateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key := pkcs8PrivateKey.(*rsa.PrivateKey)
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

func (c *ConfigData) checkConfigPath(g *Globals) error {
	configPath := g.Config
	if configPath == "" {
		configPath = stripQuotes(os.Getenv("GOSIGNALS_HOME"))
		if configPath == "" {
			configPath = ".goSignals/" + ConfigFile
			usr, err := user.Current()
			if err == nil {
				configPath = filepath.Join(usr.HomeDir, configPath)
			}
		} else {
			fmt.Printf("Using GOSIGNALS_HOME path: %s\n", configPath)
			g.ConfigFile = configPath
			return nil
		}
	}

	dirPath := filepath.Dir(configPath)
	i := len(dirPath)
	if dirPath[i-1:i-1] != "/" {
		dirPath = dirPath + "/"
	}
	baseFile := filepath.Base(configPath)
	if filepath.Ext(baseFile) == "" {
		dirPath = configPath
		baseFile = ConfigFile
	}

	_, err := os.Stat(dirPath)
	if os.IsNotExist(err) {
		fmt.Printf("Config path does not exist check: %s\n", dirPath)
		err = nil
		// path/to/whatever does not exist
		fmt.Printf("Creating new config path: %s\n", dirPath)
		err = os.Mkdir(dirPath, 0770)
		if err != nil {
			fmt.Printf("Error creating directory %s: %s", dirPath, err)
			time.Sleep(5 * time.Minute) // wait long enough to check files in docker
			return err
		}
	}

	g.ConfigFile = configPath

	return nil
}

func (c *ConfigData) Load(g *Globals) error {
	// configFile := filepath.Join(g.Config, ConfigFile)

	// Default all the maps to empty (initialize each independently)
	if c.Pems == nil {
		c.Pems = map[string][]byte{}
	}
	if c.Servers == nil {
		c.Servers = map[string]SsfServer{}
	}
	if c.keys == nil {
		c.keys = map[string]*rsa.PrivateKey{}
	}
	if c.streamConfigs == nil {
		c.streamConfigs = map[string]*model.StreamConfiguration{}
	}

	if _, err := os.Stat(g.ConfigFile); os.IsNotExist(err) {
		return nil // No existing configuration
	}

	configBytes, err := os.ReadFile(g.ConfigFile)
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
		return err
	}

	// After unmarshal, ensure non-persisted and optional maps are non-nil
	if c.Pems == nil {
		c.Pems = map[string][]byte{}
	}
	if c.Servers == nil {
		c.Servers = map[string]SsfServer{}
	}
	if c.keys == nil {
		c.keys = map[string]*rsa.PrivateKey{}
	}
	if c.streamConfigs == nil {
		c.streamConfigs = map[string]*model.StreamConfiguration{}
	}

	return nil
}

func (c *ConfigData) Save(g *Globals) error {

	out, err := json.MarshalIndent(c, "", " ")
	if err != nil {
		return err
	}
	fmt.Println("Writing to: " + g.ConfigFile)
	err = os.WriteFile(g.ConfigFile, out, 0660)
	if err != nil {
		fmt.Println("Error saving configuration: " + err.Error())
	}
	return err
}
