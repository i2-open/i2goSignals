package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type ClientConfig struct {
	Servers map[string]ServerConfig
}

type ServerConfig struct {
	Name          string
	HostPort      string
	Authorization string
	DbUrl         string
}

func (c *ClientConfig) Store(path string) {
	if len(c.Servers) > 0 {
		fileBytes, err := json.MarshalIndent(&c.Servers, "", "  ")
		fp := getFileName(path)
		tf, err := os.Create(fp)
		if err != nil {
			fmt.Println("Failed to create configuration file: " + err.Error())
			os.Exit(-1)
		}
		_, err = tf.Write(fileBytes)
		if err != nil {
			fmt.Println("Failed to write configuration data: " + err.Error())
			os.Exit(-1)
		}
		_ = tf.Close()
	}
}

func (c *ClientConfig) Load(path string) {
	fp := getFileName(path)
	var config map[string]ServerConfig
	dataBytes, err := os.ReadFile(fp)
	if err != nil {
		fmt.Println("Error reading configuration: " + err.Error())
		os.Exit(-1)
	}
	err = json.Unmarshal(dataBytes, &config)
	if err != nil {
		fmt.Println("Error parsing configuration: " + err.Error())
		os.Exit(-1)
	}
	c.Servers = config
}

func getFileName(path string) string {
	if path == "" {
		cwd, _ := os.Getwd()
		return filepath.Join(cwd, "signals_config.json")
	}

	return path
}
