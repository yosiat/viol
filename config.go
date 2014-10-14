package main

import (
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"log"
	"os"
	"path"
)

// Default configuration file name, he is located from the current working directory
var CONFIG_FILE = "config.yaml"

type Configuration struct {
	Pcap PcapConfiguraiton
}

type PcapConfiguraiton struct {
	Device    string "device"
	BpfFilter string "bpf_filter"
	Sanplen   int    "snaplen"
	Promisc   bool   "promisc"
	RFMon     bool   "rfmon"
}

// Currently our way of handling errors
// TODO: should be writen to log or somehting
func HandleError(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

// Read the configuration file (config.yml) and parses it
func ReadConfiguration() (Configuration, error) {
	config := Configuration{}

	// get the configuration file
	configFilePath, err := os.Getwd()
	if err != nil {
		return config, err
	}

	configFilePath = path.Join(configFilePath, CONFIG_FILE)
	log.Println("Reading configuration from", configFilePath)

	// read the file and parse it
	file, err := ioutil.ReadFile(configFilePath)
	if err != nil {
		return config, err
	}

	err = yaml.Unmarshal(file, &config)
	return config, err
}
