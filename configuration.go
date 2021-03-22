package main

import (
	"io/ioutil"
	"log"

	"gopkg.in/yaml.v3"
)

type Configuration struct {
	Yara struct {
		Path        string `yaml:"path"`
		Rulesrc4key string `yaml:"rulesRC4Key"`
	}
	Yarascan struct {
		Memory                 bool     `yaml:"memory"`
		Registry               bool     `yaml:"registry"`
		Startmenu              bool     `yaml:"startmenu"`
		Taskscheduler          bool     `yaml:"taskscheduler"`
		SystemDrive            bool     `yaml:"systemdrive"`
		Userfilesystem         bool     `yaml:"userfilesystem"`
		AbsolutePaths          []string `yaml:"absolutePaths"`
		InfiniteScan           bool     `yaml:"infinitescan"`
		AbsolutePathsRecursive bool     `yaml:"absolutePathsRecursive"`
	}
	Response struct {
		DumpDirectory       string `yaml:"dumpDirectory"`
		QuarantineDirectory string `yaml:"Directory"`
		QuarantineRC4Key    string `yaml:"quarantineRC4Key"`
		Kill                bool   `yaml:"kill"`
	}
	Network struct {
		Capture   bool   `yaml:"capture"`
		Bpffilter string `yaml:"bpffilter"`
		Pcapfile  string `yaml:"pcapfile"`
	}
	Output struct {
		Notifications bool `yaml:"notifications"`
		Verbose       bool `yaml:"verbose"`
	}
	Others struct {
		FakeProcesses bool `yaml:"fakeProcesses"`
	}
	Advancedparameters struct {
		MaxScanFilesize                  int      `yaml:"maxScanFilesize"`
		CleanMemoryIfFileGreaterThanSize int      `yaml:"cleanMemoryIfFileGreaterThanSize"`
		Extensions                       []string `yaml:"extensions"`
	}
}

func (c *Configuration) getConfiguration(configFile string) *Configuration {

	yamlFile, err := ioutil.ReadFile(configFile)
	if err != nil {
		log.Fatalf("Configuration file reading error #%v ", err)
	}
	err = yaml.Unmarshal(yamlFile, c)
	if err != nil {
		log.Fatalf("Configuration file parsing error: %v", err)
	}

	return c
}
