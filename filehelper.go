package main

import (
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
)

// SearchForYaraFiles search *.yar file by walking recursively from specified input path
func SearchForYaraFiles(path string) (rules []string) {
	filepath.Walk(path, func(walk string, info os.FileInfo, err error) error {
		if err != nil {
			log.Println(err)
		}

		if err == nil && !info.IsDir() && info.Size() > 0 && len(filepath.Ext(walk)) > 0 && strings.ToLower(filepath.Ext(walk)) == ".yar" {
			rules = append(rules, walk)
		}

		return nil
	})

	return rules
}

// WriteProcessMemoryToFile try to write a byte slice to the specified directory
func WriteProcessMemoryToFile(path string, file string, data []byte) (err error) {
	_, err = os.Stat(path)
	if os.IsNotExist(err) {
		if err := os.MkdirAll(path, 0600); err != nil {
			return err
		}
	}

	if err := ioutil.WriteFile(path+"/"+file, data, 0644); err != nil {
		return err
	}

	return nil
}

// StringInSlice check wether or not a string already is inside a specified slice
func StringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}
