package main

import (
	"crypto/rc4"
	b64 "encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
)

// QuarantineProcess dump process executable and memory and cipher them in quarantine folder
func QuarantineProcess(proc ProcessInformation, path string) (err error) {
	_, err = os.Stat(path)
	if os.IsNotExist(err) {
		if err := os.MkdirAll(path, 0600); err != nil {
			return err
		}
	}

	c, err := rc4.NewCipher([]byte("irma"))
	if err != nil {
		return err
	}
	xMem := make([]byte, len(proc.ProcessMemory))
	c.XORKeyStream(xMem, proc.ProcessMemory)
	err = ioutil.WriteFile(path+"/"+proc.ProcessName+fmt.Sprint(proc.PID)+".mem.irma", []byte(b64.StdEncoding.EncodeToString(xMem)), 0644)
	if err != nil {
		return err
	}

	procPE, err := ioutil.ReadFile(proc.ProcessPath)
	if err != nil {
		return err
	}

	c, err = rc4.NewCipher([]byte("irma"))
	if err != nil {
		return err
	}

	xPE := make([]byte, len(procPE))
	c.XORKeyStream(xPE, procPE)
	err = ioutil.WriteFile(path+"/"+proc.ProcessName+fmt.Sprint(proc.PID)+".pe.irma", []byte(b64.StdEncoding.EncodeToString(xPE)), 0644)
	if err != nil {
		return err
	}

	return nil
}

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
