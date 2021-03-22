package main

import (
	"archive/zip"
	"bytes"
	"crypto/rc4"
	b64 "encoding/base64"
	"io"
	"log"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

func BuildSFX(yaraPath string, rc4key string, config Configuration, outputSfxExe string) error {
	// compress inputDirectory into archive
	archive := recursiveCompressFolder(yaraPath, rc4key, config)

	// embed winrar-zipsfx binary
	sDec, err := b64.StdEncoding.DecodeString(sfxBinary)
	if err != nil {
		return err
	}

	file, err := os.Create(outputSfxExe)
	if err != nil {
		return err
	}

	defer file.Close()
	file.Write([]byte(sDec))
	file.Write(archive.Bytes())

	return nil
}

func recursiveCompressFolder(yaraPath string, rc4key string, config Configuration) bytes.Buffer {
	var buffer bytes.Buffer
	archive := zip.NewWriter(&buffer)

	files := SearchForYaraFiles(yaraPath, true)

	// embed irma.exe executable
	zipFile, err := archive.Create("irma.exe")
	if err != nil {
		log.Fatal("[ERROR] ", err)
	}

	fsFile, err := os.ReadFile(os.Args[0])
	if err != nil {
		log.Fatal("[ERROR] ", err)
	}

	r := bytes.NewReader(fsFile)
	_, err = io.Copy(zipFile, r)
	if err != nil {
		log.Fatal("[ERROR] ", err)
	}

	// embed configuration file
	zipFile, err = archive.Create("configuration.yaml")
	if err != nil {
		log.Fatal("[ERROR] ", err)
	}

	config.Yara.Path = "yara-signatures/"
	d, err := yaml.Marshal(&config)
	r = bytes.NewReader(d)
	_, err = io.Copy(zipFile, r)
	if err != nil {
		log.Fatal("[ERROR] ", err)
	}

	// embed yara rules
	for _, f := range files {
		fileName := filepath.Base(f)
		zipFile, err := archive.Create("yara-signatures/" + fileName)
		if err != nil {
			log.Fatal("[ERROR] ", err)
		}

		fsFile, err := os.ReadFile(f)
		if err != nil {
			log.Fatal("[ERROR] ", err)
		}

		// yara rule RC4 cipher
		if len(rc4key) > 0 {
			c, err := rc4.NewCipher([]byte(rc4key))
			if err != nil {
				log.Fatal("[ERROR] ", err)
			}

			c.XORKeyStream(fsFile, fsFile)
		}

		r := bytes.NewReader(fsFile)
		_, err = io.Copy(zipFile, r)
		if err != nil {
			log.Fatal("[ERROR] ", err)
		}
	}

	// sfx comment
	var sfxcomment = "the comment below contains sfx script commands\r\n\r\n" +
		"Path=%temp%\r\n" +
		"Setup=irma.exe -c configuration.yaml\r\n" +
		"Silent=1\r\n" +
		"Overwrite=1"

	archive.SetComment(sfxcomment)

	if err != nil {
		return buffer
	}
	err = archive.Close()

	if err != nil {
		log.Fatal("[ERROR] ", err)
	}
	return buffer
}
