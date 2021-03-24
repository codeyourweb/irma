package main

import (
	"archive/zip"
	"bytes"
	"crypto/rc4"
	_ "embed"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

//go:embed resources/winrar_sfx.exe
var sfxBinary []byte

func BuildSFX(yaraPath string, rc4key string, config Configuration, outputSfxExe string) error {
	// compress inputDirectory into archive
	archive := recursiveCompressFolder(yaraPath, rc4key, config)

	file, err := os.Create(outputSfxExe)
	if err != nil {
		return err
	}

	defer file.Close()

	// pack sfx binary and customized archive together
	file.Write(sfxBinary)
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
	var b2i int = 0
	if config.Sfx.SilentMode {
		b2i = 1
	}
	var sfxcomment = "the comment below contains sfx script commands\r\n\r\n" +
		"Path=" + config.Sfx.ExtractDirectory + "\r\n"

	if config.Sfx.Autoexec {
		sfxcomment += "Setup=irma.exe -c configuration.yaml"
	}

	if len(config.Sfx.LogFile) > 0 {
		sfxcomment += " -o \"" + config.Sfx.LogFile + "\""
	}

	sfxcomment += "\r\n" +
		"Silent=" + fmt.Sprint(b2i) + "\r\n" +
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
