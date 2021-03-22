package main

import (
	"bytes"
	"crypto/rc4"
	"errors"
	"os"
	"path/filepath"

	"github.com/gen2brain/go-unarr"
	"github.com/hillu/go-yara/v4"
)

// PerformYaraScan use provided YARA rules and search for match in the given byte slice
func PerformYaraScan(data *[]byte, rules *yara.Rules, verbose bool) yara.MatchRules {
	result, err := YaraScan(*data, rules)
	if err != nil && verbose {
		logMessage(LOG_ERROR, "[ERROR]", err)
	}

	return result
}

// PerformArchiveYaraScan try to decompress archive and YARA scan every file in it
func PerformArchiveYaraScan(path string, rules *yara.Rules, verbose bool) (matchs yara.MatchRules) {
	var buffer [][]byte

	a, err := unarr.NewArchive(path)
	if err != nil {
		if verbose {
			logMessage(LOG_ERROR, "[ERROR]", err)
		}
		return matchs
	}
	defer a.Close()

	list, err := a.List()
	if err != nil {
		if verbose {
			logMessage(LOG_ERROR, "[ERROR]", err)
		}
		return matchs
	}
	for _, f := range list {
		err := a.EntryFor(f)
		if err != nil {
			if verbose {
				logMessage(LOG_ERROR, "[ERROR]", err)
			}
			return matchs
		}

		data, err := a.ReadAll()
		if err != nil {
			if verbose {
				logMessage(LOG_ERROR, "[ERROR]", err)
			}
			return matchs
		}

		buffer = append(buffer, data)
	}

	matchs, err = YaraScan(bytes.Join(buffer, []byte{}), rules)
	if err != nil && verbose {
		if verbose {
			logMessage(LOG_ERROR, "[ERROR]", err)
		}
		return matchs
	}

	return matchs
}

// SearchForYaraFiles search *.yar file by walking recursively from specified input path
func SearchForYaraFiles(path string, verbose bool) (rules []string) {
	rules, err := RetrivesFilesFromUserPath(path, true, []string{".yar"}, true, verbose)
	if err != nil && verbose {
		logMessage(LOG_INFO, err)
	}
	return rules
}

// LoadYaraRules compile yara rules from specified paths and return a pointer to the yara compiler
func LoadYaraRules(path []string, rc4key string, verbose bool) (compiler *yara.Compiler, err error) {
	compiler, err = yara.NewCompiler()
	if err != nil {
		return nil, errors.New("Failed to initialize YARA compiler")
	}

	for _, dir := range path {
		f, err := os.ReadFile(dir)
		if err != nil && verbose {
			logMessage(LOG_ERROR, "[ERROR]", "Could not read rule file ", dir, err)
		}

		if len(rc4key) > 0 && !bytes.Contains(f, []byte("rule ")) {
			c, err := rc4.NewCipher([]byte(rc4key))
			if err != nil {
				logMessage(LOG_ERROR, "[ERROR]", err)
			}

			c.XORKeyStream(f, f)
		}

		namespace := filepath.Base(dir)[:len(filepath.Base(dir))-4]
		if err = compiler.AddString(string(f), namespace); err != nil && verbose {
			logMessage(LOG_ERROR, "[ERROR]", "Could not load rule file ", dir, err)
		}
	}

	return compiler, nil
}

// CompileRules try to compile every rules from the given compiler
func CompileRules(compiler *yara.Compiler) (rules *yara.Rules, err error) {

	rules, err = compiler.GetRules()
	if err != nil {
		return nil, errors.New("Failed to compile rules")
	}

	return rules, err
}

// YaraScan use libyara to scan the specified content with a compiled rule
func YaraScan(content []byte, rules *yara.Rules) (match yara.MatchRules, err error) {
	sc, _ := yara.NewScanner(rules)
	var m yara.MatchRules
	err = sc.SetCallback(&m).ScanMem(content)
	return m, err
}
