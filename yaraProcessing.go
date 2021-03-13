package main

import (
	"bytes"
	"errors"
	"log"
	"os"
	"path/filepath"

	"github.com/gen2brain/go-unarr"
	"github.com/hillu/go-yara/v4"
)

// PerformYaraScan use provided YARA rules and search for match in the given byte slice
func PerformYaraScan(data *[]byte, rules *yara.Rules, verbose bool) yara.MatchRules {
	result, err := YaraScan(*data, rules)
	if err != nil && verbose {
		log.Println("[ERROR]", err)
	}

	return result
}

// PerformArchiveYaraScan try to decompress archive and YARA scan every file in it
func PerformArchiveYaraScan(path string, rules *yara.Rules, verbose bool) yara.MatchRules {
	var buffer [][]byte

	a, err := unarr.NewArchive(path)
	if err != nil && verbose {
		log.Println("[ERROR]", err)
	}
	defer a.Close()

	list, err := a.List()
	if err != nil && verbose {
		log.Println("[ERROR]", err)
	}
	for _, f := range list {
		err := a.EntryFor(f)
		if err != nil && verbose {
			log.Println("[ERROR]", err)
		}

		data, err := a.ReadAll()
		if err != nil && verbose {
			log.Println("[ERROR]", err)
		}

		buffer = append(buffer, data)
	}

	result, err := YaraScan(bytes.Join(buffer, []byte{}), rules)
	if err != nil && verbose {
		log.Println("[ERROR]", err)
	}

	return result
}

// SearchForYaraFiles search *.yar file by walking recursively from specified input path
func SearchForYaraFiles(path string, verbose bool) (rules []string) {
	rules, err := RetrivesFilesFromUserPath(path, true, []string{".yar"}, true, verbose)
	if err != nil && verbose {
		log.Println(err)
	}
	return rules
}

// LoadYaraRules compile yara rules from specified paths and return a pointer to the yara compiler
func LoadYaraRules(path []string, verbose bool) (compiler *yara.Compiler, err error) {
	compiler, err = yara.NewCompiler()
	if err != nil {
		return nil, errors.New("Failed to initialize YARA compiler")
	}

	for _, dir := range path {
		f, err := os.Open(dir)
		if err != nil && verbose {
			log.Println("[ERROR]", "Could not open rule file ", dir, err)
		}

		namespace := filepath.Base(dir)[:len(filepath.Base(dir))-4]
		if err = compiler.AddFile(f, namespace); err != nil && verbose {
			log.Println("[ERROR]", "Could not load rule file ", dir, err)
		}
		f.Close()
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
