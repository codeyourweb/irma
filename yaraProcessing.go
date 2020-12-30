package main

import (
	"errors"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/hillu/go-yara"
)

// PerformYaraScan use provided YARA rules and search for match in the given byte slice
func PerformYaraScan(data []byte, rules *yara.Rules, verbose bool) yara.MatchRules {
	result, err := YaraScan(data, rules)
	if err != nil && verbose {
		log.Println("[ERROR]", err)
	}

	return result
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

// LoadYaraRules compile yara rules from specified paths and return a pointer to the yara compiler
func LoadYaraRules(path []string) (compiler *yara.Compiler, err error) {
	compiler, err = yara.NewCompiler()
	if err != nil {
		return nil, errors.New("Failed to initialize YARA compiler")
	}

	for _, dir := range path {
		f, err := os.Open(dir)
		if err != nil {
			log.Println("[ERROR]", "Could not open rule file ", dir, err)
		}

		namespace := filepath.Base(dir)[:len(filepath.Base(dir))-4]
		if err = compiler.AddFile(f, namespace); err != nil {
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
