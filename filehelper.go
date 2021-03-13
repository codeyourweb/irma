package main

import (
	"errors"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/hillu/go-yara/v4"
)

// WindowsFileSystemAnalysisRoutine analyse windows filesystem every 300 seconds
func WindowsFileSystemAnalysisRoutine(pQuarantine string, pKill bool, pAggressive bool, pNotifications bool, pVerbose bool, rules *yara.Rules) {
	for {
		env := ListEnvironmentPathFiles(pVerbose)
		temp := ListTemporaryFiles(pVerbose)

		for _, p := range env {
			FileAnalysis(p, pQuarantine, pKill, pAggressive, pNotifications, pVerbose, rules, "ENV")
		}

		for _, p := range temp {
			FileAnalysis(p, pQuarantine, pKill, pAggressive, pNotifications, pVerbose, rules, "TEMP")
		}

		time.Sleep(300 * time.Second)
	}
}

// UserFileSystemAnalysisRoutine analyse windows filesystem every 60 seconds
func UserFileSystemAnalysisRoutine(pQuarantine string, pKill bool, pAggressive bool, pNotifications bool, pVerbose bool, rules *yara.Rules) {
	for {
		files := ListUserWorkspaceFiles(pVerbose)

		for _, p := range files {
			FileAnalysis(p, pQuarantine, pKill, pAggressive, pNotifications, pVerbose, rules, "USER")
		}
		time.Sleep(60 * time.Second)
	}
}

// ListUserWorkspaceFiles recursively list all files in USERPROFILE directory
func ListUserWorkspaceFiles(verbose bool) (files []string) {
	f, err := RetrivesFilesFromUserPath(os.Getenv("USERPROFILE"), true, defaultScannedFileExtensions, true, verbose)
	if err != nil && verbose {
		log.Println(err)
	}

	for _, i := range f {
		files = append(files, i)
	}
	return files
}

// ListEnvironmentPathFiles list all files in PATH directories
func ListEnvironmentPathFiles(verbose bool) (files []string) {
	env := os.Getenv("PATH")
	paths := strings.Split(env, ";")
	for _, p := range paths {
		f, err := RetrivesFilesFromUserPath(p, true, defaultScannedFileExtensions, false, verbose)
		if err != nil && verbose {
			log.Println(err)
			continue
		}

		for _, i := range f {
			files = append(files, i)
		}
	}

	return files
}

// ListTemporaryFiles list all files in TEMP / TMP / %SystemRoot%\Temp
func ListTemporaryFiles(verbose bool) (files []string) {

	var folders = []string{os.Getenv("TEMP")}
	if os.Getenv("TMP") != os.Getenv("TEMP") {
		folders = append(folders, os.Getenv("TMP"))
	}

	if os.Getenv("SystemRoot")+`\Temp` != os.Getenv("TEMP") {
		folders = append(folders, os.Getenv("SystemRoot")+`\Temp`)
	}

	for _, p := range folders {
		f, err := RetrivesFilesFromUserPath(p, true, defaultScannedFileExtensions, true, verbose)
		if err != nil && verbose {
			log.Println(err)
			continue
		}

		for _, i := range f {
			files = append(files, i)
		}
	}

	return files
}

// FormatPathFromComplexString search for file/directory path and remove environments variables, quotes and extra parameters
func FormatPathFromComplexString(command string) (paths []string) {
	var buffer []string

	// quoted path
	if strings.Contains(command, `"`) || strings.Contains(command, `'`) {
		re := regexp.MustCompile(`[\'\"](.+)[\'\"]`)
		matches := re.FindStringSubmatch(command)
		for i := range matches {
			if i != 0 {
				buffer = append(buffer, matches[i])
			}
		}
	} else {
		for _, i := range strings.Split(strings.Replace(command, ",", "", -1), " ") {
			buffer = append(buffer, i)
		}

	}

	for _, item := range buffer {
		// environment variables
		if strings.Contains(command, `%`) {
			re := regexp.MustCompile(`%(\w+)%`)
			res := re.FindStringSubmatch(item)
			for i := range res {
				item = strings.Replace(item, "%"+res[i]+"%", os.Getenv(res[i]), -1)
			}
		}

		// check if file exists
		if _, err := os.Stat(item); !os.IsNotExist(err) {
			paths = append(paths, item)
		}
	}

	return paths
}

// RetrivesFilesFromUserPath return a []string of available files from given path (includeFileExtensions is available only if listFiles is true)
func RetrivesFilesFromUserPath(path string, listFiles bool, includeFileExtensions []string, recursive bool, verbose bool) ([]string, error) {
	var p []string

	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return []string{}, errors.New("Input file not found")
	}

	if !info.IsDir() {
		p = append(p, path)
	} else {
		if !recursive {
			files, err := os.ReadDir(path)
			if err != nil {
				return []string{}, err
			}
			for _, f := range files {
				if !(f.IsDir() == listFiles) && (len(includeFileExtensions) == 0 || StringInSlice(filepath.Ext(f.Name()), includeFileExtensions)) {
					p = append(p, path+string(os.PathSeparator)+f.Name())
				}
			}
		} else {
			err := filepath.Walk(path, func(walk string, info os.FileInfo, err error) error {
				if err != nil && verbose {
					log.Println("[ERROR]", err)
				}

				if err == nil && !(info.IsDir() == listFiles) && (len(includeFileExtensions) == 0 || StringInSlice(filepath.Ext(walk), includeFileExtensions)) {
					p = append(p, walk)
				}

				return nil
			})

			if err != nil && verbose {
				log.Println("[ERROR]", err)
			}
		}
	}

	return p, nil
}
