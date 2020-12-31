package main

import (
	"crypto/md5"
	"crypto/rc4"
	b64 "encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/hillu/go-yara"
)

// WindowsFileSystemAnalysisRoutine analyse windows filesystem every 300 seconds
func WindowsFileSystemAnalysisRoutine(pQuarantine string, pKill bool, pAggressive bool, pNotifications bool, pVerbose bool, rules *yara.Rules) {
	for true {
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
	for true {
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

// FileAnalysis sub-routine for file analysis (used in registry / task scheduler / startmenu scan)
func FileAnalysis(path string, pQuarantine string, pKill bool, pAggressive bool, pNotifications bool, pVerbose bool, rules *yara.Rules, sourceIndex string) {
	var err error
	var content []byte
	var result yara.MatchRules

	content, err = ioutil.ReadFile(path)
	if err != nil && pVerbose {
		log.Println(path, err)
	}

	fileHash := fmt.Sprintf("%x", md5.Sum(content))
	if !StringInSlice(fileHash, filescanHistory) {
		if pVerbose {
			log.Println("[INFO] ["+sourceIndex+"] Analyzing", path)
		}

		result, err = YaraScan(content, rules)
		if len(result) > 0 {
			// windows notifications
			if pNotifications {
				NotifyUser("YARA match", path+" match "+fmt.Sprint(len(result))+" rules")
			}

			// logging
			for _, match := range result {
				log.Println("[ALERT]", "YARA MATCH", path, match.Namespace, match.Rule)
			}

			// dump matching process to quarantine
			if len(pQuarantine) > 0 {
				log.Println("[INFO]", "DUMPING FILE", path)
				err := QuarantineFile(content, filepath.Base(path), pQuarantine)
				if err != nil {
					log.Println("[ERROR]", "Cannot quarantine file", path, err)
				}
			}
		}

		filescanHistory = append(filescanHistory, fileHash)
	}

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
			files, err := ioutil.ReadDir(path)
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

// QuarantineFile copy and encrypt suspicious file
func QuarantineFile(content []byte, filename string, quarantinePath string) (err error) {
	_, err = os.Stat(quarantinePath)
	if os.IsNotExist(err) {
		if err := os.MkdirAll(quarantinePath, 0600); err != nil {
			return err
		}
	}

	c, err := rc4.NewCipher([]byte("irma"))
	if err != nil {
		return err
	}

	xPE := make([]byte, len(content))
	c.XORKeyStream(xPE, content)
	err = ioutil.WriteFile(quarantinePath+"/"+filename+".irma", []byte(b64.StdEncoding.EncodeToString(xPE)), 0644)
	if err != nil {
		return err
	}

	return nil
}

// QuarantineProcess dump process executable and memory and cipher them in quarantine folder
func QuarantineProcess(proc ProcessInformation, quarantinePath string) (err error) {

	err = QuarantineFile(proc.ProcessMemory, proc.ProcessName+fmt.Sprint(proc.PID)+".mem", quarantinePath)
	if err != nil {
		return err
	}

	procPEContent, err := ioutil.ReadFile(proc.ProcessPath)
	if err != nil {
		return err
	}

	err = QuarantineFile(procPEContent, proc.ProcessName+fmt.Sprint(proc.PID)+".pe", proc.ProcessPath)
	if err != nil {
		return err
	}

	return nil
}
