package main

import (
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
)

// ListEnvironmentPathFile list all files in PATH directories
func ListEnvironmentPathFile() (files []string) {
	env := os.Getenv("PATH")
	paths := strings.Split(env, ";")
	for _, p := range paths {
		f, err := RetrivesFilesFromUserPath(p, true, nil, false)
		if err != nil {
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
func ListTemporaryFiles() (files []string) {

	var folders = []string{os.Getenv("TEMP")}
	if os.Getenv("TMP") != os.Getenv("TEMP") {
		folders = append(folders, os.Getenv("TMP"))
	}

	if os.Getenv("SystemRoot")+`\Temp` != os.Getenv("TEMP") {
		folders = append(folders, os.Getenv("SystemRoot")+`\Temp`)
	}

	for _, p := range folders {
		f, err := RetrivesFilesFromUserPath(p, true, nil, true)
		if err != nil {
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
func RetrivesFilesFromUserPath(path string, listFiles bool, includeFileExtensions []string, recursive bool) ([]string, error) {
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
				if err != nil {
					log.Println(err)
				}

				if err == nil && !(info.IsDir() == listFiles) && (len(includeFileExtensions) == 0 || StringInSlice(filepath.Ext(walk), includeFileExtensions)) {
					p = append(p, walk)
				}

				return nil
			})

			if err != nil {
				log.Println(err)
			}
		}
	}

	return p, nil
}

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
