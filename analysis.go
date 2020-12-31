package main

import (
	"crypto/md5"
	"crypto/rc4"
	b64 "encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"

	"github.com/hillu/go-yara"
)

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

		result = PerformYaraScan(content, rules, pVerbose)

		if len(result) > 0 {
			// windows notifications
			if pNotifications {
				NotifyUser("YARA match", path+" match "+fmt.Sprint(len(result))+" rules")
			}

			// logging
			for _, match := range result {
				log.Println("[ALERT]", "["+sourceIndex+"] YARA match", path, match.Namespace, match.Rule)
			}

			// kill
			if pKill {
				killQueue = append(killQueue, path)
			}

			// dump matching file to quarantine
			if len(pQuarantine) > 0 {
				log.Println("[INFO]", "Dumping file", path)
				err := QuarantineFile(filepath.Base(path), pQuarantine)
				if err != nil {
					log.Println("[ERROR]", "Cannot quarantine file", path, err)
				}
			}
		} else {
			filescanHistory = append(filescanHistory, fileHash)
		}
	}
}

// MemoryAnalysis sub-routine for running processes analysis
func MemoryAnalysis(proc ProcessInformation, pQuarantine string, pKill bool, pAggressive bool, pNotifications bool, pVerbose bool, rules *yara.Rules) {
	memoryHash := fmt.Sprintf("%x", md5.Sum(proc.ProcessMemory))

	// if hash isn't already whitelisted, yara scan it
	if !StringInSlice(memoryHash, memoryscanHistory) {
		if pVerbose {
			log.Println("[INFO] [MEMORY] Analyzing", proc.ProcessName, "PID:", proc.PID)
		}

		result := PerformYaraScan(proc.ProcessMemory, rules, pVerbose)
		if len(result) > 0 {
			// windows notifications
			if pNotifications {
				NotifyUser("YARA match", proc.ProcessName+" - PID:"+fmt.Sprint(proc.PID)+" match "+fmt.Sprint(len(result))+" rules")
			}

			// logging
			for _, match := range result {
				log.Println("[ALERT]", "[MEMORY] YARA match", proc.ProcessName, "PID:", fmt.Sprint(proc.PID), match.Namespace, match.Rule)
			}

			// dump matching process to quarantine
			if len(pQuarantine) > 0 {
				log.Println("[INFO]", "DUMPING PID", proc.PID)
				err := QuarantineProcess(proc, pQuarantine)
				if err != nil {
					log.Println("[ERROR]", "Cannot quarantine PID", proc.PID, err)
				}
			}

			// killing process
			if pKill {
				log.Println("[INFO]", "KILLING PID", proc.PID)
				KillProcessByID(proc.PID, pVerbose)
			}
		} else {
			memoryscanHistory = append(memoryscanHistory, memoryHash)
		}
	}
}

// QuarantineProcess dump process memory and cipher them in quarantine folder
func QuarantineProcess(proc ProcessInformation, quarantinePath string) (err error) {

	err = quarantineContent(proc.ProcessMemory, proc.ProcessName+fmt.Sprint(proc.PID)+".mem", quarantinePath)
	if err != nil {
		return err
	}

	err = QuarantineFile(proc.ProcessPath, quarantinePath)
	if err != nil {
		return err
	}

	return nil
}

// QuarantineFile dump specified file and cipher them in quarantine folder
func QuarantineFile(path, quarantinePath string) (err error) {
	fileContent, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}

	err = quarantineContent(fileContent, filepath.Base(path), quarantinePath)
	if err != nil {
		return err
	}

	return nil
}

// quarantineContent copy and encrypt suspicious content
func quarantineContent(content []byte, filename string, quarantinePath string) (err error) {
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
