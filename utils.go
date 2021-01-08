package main

import (
	"log"
	"os"

	"github.com/gen2brain/beeep"
)

// RegisterFileInHistory check if file is already known and hasn't change in files history return true if file is append to history and false if it is already known as is.
func RegisterFileInHistory(f os.FileInfo, path string, history *[]FileDescriptor) bool {
	for i, h := range *history {
		if h.FilePath == path {
			if h.LastModified == f.ModTime() && h.FileSize == f.Size() {
				return false
			}
			(*history)[i].LastModified = f.ModTime()
			(*history)[i].FileSize = f.Size()
			return true
		}
	}

	var d = FileDescriptor{FilePath: path, FileSize: f.Size(), LastModified: f.ModTime()}
	*history = append(*history, d)
	return true
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

// NotifyUser use Windows notification to instant alert
func NotifyUser(title string, message string) {
	err := beeep.Alert(title, message, "")
	if err != nil {
		panic(err)
	}
}

// SpawnFakeProcesses drop fake analysis process
func SpawnFakeProcesses(verbose bool) {
	if err := SpawnFakeProcess("procmon.exe"); err != nil && verbose {
		log.Println("[ERROR]", err)
	}
	if err := SpawnFakeProcess("wireshark.exe"); err != nil && verbose {
		log.Println("[ERROR]", err)
	}
	if err := SpawnFakeProcess("tcpdump.exe"); err != nil && verbose {
		log.Println("[ERROR]", err)
	}
	if err := SpawnFakeProcess("sysmon.exe"); err != nil && verbose {
		log.Println("[ERROR]", err)
	}
	if err := SpawnFakeProcess("sysmon64.exe"); err != nil && verbose {
		log.Println("[ERROR]", err)
	}
	if err := SpawnFakeProcess("x86dbg.exe"); err != nil && verbose {
		log.Println("[ERROR]", err)
	}
	if err := SpawnFakeProcess("x64dbg.exe"); err != nil && verbose {
		log.Println("[ERROR]", err)
	}
	if err := SpawnFakeProcess("inetsim.exe"); err != nil && verbose {
		log.Println("[ERROR]", err)
	}
}
