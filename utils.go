package main

import (
	"log"

	"github.com/gen2brain/beeep"
)

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
