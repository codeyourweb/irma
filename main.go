// #cgo !yara_no_pkg_config,!yara_static  pkg-config: yara
// #cgo !yara_no_pkg_config,yara_static   pkg-config: --static yara
// #cgo yara_no_pkg_config                LDFLAGS:    -lyara
// compile: go build -tags yara_static -a -ldflags '-s -w -extldflags "-static"' .
package main

import (
	"fmt"
	"log"
	"os"

	"github.com/akamensky/argparse"
	"github.com/gen2brain/beeep"
)

func main() {
	var err error

	// create mutex to avoid irpame running multiple instances
	if _, err = CreateMutex("irpameMutex"); err != nil {
		os.Exit(1)
	}

	parser := argparse.NewParser("irpame", "Incident Response - Primary Analysis & Malware Eradication")
	pYaraPath := parser.String("y", "yara-rules", &argparse.Options{Required: false, Default: "./yara-signatures", Help: "Yara rules path (the program will look for *.yar files recursively)"})
	pDump := parser.String("d", "dump", &argparse.Options{Required: false, Help: "Dump all running process to the specified directory"})
	pKill := parser.Flag("k", "kill", &argparse.Options{Required: false, Help: "Kill suspicious process ID (without removing process binary)"})
	pFaker := parser.Flag("f", "faker", &argparse.Options{Required: false, Help: "Spawn fake processes such as wireshark / procmon / procdump / x64dbg"})
	pAggressive := parser.Flag("a", "aggressive", &argparse.Options{Required: false, Help: "Aggressive mode - remove suscpicious process executable / track and remove PPID / remove schedule task & regkey persistence"})
	pNotifications := parser.Flag("n", "notifications", &argparse.Options{Required: false, Help: "Use Windows notifications when a file or memory stream match your YARA rules"})

	err = parser.Parse(os.Args)
	if err != nil {
		fmt.Print(parser.Usage(err))
	}

	// spawn fake analysis processes (this binary is just a 10 seconds sleep infinite loop)
	if *pFaker {
		spawnFakeProcesses()
	}

	// load yara signature
	yaraPath := *pYaraPath
	yaraFiles := SearchForYaraFiles(yaraPath)
	compiler, err := LoadYaraRules(yaraFiles)
	if err != nil {
		log.Fatal(err)
	}

	rules, err := CompileRules(compiler)
	if err != nil {
		log.Fatal(err)
	}

	// list process information and memory
	procs := ListProcess()

	// dump process memory and quit the program
	if len(*pDump) > 0 {
		pDump := *pDump
		for _, proc := range procs {
			if err := WriteProcessMemoryToFile(pDump, proc.ProcessName+fmt.Sprint(proc.PID)+".dmp", proc.ProcessMemory); err != nil {
				log.Println(err)
			}
		}
		os.Exit(0)
	}

	// analyze process memory
	for _, proc := range procs {
		result, err := YaraScan(proc.ProcessMemory, rules)
		if err != nil {
			log.Println(err)
		}

		if len(result) > 0 {
			if *pNotifications {
				notifyUser("YARA match", proc.ProcessName+":"+fmt.Sprint(proc.PID)+" match "+fmt.Sprint(len(result))+" rules")
			}

			for _, match := range result {
				fmt.Println("[YARA MATCH]", proc.ProcessName, "PID:", fmt.Sprint(proc.PID), match.Namespace, match.Rule)
			}
		}
	}

	// TODO: kill matching processes
	if *pKill {

	}

	// TODO: remove malware and persistence
	if *pAggressive {

	}

	// TODO: routine - analyze file in temporary folder

}

func notifyUser(title string, message string) {
	err := beeep.Alert(title, message, "")
	if err != nil {
		panic(err)
	}
}

func spawnFakeProcesses() {
	if err := SpawnFakeProcess("procmon.exe"); err != nil {
		log.Println(err)
	}
	if err := SpawnFakeProcess("wireshark.exe"); err != nil {
		log.Println(err)
	}
	if err := SpawnFakeProcess("tcpdump.exe"); err != nil {
		log.Println(err)
	}
	if err := SpawnFakeProcess("sysmon.exe"); err != nil {
		log.Println(err)
	}
	if err := SpawnFakeProcess("sysmon64.exe"); err != nil {
		log.Println(err)
	}
	if err := SpawnFakeProcess("x86dbg.exe"); err != nil {
		log.Println(err)
	}
	if err := SpawnFakeProcess("x64dbg.exe"); err != nil {
		log.Println(err)
	}
	if err := SpawnFakeProcess("inetsim.exe"); err != nil {
		log.Println(err)
	}
}
