// #cgo !yara_no_pkg_config,!yara_static  pkg-config: yara
// #cgo !yara_no_pkg_config,yara_static   pkg-config: --static yara
// #cgo yara_no_pkg_config                LDFLAGS:    -lyara
// compile: go build -tags yara_static -a -ldflags '-s -w -extldflags "-static"' .
package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"time"

	"github.com/akamensky/argparse"
	"github.com/gen2brain/beeep"
	"github.com/hillu/go-yara"
)

var (
	notificationsHistory []string
	filescanHistory      []string
	memoryscanHistory    []string
)

func main() {
	var err error

	// create mutex to avoid program running multiple instances
	if _, err = CreateMutex("irmaBinMutex"); err != nil {
		os.Exit(1)
	}

	parser := argparse.NewParser("irma", "Incident Response - Minimal Analysis")
	pYaraPath := parser.String("y", "yara-rules", &argparse.Options{Required: false, Default: "./yara-signatures", Help: "Yara rules path (the program will look for *.yar files recursively)"})
	pDump := parser.String("d", "dump", &argparse.Options{Required: false, Help: "Dump all running process to the specified directory"})
	pQuarantine := parser.String("q", "quarantine", &argparse.Options{Required: false, Help: "Specify path to store matching artefacts in quarantine (Base64/RC4 with key: irma"})
	pKill := parser.Flag("k", "kill", &argparse.Options{Required: false, Help: "Kill suspicious process ID (without removing process binary)"})
	pFaker := parser.Flag("f", "faker", &argparse.Options{Required: false, Help: "Spawn fake processes such as wireshark / procmon / procdump / x64dbg"})
	pAggressive := parser.Flag("a", "aggressive", &argparse.Options{Required: false, Help: "Aggressive mode - remove suscpicious process executable / track and remove suspicious PPID / remove schedule task & regkey persistence"})
	pNotifications := parser.Flag("n", "notifications", &argparse.Options{Required: false, Help: "Use Windows notifications when a file or memory stream match your YARA rules"})
	pVerbose := parser.Flag("v", "verbose", &argparse.Options{Required: false, Help: "Display every error"})

	err = parser.Parse(os.Args)
	if err != nil {
		fmt.Print(parser.Usage(err))
	}

	// spawn fake analysis processes (this binary is just a 10 seconds sleep infinite loop)
	if *pFaker {
		SpawnFakeProcesses(*pVerbose)
	}

	// load yara signature
	fmt.Println("[INFO] Starting IRMA")
	yaraPath := *pYaraPath
	yaraFiles := SearchForYaraFiles(yaraPath)
	compiler, err := LoadYaraRules(yaraFiles)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Loading ", len(yaraFiles), "YARA files")

	// compile yara rules
	rules, err := CompileRules(compiler)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(len(rules.GetRules()), "YARA rules compiled")

	go SystemAnalysisRoutine(*pDump, *pQuarantine, *pKill, *pAggressive, *pNotifications, *pVerbose, rules)
	for true {
		time.Sleep(5 * time.Second)
	}
}

// SystemAnalysisRoutine analyse system artefacts every 5 seconds
func SystemAnalysisRoutine(pDump string, pQuarantine string, pKill bool, pAggressive bool, pNotifications bool, pVerbose bool, rules *yara.Rules) {
	for true {
		// list process information and memory
		procs := ListProcess(pVerbose)

		// dump process memory and quit the program
		if len(pDump) > 0 {
			for _, proc := range procs {
				if err := WriteProcessMemoryToFile(pDump, proc.ProcessName+fmt.Sprint(proc.PID)+".dmp", proc.ProcessMemory); err != nil && pVerbose {
					log.Println(err)
				}
			}
			os.Exit(0)
		}

		// analyze process memory and executable
		for _, proc := range procs {
			result := PerformYaraScan(proc.ProcessMemory, rules, pVerbose)
			if len(result) == 0 {
				procPE, err := ioutil.ReadFile(proc.ProcessPath)
				if err != nil && pVerbose {
					log.Println(err)
				}
				result = PerformYaraScan(procPE, rules, pVerbose)
			}

			if len(result) > 0 {
				// windows notifications
				if pNotifications {
					NotifyUser("YARA match", proc.ProcessName+":"+fmt.Sprint(proc.PID)+" match "+fmt.Sprint(len(result))+" rules")
				}

				// logging
				for _, match := range result {
					log.Println("[YARA MATCH]", proc.ProcessName, "PID:", fmt.Sprint(proc.PID), match.Namespace, match.Rule)
				}

				// dump matching process to quarantine
				if len(pQuarantine) > 0 {
					log.Println("[ACTION]", "Dumping PID", proc.PID)
					err := QuarantineProcess(proc, pQuarantine)
					if err != nil && pVerbose {
						log.Println("Cannot quarantine PID", proc.PID, err)
					}
				}

				// killing process
				if pKill {
					log.Println("[ACTION]", "Killing PID", proc.PID)
					KillProcessByID(proc.PID, pVerbose)
				}

			}
		}

		// TODO aggressive mode
		if pAggressive {

		}

		// TODO: routine - analyze file in temporary folder

		time.Sleep(5 * time.Second)
	}

}

// PerformYaraScan use provided YARA rules and search for match in the given byte slice
func PerformYaraScan(data []byte, rules *yara.Rules, verbose bool) yara.MatchRules {
	result, err := YaraScan(data, rules)
	if err != nil && verbose {
		log.Println(err)
	}

	return result
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
		log.Println(err)
	}
	if err := SpawnFakeProcess("wireshark.exe"); err != nil && verbose {
		log.Println(err)
	}
	if err := SpawnFakeProcess("tcpdump.exe"); err != nil && verbose {
		log.Println(err)
	}
	if err := SpawnFakeProcess("sysmon.exe"); err != nil && verbose {
		log.Println(err)
	}
	if err := SpawnFakeProcess("sysmon64.exe"); err != nil && verbose {
		log.Println(err)
	}
	if err := SpawnFakeProcess("x86dbg.exe"); err != nil && verbose {
		log.Println(err)
	}
	if err := SpawnFakeProcess("x64dbg.exe"); err != nil && verbose {
		log.Println(err)
	}
	if err := SpawnFakeProcess("inetsim.exe"); err != nil && verbose {
		log.Println(err)
	}
}
