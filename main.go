// #cgo !yara_no_pkg_config,!yara_static  pkg-config: yara
// #cgo !yara_no_pkg_config,yara_static   pkg-config: --static yara
// #cgo yara_no_pkg_config                LDFLAGS:    -lyara
// compile: go build -tags yara_static -a -ldflags '-s -w -extldflags "-static"' .
package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/akamensky/argparse"
	"golang.org/x/sys/windows"
)

var (
	notificationsHistory []string
	filescanHistory      []FileDescriptor
	memoryHashHistory    []string
	killQueue            []string
	exit                 = make(chan bool)
)

var defaultScannedFileExtensions = []string{".txt", ".csv", ".htm", ".html", ".flv", ".f4v", ".avi", ".3gp", ".3g2", ".3gp2", ".3p2", ".divx", ".mp4", ".mkv", ".mov", ".qt", ".asf", ".wmv", ".rm", ".rmvb", ".vob", ".dat", ".mpg", ".mpeg", ".bik", ".fcs", ".mp3", ".mpeg3", ".flac", ".ape", ".ogg", ".aac", ".m4a", ".wma", ".ac3", ".wav", ".mka", ".rm", ".ra", ".ravb", ".mid", ".midi", ".cda", ".jpg", ".jpe", ".jpeg", ".jff", ".gif", ".png", ".bmp", ".tif", ".tiff", ".emf", ".wmf", ".eps", ".psd", ".cdr", ".swf", ".exe", ".lnk", ".dll", ".ps1", ".scr", ".ocx", ".com", ".sys", ".class", ".o", ".so", ".elf", ".prx", ".vb", ".vbs", ".js", ".bat", ".cmd", ".msi", ".msp", ".deb", ".rpm", ".sh", ".pl", ".dylib", ".doc", ".dot", ".docx", ".dotx", ".docm", ".dotm", ".xsl", ".xls", ".xlsx", ".xltx", ".xlsm", ".xltm", ".xlam", ".xlsb", ".ppt", ".pot", ".pps", ".pptx", ".potx", ".pptm", ".potm", ".ppsx", ".ppsm", ".rtf", ".pdf", ".msg", ".eml", ".vsd", ".vss", ".vst", ".vdx", ".vsx", ".vtx", ".xps", ".oxps", ".one", ".onepkg", ".xsn", ".odt", ".ods", ".odp", ".sxw", ".pub", ".mdb", ".accdb", ".accde", ".accdr", ".accdc", ".chm", ".mht", ".zip", ".7z", ".7-z", ".rar", ".iso", ".cab", ".jar", ".bz", ".bz2", ".tbz", ".tbz2", ".gz", ".tgz", ".arj", ".dmg", ".smi", ".img", ".xar"}

func main() {
	var err error
	log.SetOutput(os.Stdout)

	// create mutex to avoid program running multiple instances
	if _, err = CreateMutex("irmaBinMutex"); err != nil {
		log.Println("Only one instance or irma can be launched")
		os.Exit(1)
	}

	// clean and exit on CTRL+C
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for sig := range c {
			log.Printf("captured %v, stopping irma and exiting..", sig)
			exit <- true
		}
	}()

	parser := argparse.NewParser("irma", "Incident Response - Minimal Analysis")
	pNetworkCapturePath := parser.String("c", "network-capture", &argparse.Options{Required: false, Default: "", Help: "Capture network interface to PCAP file"})
	pBpfFilter := parser.String("b", "bpffilter", &argparse.Options{Required: false, Default: "", Help: "Use Berkeley Packet Filter to capture only selected parts of network traffic"})
	pYaraPath := parser.String("y", "yara-rules", &argparse.Options{Required: false, Default: "./yara-signatures", Help: "Yara rules path (the program will look for *.yar files recursively)"})
	pDump := parser.String("d", "dump", &argparse.Options{Required: false, Help: "Dump all running process to the specified directory"})
	pQuarantine := parser.String("q", "quarantine", &argparse.Options{Required: false, Help: "Specify path to store matching artefacts in quarantine (Base64/RC4 with key: irma"})
	pKill := parser.Flag("k", "kill", &argparse.Options{Required: false, Help: "Kill suspicious process ID (without removing process binary)"})
	pFaker := parser.Flag("f", "faker", &argparse.Options{Required: false, Help: "Spawn fake processes such as wireshark / procmon / procdump / x64dbg"})
	pNotifications := parser.Flag("n", "notifications", &argparse.Options{Required: false, Help: "Use Windows notifications when a file or memory stream match your YARA rules"})
	pVerbose := parser.Flag("v", "verbose", &argparse.Options{Required: false, Help: "Display every error and information messages"})
	pAggressive := parser.Flag("a", "aggressive", &argparse.Options{Required: false, Help: "Aggressive mode - remove suscpicious process executable / track and kill suspicious PPID / remove schedule task & regkey persistence"})

	err = parser.Parse(os.Args)
	if err != nil {
		fmt.Print(parser.Usage(err))
	}

	// Retrieve current user permissions
	admin, elevated := CheckCurrentUserPermissions()
	if !admin && !elevated {
		log.Println("[WARNING] IRMA is not running with admin righs. Notice that the analysis will be partial and limited to the current user scope")
		time.Sleep(5 * time.Second)
	}

	// spawn fake analysis processes (this binary is just a 10 seconds sleep infinite loop)
	if *pFaker {
		SpawnFakeProcesses(*pVerbose)
	}

	// load yara signature
	log.Println("[INIT] Starting IRMA")
	yaraPath := *pYaraPath
	yaraFiles := SearchForYaraFiles(yaraPath, *pVerbose)
	compiler, err := LoadYaraRules(yaraFiles, *pVerbose)
	if err != nil {
		log.Fatal(err)
	}

	if len(yaraFiles) == 0 {
		log.Fatal("No YARA rule found - Please add *.yar in " + *pYaraPath + " folder")
	}

	log.Println("[INIT] Loading ", len(yaraFiles), "YARA files")

	// compile yara rules
	rules, err := CompileRules(compiler)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("[INIT]", len(rules.GetRules()), "YARA rules compiled")
	log.Println("[INFO] Start scanning Memory / Registry / StartMenu / Task Scheduler / Filesystem")
	if len(*pNetworkCapturePath) > 0 {
		go NetworkAnalysisRoutine(*pBpfFilter, *pNetworkCapturePath, *pVerbose)
	}
	go MemoryAnalysisRoutine(*pDump, *pQuarantine, *pKill, *pAggressive, *pNotifications, *pVerbose, rules)
	go RegistryAnalysisRoutine(*pQuarantine, *pKill, *pAggressive, *pNotifications, *pVerbose, rules)
	go StartMenuAnalysisRoutine(*pQuarantine, *pKill, *pAggressive, *pNotifications, *pVerbose, rules)
	go TaskSchedulerAnalysisRoutine(*pQuarantine, *pKill, *pAggressive, *pNotifications, *pVerbose, rules)
	go WindowsFileSystemAnalysisRoutine(*pQuarantine, *pKill, *pAggressive, *pNotifications, *pVerbose, rules)
	go UserFileSystemAnalysisRoutine(*pQuarantine, *pKill, *pAggressive, *pNotifications, *pVerbose, rules)
	<-exit

}

// CheckCurrentUserPermissions retieves the current user permissions and check if the program run with elevated privileges
func CheckCurrentUserPermissions() (admin bool, elevated bool) {
	var err error
	var sid *windows.SID
	err = windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&sid)
	if err != nil {
		log.Fatalf("[ERROR] SID Error: %s", err)
		return false, false
	}
	defer windows.FreeSid(sid)
	token := windows.Token(0)

	admin, err = token.IsMember(sid)
	if err != nil {
		log.Fatalf("[ERROR] Token Membership Error: %s", err)
		return false, false
	}

	return admin, token.IsElevated()
}
