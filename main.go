// #cgo !yara_no_pkg_config,!yara_static  pkg-config: yara
// #cgo !yara_no_pkg_config,yara_static   pkg-config: --static yara
// #cgo yara_no_pkg_config                LDFLAGS:    -lyara
// compile: go build -tags yara_static -a -ldflags '-s -w -extldflags "-static"' .
package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"sync"
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
	config               Configuration
)

var defaultScannedFileExtensions = []string{}
var maxFilesizeScan int
var cleanIfFileSizeGreaterThan int
var quarantineKey string
var archivesFormats = []string{"application/x-tar", "application/x-7z-compressed", "application/zip", "application/vnd.rar"}
var wg sync.WaitGroup

func main() {
	var err error

	// create mutex to avoid program running multiple instances
	if _, err = CreateMutex("irmaBinMutex"); err != nil {
		logMessage(LOG_ERROR, "Only one instance or irma can be launched")
		os.Exit(1)
	}

	// clean and exit on CTRL+C
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for sig := range c {
			fmt.Printf("[INFO] captured %v, stopping irma and exiting..", sig)
			exit <- true
		}
	}()

	// parse arguments
	parser := argparse.NewParser("irma", "Incident Response - Minimal Analysis")
	pConfigurationFile := parser.String("c", "configuration", &argparse.Options{Required: true, Default: "configuration.yaml", Help: "yaml configuration file"})
	pBuilder := parser.String("b", "builder", &argparse.Options{Required: false, Default: "", Help: "create a standalone launcher executable with packed rules and configuration"})
	pLog := parser.String("o", "outfile", &argparse.Options{Required: false, Default: "", Help: "save log informations inside the specified file path"})

	err = parser.Parse(os.Args)
	if err != nil {
		fmt.Print(parser.Usage(err))
	}

	// read configuration file
	config.getConfiguration(*pConfigurationFile)
	if len(*pBuilder) > 0 {
		BuildSFX(config.Yara.Path, config.Yara.Rulesrc4key, config, *pBuilder)
		os.Exit(0)
	}

	maxFilesizeScan = config.Advancedparameters.MaxScanFilesize
	cleanIfFileSizeGreaterThan = config.Advancedparameters.CleanMemoryIfFileGreaterThanSize
	defaultScannedFileExtensions = config.Advancedparameters.Extensions
	quarantineKey = config.Response.QuarantineRC4Key

	// log inside a file
	if len(*pLog) > 0 {
		f, err := os.OpenFile(*pLog, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
		if err != nil {
			log.Fatal(err)
		}

		out := os.Stdout
		mw := io.MultiWriter(out, f)
		r, w, _ := os.Pipe()

		os.Stdout = w
		os.Stderr = w

		go func() {
			_, _ = io.Copy(mw, r)
		}()

	}

	// Retrieve current user permissions
	admin, elevated := CheckCurrentUserPermissions()
	if !admin && !elevated {
		logMessage(LOG_INFO, "[WARNING] IRMA is not running with admin righs. Notice that the analysis will be partial and limited to the current user scope")
		time.Sleep(5 * time.Second)
	}

	// spawn fake analysis processes (this binary is just a 10 seconds sleep infinite loop)
	if config.Others.FakeProcesses {
		SpawnFakeProcesses(config.Output.Verbose)
	}

	// load yara signature
	logMessage(LOG_INFO, "[INIT] Starting IRMA")
	yaraPath := config.Yara.Path
	yaraFiles := SearchForYaraFiles(yaraPath, config.Output.Verbose)
	compiler, err := LoadYaraRules(yaraFiles, config.Yara.Rulesrc4key, config.Output.Verbose)
	if err != nil {
		logMessage(LOG_ERROR, err)
	}

	if len(yaraFiles) == 0 {
		logMessage(LOG_ERROR, "[ERROR] No YARA rule found - Please add *.yar in "+config.Yara.Path+" folder")
	}

	logMessage(LOG_INFO, "[INIT] Loading ", len(yaraFiles), "YARA files")

	// compile yara rules
	rules, err := CompileRules(compiler)
	if err != nil {
		logMessage(LOG_ERROR, err)
	}
	logMessage(LOG_INFO, "[INIT]", len(rules.GetRules()), "YARA rules compiled")

	if config.Network.Capture {
		wg.Add(1)
		logMessage(LOG_INFO, "[INFO] Start network capture")
		go NetworkAnalysisRoutine(config.Network.Bpffilter, config.Network.Pcapfile, config.Output.Verbose)
	}

	if config.Yarascan.Memory {
		wg.Add(1)
		logMessage(LOG_INFO, "[INFO] Start scanning memory")
		go MemoryAnalysisRoutine(config.Response.DumpDirectory, config.Response.QuarantineDirectory, config.Response.Kill, config.Output.Notifications, config.Output.Verbose, config.Yarascan.InfiniteScan, rules)
	}

	if config.Yarascan.Registry {
		wg.Add(1)
		logMessage(LOG_INFO, "[INFO] Start scanning registry")
		go RegistryAnalysisRoutine(config.Response.QuarantineDirectory, config.Response.Kill, config.Output.Notifications, config.Output.Verbose, config.Yarascan.InfiniteScan, rules)
	}

	if config.Yarascan.Startmenu {
		wg.Add(1)
		logMessage(LOG_INFO, "[INFO] Start scanning startmenu")
		go StartMenuAnalysisRoutine(config.Response.QuarantineDirectory, config.Response.Kill, config.Output.Notifications, config.Output.Verbose, config.Yarascan.InfiniteScan, rules)
	}

	if config.Yarascan.Taskscheduler {
		wg.Add(1)
		logMessage(LOG_INFO, "[INFO] Start scanning tasks scheduler")
		go TaskSchedulerAnalysisRoutine(config.Response.QuarantineDirectory, config.Response.Kill, config.Output.Notifications, config.Output.Verbose, config.Yarascan.InfiniteScan, rules)
	}

	if config.Yarascan.Userfilesystem {
		wg.Add(1)
		logMessage(LOG_INFO, "[INFO] Start scanning user filesystem")
		go UserFileSystemAnalysisRoutine(config.Response.QuarantineDirectory, config.Response.Kill, config.Output.Notifications, config.Output.Verbose, config.Yarascan.InfiniteScan, rules)
	}

	if config.Yarascan.SystemDrive {
		wg.Add(1)
		logMessage(LOG_INFO, "[INFO] Start scanning system drive")
		go WindowsFileSystemAnalysisRoutine(config.Response.QuarantineDirectory, config.Response.Kill, config.Output.Notifications, config.Output.Verbose, config.Yarascan.InfiniteScan, rules)
	}

	for _, p := range config.Yarascan.AbsolutePaths {
		logMessage(LOG_INFO, "[INFO] Start scanning "+p)
		go func(path string) {
			wg.Add(1)
			for {
				files, err := RetrivesFilesFromUserPath(path, true, defaultScannedFileExtensions, config.Yarascan.AbsolutePathsRecursive, config.Output.Verbose)
				if err != nil {
					if config.Output.Verbose {
						logMessage(LOG_ERROR, err)
					}
					break
				}

				for _, f := range files {
					FileAnalysis(f, config.Response.QuarantineDirectory, config.Response.Kill, config.Output.Notifications, config.Output.Verbose, rules, "CUSTOMSCAN")
				}

				if !config.Yarascan.InfiniteScan {
					wg.Done()
					break
				} else {
					time.Sleep(60 * time.Second)
				}
			}
		}(p)
	}

	// Exit program when all goroutines have ended
	wg.Wait()
	os.Exit(0)
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
