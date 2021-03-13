package main

import (
	_ "embed"
	"os"
	"syscall"
)

//go:embed resources/fake_process.exe
var faker []byte

// SpawnFakeProcess drop an useless process and execute it
func SpawnFakeProcess(processName string) (err error) {
	err = os.WriteFile(processName, faker, 0644)
	if err != nil {
		return err
	}

	var sI syscall.StartupInfo
	var pI syscall.ProcessInformation
	argv := syscall.StringToUTF16Ptr(processName)
	err = syscall.CreateProcess(nil, argv, nil, nil, true, 0, nil, nil, &sI, &pI)
	if err != nil {
		return err
	}

	return nil
}
