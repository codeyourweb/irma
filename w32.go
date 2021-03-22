package main

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows services constants
const (
	SVC_SC_ENUM_PROCESS_INFO = 0
	SVC_SERVICE_WIN32        = 0x00000030
	SVC_SERVICE_STATE_ALL    = 0x00000003
	SVC_SERVICE_ACCEPT_STOP  = 0x00000001
)

var (
	modAdvapi32                 = windows.NewLazySystemDLL("Advapi32.dll")
	modkernel32                 = windows.NewLazySystemDLL("Kernel32.dll")
	modpsapi                    = windows.NewLazySystemDLL("Psapi.dll")
	procCreateMutex             = modkernel32.NewProc("CreateMutexW")
	procGetSystemInfo           = modkernel32.NewProc("GetSystemInfo")
	procReadProcessMemory       = modkernel32.NewProc("ReadProcessMemory")
	procVirtualProtect          = modkernel32.NewProc("VirtualProtect")
	procGetExitCodeProcess      = modkernel32.NewProc("GetExitCodeProcess")
	procGetProcessImageFileName = modpsapi.NewProc("GetProcessImageFileNameA")
	procEnumProcessModules      = modpsapi.NewProc("EnumProcessModules")
	procGetModuleFileNameEx     = modpsapi.NewProc("GetModuleFileNameExA")
	procGetModuleInformation    = modpsapi.NewProc("GetModuleInformation")
	procSvcEnumServicesStatusEx = modAdvapi32.NewProc("EnumServicesStatusExW")
)

// wrapper for WIN32 API ENUM_SERVICE_STATUS_PROCESSW structure
// https://docs.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-enum_service_status_processw
type ENUM_SERVICE_STATUS_PROCESS struct {
	lpServiceName        *uint16
	lpDisplayName        *uint16
	ServiceStatusProcess SERVICE_STATUS_PROCESS
}

// wrapper for WIN32 API SERVICE_STATUS_PROCESS structure
// https://docs.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_status_process
type SERVICE_STATUS_PROCESS struct {
	dwServiceType             uint32
	dwCurrentState            uint32
	dwControlsAccepted        uint32
	dwWin32ExitCode           uint32
	dwServiceSpecificExitCode uint32
	dwCheckPoint              uint32
	dwWaitHint                uint32
	dwProcessId               uint32
	dwServiceFlags            uint32
}

// SystemInfo structure contains information about the current computer system. This includes the architecture and type of the processor, the number of processors in the system, the page size, and other such information.
// https://docs.microsoft.com/en-us/windows/win32/api/sysinfoapi/ns-sysinfoapi-system_info
type SystemInfo struct {
	ProcessorArchitecture     int16
	reserved                  int16
	PageSize                  int32
	MinimumApplicationAddress uintptr
	MaximumApplicationAddress uintptr
	ActiveProcessorMask       uintptr
	NumberOfProcessors        int32
	ProcessorType             int32
	AllocationGranularity     int32
	ProcessorLevel            int16
	ProcessorRevision         int16
}

// ModuleInfo structure contains the module load address, size, and entry point.
// https://docs.microsoft.com/en-us/windows/win32/api/psapi/ns-psapi-moduleinfo
type ModuleInfo struct {
	BaseOfDll   uintptr
	SizeOfImage int32
	EntryPoint  uintptr
}

// GetSystemInfo is a wrapper for the same WIN32 API function
// https://docs.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsysteminfo
func GetSystemInfo() (si SystemInfo) {
	_, _, _ = syscall.Syscall(procGetSystemInfo.Addr(), 1, uintptr(unsafe.Pointer(&si)), 0, 0)
	return si
}

// GetProcessImageFileName is a wrapper for the same WIN32 API function
// https://docs.microsoft.com/fr-fr/windows/win32/api/psapi/nf-psapi-getprocessimagefilenamea?redirectedfrom=MSDN
func GetProcessImageFileName(hProcess windows.Handle, nSize uintptr) (data []byte, err error) {
	data = make([]byte, nSize)
	ret, _, err := syscall.Syscall(procGetProcessImageFileName.Addr(), 3, uintptr(hProcess), uintptr(unsafe.Pointer(&data[0])), nSize)
	if ret == 0 {
		return nil, err
	}

	return data, nil
}

// EnumProcessModules is a wrapper for the same WIN32 API function
// https://docs.microsoft.com/fr-fr/windows/win32/api/psapi/nf-psapi-enumprocessmodules?redirectedfrom=MSDN
func EnumProcessModules(hProcess windows.Handle, nSize uintptr) (modules []syscall.Handle, err error) {
	modules = make([]syscall.Handle, nSize)
	var sizeNeeded uint32 = 0
	ret, _, _ := syscall.Syscall6(procEnumProcessModules.Addr(), 4, uintptr(hProcess), uintptr(unsafe.Pointer(&modules[0])), uintptr(nSize), uintptr(unsafe.Pointer(&sizeNeeded)), 0, 0)
	if ret == 0 {
		return nil, err
	}

	return modules, nil
}

// GetModuleFileNameEx is a wrapper for the same WIN32 API function
// https://docs.microsoft.com/fr-fr/windows/win32/api/psapi/nf-psapi-getmodulefilenameexa?redirectedfrom=MSDN
func GetModuleFileNameEx(hProcess windows.Handle, hModule syscall.Handle, nSize uintptr) (data []byte, err error) {
	data = make([]byte, nSize)
	ret, _, _ := syscall.Syscall6(procGetModuleFileNameEx.Addr(), 4, uintptr(hProcess), uintptr(hModule), uintptr(unsafe.Pointer(&data[0])), uintptr(nSize), 0, 0)
	if ret == 0 {
		return nil, err
	}

	return data, nil
}

// GetModuleInformation is a wrapper for the same WIN32 API function
// https://docs.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-getmoduleinformation
func GetModuleInformation(hProcess windows.Handle, hModule syscall.Handle) (modInfos ModuleInfo, err error) {
	ret, _, err := syscall.Syscall6(procGetModuleInformation.Addr(), 4, uintptr(hProcess), uintptr(hModule), uintptr(unsafe.Pointer(&modInfos)), uintptr(unsafe.Sizeof(modInfos)), 0, 0)
	if ret == 0 {
		return ModuleInfo{}, err
	}

	return modInfos, nil
}

// ReadProcessMemory is a wrapper for the same WIN32 API function
// https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-readprocessmemory
func ReadProcessMemory(hProcess windows.Handle, lpBaseAddress uintptr, nSize uintptr) (data []byte, err error) {
	data = make([]byte, nSize)
	var lpNumberOfBytesRead uint32 = 0
	ret, _, err := syscall.Syscall6(procReadProcessMemory.Addr(), 5, uintptr(hProcess), lpBaseAddress, uintptr(unsafe.Pointer(&data[0])), nSize, uintptr(unsafe.Pointer(&lpNumberOfBytesRead)), 0)
	if ret == 0 {
		return nil, err
	}

	return data, nil
}

// CreateMutex is a wrapper for CreateMutexW WIN32 API function
// https://docs.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-createmutexw
func CreateMutex(name string) (uintptr, error) {
	ret, _, err := procCreateMutex.Call(
		0,
		0,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(name))),
	)
	switch int(err.(syscall.Errno)) {
	case 0:
		return ret, nil
	default:
		return ret, err
	}
}

// VirtualProtect is a wrapper for the same WIN32 API function
// https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect
func VirtualProtect(lpAddress unsafe.Pointer, dwSize uintptr, flNewProtect uint32, lpflOldProtect unsafe.Pointer) bool {
	ret, _, _ := procVirtualProtect.Call(
		uintptr(lpAddress),
		uintptr(dwSize),
		uintptr(flNewProtect),
		uintptr(lpflOldProtect))
	return ret > 0
}

// GetExitCodeProcess is a wrapper for the same WIN32 API function
// https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getexitcodeprocess
func GetExitCodeProcess(hProcess windows.Handle) uint32 {
	var lpExitCode uint32 = 0
	ret, _, _ := syscall.Syscall(procGetExitCodeProcess.Addr(), 2, uintptr(hProcess), uintptr(unsafe.Pointer(&lpExitCode)), 0)
	if ret != 0 {
		return lpExitCode
	}

	return 0
}
