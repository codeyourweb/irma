package main

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modkernel32                 = windows.NewLazySystemDLL("Kernel32.dll")
	modpsapi                    = windows.NewLazySystemDLL("Psapi.dll")
	procCreateMutex             = modkernel32.NewProc("CreateMutexW")
	procGetSystemInfo           = modkernel32.NewProc("GetSystemInfo")
	procReadProcessMemory       = modkernel32.NewProc("ReadProcessMemory")
	procVirtualProtect          = modkernel32.NewProc("VirtualProtect")
	procGetProcessImageFileName = modpsapi.NewProc("GetProcessImageFileNameA")
	procEnumProcessModules      = modpsapi.NewProc("EnumProcessModules")
	procGetModuleFileNameEx     = modpsapi.NewProc("GetModuleFileNameExA")
	procGetModuleInformation    = modpsapi.NewProc("GetModuleInformation")
)

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
