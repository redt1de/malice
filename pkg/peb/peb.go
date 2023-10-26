package peb

import "golang.org/x/sys/windows"

func GetPEB() uintptr
func GetExportsDirAddr(modBaseAddr uintptr) uintptr
func GetNumberOfNames(exportsBase uintptr) uint32
func GetAddressOfFunctions(moduleBase, exportsBase uintptr) uintptr
func GetAddressOfNames(moduleBase, exportsBase uintptr) uintptr
func GetAddressOfNameOrdinals(moduleBase, exportsBase uintptr) uintptr
func Rva2Va(moduleBase uintptr, rva uint32) uintptr

func getModByIndex(i int) (start uintptr, size uintptr, modulepath *UniString)
func GetModPtrByIndex(i int) *LdrDataTableEntry

// GetModByIndex returns the start address of module located at i in the load order. This might be useful if there is a function you need that isn't in ntdll, or if some rude individual has loaded themselves before ntdll.
func GetModByIndex(i int) (start uintptr, size uintptr, modulepath string) {
	var badstring *UniString
	start, size, badstring = getModByIndex(i)
	modulepath = badstring.String()
	return
}

type UniString struct {
	Length    uint16
	MaxLength uint16
	PWstr     *uint16
}

func (s UniString) String() string {
	return windows.UTF16PtrToString(s.PWstr)
}

type LdrDataTableEntry struct {
	InLoadOrderLinks           ListEntry
	InMemoryOrderLinks         ListEntry
	InInitializationOrderLinks ListEntry
	DllBase                    *uintptr
	EntryPoint                 *uintptr
	SizeOfImage                *uintptr
	FullDllName                UniString
	BaseDllName                UniString
	Flags                      uint32
	LoadCount                  uint16
	TlsIndex                   uint16
	HashLinks                  ListEntry
	TimeDateStamp              uint64
}

type ListEntry struct {
	Flink *ListEntry
	Blink *ListEntry
}
