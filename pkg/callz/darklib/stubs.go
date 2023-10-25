package darklib

import "golang.org/x/sys/windows"

// GetPEB returns addr to PEB
func GetPEB() uintptr

// GetNtdll returns the start and size of ntdll
func GetNtdll() (start uintptr, size uintptr)

// getModByIndex returns the start address of module located at i in the load order. This might be useful if there is a function you need that isn't in ntdll, or if some rude individual has loaded themselves before ntdll.
func getModByIndex(i int) (start uintptr, size uintptr, modulepath *unistring)

// GetModPtrByIndex returns a pointer to the ldr data table entry in full, incase there is something interesting in there you want to see.
func GetModPtrByIndex(i int) *LdrDataTableEntry

type LdrDataTableEntry struct {
	InLoadOrderLinks           ListEntry
	InMemoryOrderLinks         ListEntry
	InInitializationOrderLinks ListEntry
	DllBase                    *uintptr
	EntryPoint                 *uintptr
	SizeOfImage                *uintptr
	FullDllName                unistring
	BaseDllName                unistring
	Flags                      uint32
	LoadCount                  uint16
	TlsIndex                   uint16
	HashLinks                  ListEntry
	TimeDateStamp              uint64
}

type unistring struct {
	Length    uint16
	MaxLength uint16
	PWstr     *uint16
}

func (s unistring) String() string {
	return windows.UTF16PtrToString(s.PWstr)
}

type ListEntry struct {
	Flink *ListEntry
	Blink *ListEntry
}

// GetModByIndex returns the start address of module located at i in the load order. This might be useful if there is a function you need that isn't in ntdll, or if some rude individual has loaded themselves before ntdll.
func GetModByIndex(i int) (start uintptr, size uintptr, modulepath string) {
	var badstring *unistring
	start, size, badstring = getModByIndex(i)
	modulepath = badstring.String()
	return
}
