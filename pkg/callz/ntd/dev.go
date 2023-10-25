package ntd

import (
	"fmt"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// /////////////////////////////////////////////////////
// getModByIndex returns the start address of module located at i in the load order. This might be useful if there is a function you need that isn't in ntdll, or if some rude individual has loaded themselves before ntdll.
func getModByIndex(i int) (start uintptr, size uintptr, modulepath *unistring)

// GetModByIndex returns the start address of module located at i in the load order. This might be useful if there is a function you need that isn't in ntdll, or if some rude individual has loaded themselves before ntdll.
func GetModByIndex(i int) (start uintptr, size uintptr, modulepath string) {
	var badstring *unistring
	start, size, badstring = getModByIndex(i)
	modulepath = badstring.String()
	return
}

type unistring struct {
	Length    uint16
	MaxLength uint16
	PWstr     *uint16
}

func (s unistring) String() string {
	return windows.UTF16PtrToString(s.PWstr)
}

func Test() {
	i := 0
	println("[!] Walking PEB...")
	for {
		start, size, p := GetModByIndex(i)
		if p == "" {
			break
		}
		fmt.Printf("[+] %s: 0x%x - 0x%x\n", p, start, start+size)
		mbi, err := getProt(start + 0x1000)
		if err != nil {
			fmt.Println(err)
		}
		a := (mbi.Protect & windows.PAGE_GUARD) > 0
		fmt.Printf("    Protect: 0x%x, PAGE_GUARD: %t\n", mbi.Protect, a)
		i++
	}
}

func getMod(name string) (start uintptr, size uintptr, modulepath string) {
	_, _, p := GetModByIndex(0)
	base := p
	i := 1
	for {
		s, si, p := GetModByIndex(i)
		if p == "" {
			break
		}
		// asis := filepath.Base(p)
		// up := strings.ToUpper(asis)
		// low := strings.ToLower(asis)
		if p != "" {

			// if strings.EqualFold(filepath.Base(p), name) || d.c.Hasher(up) == name || d.c.Hasher(low) == name || d.c.Hasher(asis) == name {
			if strings.EqualFold(filepath.Base(p), name) {
				return s, si, p
			}
			if p == base {
				break
			}
			i++
		}

	}
	return 0, 0, ""
}

// ///////////////////////////////////////////////////////////

type MEMORY_BASIC_INFORMATION struct {
	BaseAddress       uintptr
	AllocationBase    uintptr
	AllocationProtect uint32
	PartitionId       uint16
	_                 uint16
	RegionSize        uintptr
	State             uint32
	Protect           uint32
	Type              uint32
}

func getProt(base uintptr) (*windows.MemoryBasicInformation, error) {
	var mbi windows.MemoryBasicInformation
	hProc := windows.CurrentProcess()
	err := windows.VirtualQueryEx(
		hProc,
		base,
		&mbi,
		unsafe.Sizeof(mbi),
	)
	if err != nil {
		return nil, err
	}
	return &mbi, nil

}
