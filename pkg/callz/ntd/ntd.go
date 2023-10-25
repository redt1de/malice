package ntd

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"github.com/redt1de/malice/pkg/callz"
	"github.com/redt1de/malice/pkg/callz/hashers"
	"github.com/redt1de/malice/pkg/pe"
)

const (
	RESOLVER_MEM    = 0
	RESOLVER_DISK   = 1
	RESOLVER_EXCEPT = 2
)

var GADGET_SYSCALL_RET = []byte{0x0f, 0x05, 0xc3}

type NtDll struct {
	Start uintptr
	Size  uintptr
	Pe    *pe.File
	cfg   *callz.CallerCFG
}

// Get address to dll function without calling any windows api functions like GetProcAddress
type NtProc struct {
	Name string
	addr uintptr
	dll  *NtDll
}

func NewNtDll(opts ...callz.CallerOpt) *NtDll {
	var err error
	var peFile *pe.File
	var image []byte
	cf := &callz.CallerCFG{
		Resolver: RESOLVER_MEM,
		Hasher:   hashers.None,
	}
	for _, opt := range opts {
		opt(cf)
	}

	start, size := GetNtdll()
	switch cf.Resolver {
	case RESOLVER_MEM:
		peFile, err = pe.NewFileFromMemory(start, int(size))
		if err != nil {
			panic("failed to load data:" + err.Error())
		}
	case RESOLVER_DISK:
		image, err = os.ReadFile(string([]byte{'C', ':', '\\', 'W', 'i', 'n', 'd', 'o', 'w', 's', '\\', 'S', 'y', 's', 't', 'e', 'm', '3', '2', '\\', 'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l'}))
		if err != nil {
			panic("failed to load data:" + err.Error())
		}
		peFile, err = pe.NewFile(bytes.NewReader(image))
		if err != nil {
			panic("failed to load data:" + err.Error())
		}
	}

	return &NtDll{
		Start: start,
		Size:  size,
		Pe:    peFile,
		cfg:   cf,
	}
}

// GetNtdll returns the start and size of ntdll
func GetNtdll() (start uintptr, size uintptr)

// func getModByIndex(i int) (start uintptr, size uintptr)

// GetSSN does the heavy lifting - will resolve a name or ordinal into a sysid by getting exports, and parsing the first few bytes of the function to extract the ID. Doens't look at the ord value unless useOrd is set to true.
func (n *NtDll) GetSSN(funcname string) (uint16, error) {
	ex, e := n.Pe.Exports()
	if e != nil {
		return 0, e
	}

	for _, exp := range ex {
		// println(funcname, "vs", exp.Name)
		if n.cfg.Hasher(exp.Name) == funcname || exp.Name == funcname {
			offset := rvaToOffset(n.Pe, exp.VirtualAddress)
			bBytes, e := n.Pe.Bytes() // on sentinelOne box, this panics.Exception: 0x80000001 == STATUS_GUARD_PAGE_VIOLATION
			if e != nil {
				return 0, e
			}
			buff := bBytes[offset : offset+10]

			sysId, e := sysIDFromRawBytes(buff)

			var err MayBeHookedError
			// Look for the syscall ID in the neighborhood
			if errors.As(e, &err) {
				// big thanks to @nodauf for implementing the halos gate logic
				// start, size := GetNtdll()
				distanceNeighbor := 0
				// Search forward
				for i := uintptr(offset); i < n.Start+n.Size; i += 1 {
					if bBytes[i] == byte('\x0f') && bBytes[i+1] == byte('\x05') && bBytes[i+2] == byte('\xc3') {
						distanceNeighbor++
						// The sysid should be located 14 bytes after the syscall; ret instruction.
						sysId, e := sysIDFromRawBytes(bBytes[i+14 : i+14+8])
						if !errors.As(e, &err) {
							return sysId - uint16(distanceNeighbor), e
						}
					}
				}
				// reset the value to 1. When we go forward we catch the current syscall; ret but not when we go backward, so distanceNeighboor = 0 for forward and distanceNeighboor = 1 for backward
				distanceNeighbor = 1
				// If nothing has been found forward, search backward
				for i := uintptr(offset) - 1; i > 0; i -= 1 {
					if bBytes[i] == byte('\x0f') && bBytes[i+1] == byte('\x05') && bBytes[i+2] == byte('\xc3') {
						distanceNeighbor++
						// The sysid should be located 14 bytes after the syscall; ret instruction.
						sysId, e := sysIDFromRawBytes(bBytes[i+14 : i+14+8])
						if !errors.As(e, &err) {
							return sysId + uint16(distanceNeighbor) - 1, e
						}
					}
				}
			} else {
				return sysId, e
			}
		}
	}
	return 0, errors.New("could not find syscall ID")
}

// rvaToOffset converts an RVA value from a PE file into the file offset. When using binject/debug, this should work fine even with in-memory files.
func rvaToOffset(pefile *pe.File, rva uint32) uint32 {
	for _, hdr := range pefile.Sections {
		baseoffset := uint64(rva)
		if baseoffset > uint64(hdr.VirtualAddress) &&
			baseoffset < uint64(hdr.VirtualAddress+hdr.VirtualSize) {
			return rva - hdr.VirtualAddress + hdr.Offset
		}
	}
	return rva
}

// sysIDFromRawBytes takes a byte slice and determines if there is a sysID in the expected location. Returns a MayBeHookedError if the signature does not match.
func sysIDFromRawBytes(b []byte) (uint16, error) {
	if !bytes.HasPrefix(b, HookCheck) {
		return 0, MayBeHookedError{Foundbytes: b}
	}
	if b[4] == 0xe9 { // tartarus gate
		return 0, MayBeHookedError{Foundbytes: b}
	}
	return binary.LittleEndian.Uint16(b[4:8]), nil
}

// HookCheck is the bytes expected to be seen at the start of the function:
var HookCheck = []byte{0x4c, 0x8b, 0xd1, 0xb8}

// MayBeHookedError an error returned when trying to extract the sysid from a resolved function. Contains the bytes that were actually found (incase it's useful to someone?)
type MayBeHookedError struct {
	Foundbytes []byte
}

func (e MayBeHookedError) Error() string {
	return fmt.Sprintf("maybe EDRish: wanted %x got %x", HookCheck, e.Foundbytes)
}

func IsHooked(addr uintptr) bool {
	readmem := unsafe.Slice((*byte)(unsafe.Pointer(addr)), 4)
	return !bytes.Equal(readmem, HookCheck)
}

func getTrampoline(exportAddr uintptr) uintptr

// GetTRampolines returns the address of a clean syscall;ret gadget. Intentionally searches in syscall stubs != to the syscall we are calling, like SysWhispers3
func (n *NtDll) GetTrampoline(notfunc string) uintptr {
	ex, e := n.Pe.Exports()
	if e != nil {
		return 0
	}
	for _, exp := range ex {
		if exp.Name != notfunc && n.cfg.Hasher(exp.Name) != notfunc { // avoid the syscall we're using
			// tramp := getTrampoline(n.Start + uintptr(exp.VirtualAddress))
			tramp := n.FindGadget(GADGET_SYSCALL_RET)
			if tramp != 0 {
				return tramp
			}
		}
	}
	return 0
}

// NewProc mimics windows.NewLazyDLL().NewProc() but does so without any windows api functions like GetProcAddress
func (u *NtDll) NewProc(name string) *NtProc {
	ret := &NtProc{Name: name, dll: u}

	ex, e := u.Pe.Exports()
	if e != nil {
		return nil
	}

	for _, exp := range ex {
		if exp.Name == name || u.cfg.Hasher(exp.Name) == name {
			ret.addr = u.Start + uintptr(exp.VirtualAddress)
			return ret
		}
	}
	panic(name + " not found in ntd")
}

// Addr mimics windows.NewLazyDLL().NewProc().Addr()
func (pr *NtProc) Addr() uintptr {
	return pr.addr
}

// Call mimics windows.NewLazyDLL().NewProc().Call()
func (p *NtProc) Call(a ...uintptr) (r1, r2 uintptr, lastErr error) {
	switch len(a) {
	case 0:
		return syscall.Syscall(p.Addr(), uintptr(len(a)), 0, 0, 0)
	case 1:
		return syscall.Syscall(p.Addr(), uintptr(len(a)), a[0], 0, 0)
	case 2:
		return syscall.Syscall(p.Addr(), uintptr(len(a)), a[0], a[1], 0)
	case 3:
		return syscall.Syscall(p.Addr(), uintptr(len(a)), a[0], a[1], a[2])
	case 4:
		return syscall.Syscall6(p.Addr(), uintptr(len(a)), a[0], a[1], a[2], a[3], 0, 0)
	case 5:
		return syscall.Syscall6(p.Addr(), uintptr(len(a)), a[0], a[1], a[2], a[3], a[4], 0)
	case 6:
		return syscall.Syscall6(p.Addr(), uintptr(len(a)), a[0], a[1], a[2], a[3], a[4], a[5])
	case 7:
		return syscall.Syscall9(p.Addr(), uintptr(len(a)), a[0], a[1], a[2], a[3], a[4], a[5], a[6], 0, 0)
	case 8:
		return syscall.Syscall9(p.Addr(), uintptr(len(a)), a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], 0)
	case 9:
		return syscall.Syscall9(p.Addr(), uintptr(len(a)), a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8])
	case 10:
		return syscall.Syscall12(p.Addr(), uintptr(len(a)), a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], 0, 0)
	case 11:
		return syscall.Syscall12(p.Addr(), uintptr(len(a)), a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10], 0)
	case 12:
		return syscall.Syscall12(p.Addr(), uintptr(len(a)), a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10], a[11])
	case 13:
		return syscall.Syscall15(p.Addr(), uintptr(len(a)), a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10], a[11], a[12], 0, 0)
	case 14:
		return syscall.Syscall15(p.Addr(), uintptr(len(a)), a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10], a[11], a[12], a[13], 0)
	case 15:
		return syscall.Syscall15(p.Addr(), uintptr(len(a)), a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10], a[11], a[12], a[13], a[14])
	default:
		panic("Call " + p.Name + " with too many arguments ")
	}
}

// FindGadget searches the module for a sequence of bytes (gadget), i.e. syscall;ret
func (d *NtDll) FindGadget(bmask []byte) uintptr {
	for _, s := range d.Pe.Sections {
		if s.Name == ".text" {
			searchStart := uintptr(s.VirtualAddress) + d.Start
			dat, _ := s.Data()
			match := bytes.Index(dat, bmask)
			return searchStart + uintptr(match)
		}
	}
	return 0
}
