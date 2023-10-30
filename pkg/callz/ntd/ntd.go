package ntd

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"github.com/redt1de/malice/pkg/callz"
	"github.com/redt1de/malice/pkg/callz/hashers"
	"github.com/redt1de/malice/pkg/mem"
	"github.com/redt1de/malice/pkg/pe"
	"github.com/redt1de/malice/pkg/peb"
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

func GetNtdll() (start uintptr, size uintptr) {
	i := 0
	for {
		start, size, p := peb.GetModByIndex(i)
		if p == "" {
			break
		}
		p = strings.ToLower(filepath.Base(p))
		p = hashers.Djb2(p)
		if p == "377d2b522d3b5ed" {
			return start, size
		}
		i++
	}
	return 0, 0
}

// new version of getssn, moving away from debug/pe since S1 causes issues. needs testing.
func (n *NtDll) GetSSN(name string) (uint16, error) {
	baseAddr := n.Start
	exportsBaseAddr := peb.GetExportsDirAddr(baseAddr)
	numberOfNames := peb.GetNumberOfNames(exportsBaseAddr)
	addressOfFunctions := peb.GetAddressOfFunctions(baseAddr, exportsBaseAddr)
	addressOfNames := peb.GetAddressOfNames(baseAddr, exportsBaseAddr)
	addressOfNameOrdinals := peb.GetAddressOfNameOrdinals(baseAddr, exportsBaseAddr)
	for i := uint32(0); i < numberOfNames; i++ {
		fn := mem.ReadCString(baseAddr, mem.ReadDwordAtOffset(addressOfNames, i*4))
		if string(fn) == name || n.cfg.Hasher(string(fn)) == name {
			nameOrd := mem.ReadWordAtOffset(addressOfNameOrdinals, i*2)
			rva := mem.ReadDwordAtOffset(addressOfFunctions, uint32(nameOrd*4))
			fnAddr := peb.Rva2Va(baseAddr, rva)
			bBytes := *(*[]byte)(unsafe.Pointer(fnAddr))
			buff := unsafe.Slice((*byte)(unsafe.Pointer(&bBytes)), 10)
			sysId, e := sysIDFromRawBytes(buff)
			var err MayBeHookedError
			// Look for the syscall ID in the neighborhood
			if errors.As(e, &err) {
				// big thanks to @nodauf for implementing the halos gate logic
				distanceNeighbor := 0
				// Search forward
				for i := uintptr(fnAddr); i < n.Start+n.Size-32; i += 1 {
					bBytes := *(*[]byte)(unsafe.Pointer(i))
					buf := unsafe.Slice((*byte)(unsafe.Pointer(&bBytes)), 32)
					if buf[0] == byte('\x0f') && buf[1] == byte('\x05') && buf[2] == byte('\xc3') {
						distanceNeighbor++
						// The sysid should be located 14 bytes after the syscall; ret instruction.
						sysId, e := sysIDFromRawBytes(buf[14 : 14+8])
						if !errors.As(e, &err) {
							return sysId - uint16(distanceNeighbor), e
						}
					}
				}
				// reset the value to 1. When we go forward we catch the current syscall; ret but not when we go backward, so distanceNeighboor = 0 for forward and distanceNeighboor = 1 for backward
				distanceNeighbor = 1
				// If nothing has been found forward, search backward
				for i := uintptr(fnAddr) - 1; i > 0; i -= 1 {
					bBytes := *(*[]byte)(unsafe.Pointer(i))
					buf := unsafe.Slice((*byte)(unsafe.Pointer(&bBytes)), 32)
					if buf[i] == byte('\x0f') && buf[i+1] == byte('\x05') && buf[i+2] == byte('\xc3') {
						distanceNeighbor++
						// The sysid should be located 14 bytes after the syscall; ret instruction.
						sysId, e := sysIDFromRawBytes(buf[14 : 14+8])
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

func (u *NtDll) NewProc(name string) *NtProc {
	ret := &NtProc{Name: name, dll: u}
	baseAddr := u.Start
	exportsBaseAddr := peb.GetExportsDirAddr(baseAddr)
	numberOfNames := peb.GetNumberOfNames(exportsBaseAddr)
	addressOfFunctions := peb.GetAddressOfFunctions(baseAddr, exportsBaseAddr)
	addressOfNames := peb.GetAddressOfNames(baseAddr, exportsBaseAddr)
	addressOfNameOrdinals := peb.GetAddressOfNameOrdinals(baseAddr, exportsBaseAddr)
	for i := uint32(0); i < numberOfNames; i++ {
		fn := mem.ReadCString(baseAddr, mem.ReadDwordAtOffset(addressOfNames, i*4))
		if string(fn) == name || u.cfg.Hasher(string(fn)) == name {
			nameOrd := mem.ReadWordAtOffset(addressOfNameOrdinals, i*2)
			rva := mem.ReadDwordAtOffset(addressOfFunctions, uint32(nameOrd*4))
			ret.addr = peb.Rva2Va(baseAddr, rva)
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
