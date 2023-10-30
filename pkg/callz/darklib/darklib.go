package darklib

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/redt1de/malice/pkg/callz"
	"github.com/redt1de/malice/pkg/callz/hashers"
	"github.com/redt1de/malice/pkg/mem"
	"github.com/redt1de/malice/pkg/pe"
	"github.com/redt1de/malice/pkg/peb"
)

var (
	GADGET_SYSCALL_RET    = []byte{0x0f, 0x05, 0xc3}
	GADGET_ADD_RSP_68_RET = []byte{0x48, 0x83, 0xC4, 0x68, 0xC3}
	GADGET_ADD_RSP_78_RET = []byte{0x48, 0x83, 0xC4, 0x78, 0xC3}
	GADGET_JMP_RBX        = []byte{0xff, 0x23}
)

const (
	RESOLVER_MEM    = 0
	RESOLVER_DISK   = 1
	RESOLVER_EXCEPT = 2
)

// References:
// https://github.com/C-Sto/BananaPhone/
// golang.org/x/sys/windows

// Get dll without calling any windows api functions like LoadLibrary
type DarkDll struct {
	Name  string
	Start uintptr
	Size  uintptr
	Pe    *pe.File
	cfg   *callz.CallerCFG
}

// Get address to dll function without calling any windows api functions like GetProcAddress
type DarkProc struct {
	Name string
	addr uintptr
	dll  *DarkDll
}

type DarkCaller struct {
	c *callz.CallerCFG
}

func TestOpt(c *callz.CallerCFG) {
	c.Opts["test"] = true
}

// New returns a new darklib caller. specify hasher here, or use default (hashers.None). Does not make use of resolvers since they are mainly for SSNs. I may add functionalily in the future for options to load from disk/remote
func New(opts ...callz.CallerOpt) *DarkCaller {
	cf := &callz.CallerCFG{
		Resolver: RESOLVER_MEM,
		Hasher:   hashers.None,
		Opts:     make(map[string]interface{}),
	}
	for _, opt := range opts {
		opt(cf)
	}

	return &DarkCaller{c: cf}
}

// NotLazyDll mimics windows.NewLazyDLL() without any calls to LoadLibrary or GetProcAddress. returns nil if DLL is not found in memory.
func (d *DarkCaller) NewDarkDll(name string) *DarkDll {
	var err error
	var peFile *pe.File
	var image []byte
	start, size, p := d.getMod(name)
	if start == 0 {
		return nil
		panic("failed to find dll by name or hash:" + name)
	}

	switch d.c.Resolver {
	case RESOLVER_MEM:
		peFile, err = pe.NewFileFromMemory(start, int(size))
		if err != nil {
			return nil
			// panic(err)
		}

	case RESOLVER_DISK:
		image, err = os.ReadFile(name)
		if err != nil {
			try := string([]byte{'C', ':', '\\', 'W', 'i', 'n', 'd', 'o', 'w', 's', '\\', 'S', 'y', 's', 't', 'e', 'm', '3', '2', '\\'})
			image, err = os.ReadFile(try + name)
			if err != nil {
				return nil
				//panic("failed to load data:" + err.Error())
			}
		}
		peFile, err = pe.NewFile(bytes.NewReader(image))
		if err != nil {
			return nil
			// panic("failed to load data:" + err.Error())
		}
	}
	return &DarkDll{
		Name:  filepath.Base(p),
		Size:  size,
		Start: start,
		cfg:   d.c,
		Pe:    peFile,
	}
}

func (d *DarkCaller) MustDarkLoadDLL(fpath string) *DarkDll {
	ret := d.DarkLoadDLL(fpath)
	if ret == nil {
		panic("failed to load dll:" + fpath)
	}
	return ret
}

// DarkLoadDll performs a DarkLoadLibrary. Does not link to PEB yet
func (d *DarkCaller) DarkLoadDLL(fpath string) *DarkDll {
	var image []byte
	var err error
	name := filepath.Base(fpath)
	switch d.c.Resolver {
	case RESOLVER_MEM:
		panic("darkloadlib from mem not implemented")
	case RESOLVER_DISK:
		image, err = os.ReadFile(fpath)
		if err != nil {
			try := string([]byte{'C', ':', '\\', 'W', 'i', 'n', 'd', 'o', 'w', 's', '\\', 'S', 'y', 's', 't', 'e', 'm', '3', '2', '\\'})
			image, err = os.ReadFile(try + name)
			if err != nil {
				return nil
				//panic("failed to load data:" + err.Error())
			}
		}
	}

	if len(image) == 0 {
		return nil
	}
	ret, err := d.LoadLibrary(&image, name)
	if err != nil || ret.Start == 0 {
		return nil
	}
	return ret
}

// Handle mimics windows.NewLazyDLL().Handle()
func (u *DarkDll) Handle() uintptr {
	return u.Start
}

func (u *DarkDll) MustFindProc(name string) *DarkProc {
	ret := u.NewProc(name)
	if ret == nil {
		panic("failed to find proc:" + name)
	}
	return ret
}

func (u *DarkDll) FindProc(name string) *DarkProc {
	ret := u.NewProc(name)
	return ret
}

// NewProc mimics windows.NewLazyDLL().NewProc() but does so without any windows api functions like GetProcAddress
func (u *DarkDll) NewProc(name string) *DarkProc {
	ret := &DarkProc{Name: name, dll: u}
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
	return nil
}

// Addr mimics windows.NewLazyDLL().NewProc().Addr()
func (pr *DarkProc) Addr() uintptr {
	return pr.addr
}

// Call mimics windows.NewLazyDLL().NewProc().Call()
func (p *DarkProc) Call(a ...uintptr) (r1, r2 uintptr, lastErr error) {
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

// getMod is the wrapper around the asm funcs to walk the module list in PEB
func (d *DarkCaller) getMod(name string) (start uintptr, size uintptr, modulepath string) {
	_, _, p := peb.GetModByIndex(0)
	base := p
	i := 1
	for {
		s, si, p := peb.GetModByIndex(i)
		if p == "" {
			break
		}
		asis := filepath.Base(p)
		up := strings.ToUpper(asis)
		low := strings.ToLower(asis)
		if p != "" {
			if strings.EqualFold(filepath.Base(p), name) || d.c.Hasher(up) == name || d.c.Hasher(low) == name || d.c.Hasher(asis) == name {
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

// FindGadget searches the module for a sequence of bytes (gadget), i.e. syscall;ret
func (d *DarkDll) FindGadget(bmask []byte) uintptr {
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

func (d *DarkCaller) IsModuleLoaded(name string) bool {
	s, _, _ := d.getMod(name)
	return s != 0
}
