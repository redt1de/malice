package proxycall

import (
	"reflect"
	"unsafe"

	"github.com/redt1de/malice/pkg/callz"
	"github.com/redt1de/malice/pkg/callz/hashers"
	"github.com/redt1de/malice/pkg/callz/ntd"
	"golang.org/x/sys/windows"
)

// References:
// https://github.com/timwhitez/Doge-Gabh/tree/main/pkg/proxycall

var HashFunc func(string) string

type ProxyArgs struct {
	Addr    uintptr
	ArgsLen uintptr
	Args1   uintptr
	Args2   uintptr
	Args3   uintptr
	Args4   uintptr
	Args5   uintptr
	Args6   uintptr
	Args7   uintptr
	Args8   uintptr
	Args9   uintptr
	Args10  uintptr
}

type Proxy struct {
	addr   uintptr
	Config *callz.CallerCFG
	ntd    *ntd.NtDll
}

type ProxyCaller struct {
	c   *callz.CallerCFG
	ntd *ntd.NtDll
}

// returns a new ProxyCaller, specify hasher and resolvers here. This implementation is unreliable, needs work.
func New(opts ...callz.CallerOpt) *ProxyCaller {
	cf := &callz.CallerCFG{
		// Resolver: callz.SSN_MEM,
		Hasher: hashers.None,
	}
	for _, opt := range opts {
		opt(cf)
	}
	n := ntd.NewNtDll(opts...)
	return &ProxyCaller{c: cf, ntd: n}
}

// Call mimics windows.NewLazyDLL().NewProc().Call()
func (p *Proxy) Call(ag ...uintptr) (uintptr, uintptr, error) {
	a := pSa(p.addr, ag...)
	p.pCwS(a)
	return 0, 0, nil
}

func (p *Proxy) Addr() uintptr {
	return p.addr
}

func (d *ProxyCaller) NewProc(proc string) *Proxy {
	return &Proxy{
		ntd:    d.ntd,
		Config: d.c,
		addr:   d.ntd.NewProc(proc).Addr(),
		// addr:= darklib.New(callz.WithConfig(d.c)).NotLazyDLL(string([]byte{'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l'})).NewProc(proc).Addr(),
	}
}

func (d *Proxy) pCwS(Args0 uintptr) {
	egg := []byte{0x52, 0x33, 0x64, 0x54, 0x31, 0x64, 0x65} // R3dT1de egg
	addr := reflect.ValueOf(proxyTag).Pointer()             // address to function that calls asm function

	BaseAddr := addr
	addr = findTag(egg, BaseAddr) // search for the asm func to handle args, returns start of hex asm. i.e. address to asmfunc past the egg.

	// cllr := darklib.New(callz.WithHasher(hashers.Djb2))
	// notnt := cllr.NewDarkDll("377d2b522d3b5ed")
	// pTpAllocWork := notnt.NewProc("c02905e335829537")
	// pTpPostWork := notnt.NewProc("726dd9f9c94fc392")
	// pTpReleaseWork := notnt.NewProc("6edd6407cb60d48d")

	pTpAllocWork := d.ntd.NewProc(string([]byte{'T', 'p', 'A', 'l', 'l', 'o', 'c', 'W', 'o', 'r', 'k'}))
	pTpPostWork := d.ntd.NewProc(string([]byte{'T', 'p', 'P', 'o', 's', 't', 'W', 'o', 'r', 'k'}))
	pTpReleaseWork := d.ntd.NewProc(string([]byte{'T', 'p', 'R', 'e', 'l', 'e', 'a', 's', 'e', 'W', 'o', 'r', 'k'}))

	WorkReturn := uintptr(0)
	pTpAllocWork.Call(uintptr(unsafe.Pointer(&WorkReturn)), addr, Args0, 0)

	pTpPostWork.Call(WorkReturn)

	pTpReleaseWork.Call(WorkReturn)
	windows.WaitForSingleObject(0xffffffffffffffff, 0x200)
}

func pSa(Addr uintptr, Args ...uintptr) uintptr {
	newArgs := ProxyArgs{}
	newArgs.Addr = Addr
	if Args == nil {
		newArgs.ArgsLen = 0
		return uintptr(unsafe.Pointer(&newArgs))
	}
	if len(Args) > 10 {
		panic("Too much args")
	}
	len0 := len(Args)
	newArgs.ArgsLen = uintptr(len0)

	pArgs := &newArgs
	value := reflect.ValueOf(pArgs).Elem()
	for i := 0; i < len0; i++ {
		if value.Field(i).CanSet() {
			ptr := unsafe.Pointer(value.Field(i + 2).UnsafeAddr())
			*(*uintptr)(ptr) = Args[i]
		}
	}
	return uintptr(unsafe.Pointer(&newArgs))
}

func findTag(egg []byte, startAddress uintptr) uintptr {
	var currentOffset = uintptr(0)
	currentAddress := startAddress
	for {
		currentOffset++
		currentAddress = startAddress + currentOffset
		if memcmp(unsafe.Pointer(&egg[0]), unsafe.Pointer(currentAddress), 7) == 0 {
			return currentAddress + 7
		}
	}
}

func memcmp(dest, src unsafe.Pointer, len uintptr) int {
	cnt := len >> 3
	var i uintptr = 0
	for i = 0; i < cnt; i++ {
		var pdest *uint64 = (*uint64)(unsafe.Pointer(uintptr(dest) + uintptr(8*i)))
		var psrc *uint64 = (*uint64)(unsafe.Pointer(uintptr(src) + uintptr(8*i)))
		switch {
		case *pdest < *psrc:
			return -1
		case *pdest > *psrc:
			return 1
		default:
		}
	}

	left := len & 7
	for i = 0; i < left; i++ {
		var pdest *uint8 = (*uint8)(unsafe.Pointer(uintptr(dest) + uintptr(8*cnt+i)))
		var psrc *uint8 = (*uint8)(unsafe.Pointer(uintptr(src) + uintptr(8*cnt+i)))
		switch {
		case *pdest < *psrc:
			return -1
		case *pdest > *psrc:
			return 1
		default:
		}
	}
	return 0
}

func proxyTag() {
	pC()
}

func pC()
