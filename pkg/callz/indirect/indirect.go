package indirect

import (
	"github.com/redt1de/malice/pkg/callz"
	"github.com/redt1de/malice/pkg/callz/hashers"
	"github.com/redt1de/malice/pkg/callz/ntd"
)

// References:
// https://github.com/susMdT/go-indirect/

type Indirect struct {
	Name  string
	SysID uint16
	tramp uintptr
	cfg   *callz.CallerCFG
	ntd   *ntd.NtDll
}

type InDirectCaller struct {
	c   *callz.CallerCFG
	ntd *ntd.NtDll
}

// New returns a new IndirectCaller, specify hasher and resolvers here.
func New(opts ...callz.CallerOpt) *InDirectCaller {
	cf := &callz.CallerCFG{
		Resolver: ntd.RESOLVER_MEM,
		Hasher:   hashers.None,
	}
	for _, opt := range opts {
		opt(cf)
	}
	n := ntd.NewNtDll(opts...)
	return &InDirectCaller{c: cf, ntd: n}
}

// Call mimics windows.NewLazyDLL().NewProc().Call()
func (i *Indirect) Call(ag ...uintptr) (uintptr, uintptr, error) {
	ret := doCall(i.SysID, i.tramp, ag...)
	return uintptr(ret), 0, nil
}

// func (i *Indirect) FancyCall(ag ...uintptr) (uintptr, uintptr, error) {
// 	tramp2 := findRetGadget()
// 	// fmt.Printf("k32tramp ret gadget: 0x%x\n", tramp2)
// 	// fmt.Printf("syscall;ret gadget: 0x%x\n", i.tramp)
// 	ret := doFancyCall(i.SysID, i.tramp, tramp2, ag...)
// 	return uintptr(ret), 0, nil
// }

// func findRetGadget() uintptr {
// 	ret := callz.FindInModule("kernel32.dll", callz.GADGET_ADD_RSP_78_RET)
// 	if ret == 0 {
// 		ret = callz.FindInModule("kernelbase.dll", callz.GADGET_ADD_RSP_78_RET)
// 		if ret == 0 {
// 			panic("ret gadget not found")
// 		}
// 	}

// 	return ret
// }

// NewProc mimics windows.NewLazyDLL().NewProc()
func (d *InDirectCaller) NewProc(proc string) *Indirect {
	var err error
	ret := &Indirect{Name: proc, cfg: d.c, ntd: d.ntd}

	ret.SysID, err = d.ntd.GetSSN(proc)
	if err != nil {
		panic("failed to get id:" + err.Error())
	}
	ret.tramp = d.ntd.GetTrampoline(proc)

	return ret
}

// ///////////////////////////////////////////////////////////////////////////////
// stub for asm implementation
func cleanup()
func doCall(ssn uint16, syscall_ret_tramp uintptr, argh ...uintptr) uint32
func doFancyCall(ssn uint16, syscall_ret_tramp uintptr, add_rsp_68_ret_tramp uintptr, argh ...uintptr) uint32 // <<<< for testing synthetic stack stuffs
