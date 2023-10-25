package direct

import (
	"github.com/redt1de/malice/pkg/callz"
	"github.com/redt1de/malice/pkg/callz/hashers"
	"github.com/redt1de/malice/pkg/callz/ntd"
)

// https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop
// https://labs.en1gma.co/malwaredevelopment/evasion/security/2023/08/14/syscalls.html

type Direct struct {
	Name  string
	SysID uint16
	cfg   *callz.CallerCFG
	ntd   *ntd.NtDll
}

type DirectCaller struct {
	c   *callz.CallerCFG
	ntd *ntd.NtDll
}

// New returns a new DirectCaller, specify hasher and resolvers here.
func New(opts ...callz.CallerOpt) *DirectCaller {
	cf := &callz.CallerCFG{
		Resolver: ntd.RESOLVER_MEM,
		Hasher:   hashers.None,
	}
	for _, opt := range opts {
		opt(cf)
	}
	n := ntd.NewNtDll(opts...)
	return &DirectCaller{c: cf, ntd: n}
}

// Call mimics windows.NewLazyDLL().NewProc().Call()
func (i *Direct) Call(ag ...uintptr) (uintptr, uintptr, error) {
	err := doCall(i.SysID, ag...)
	return uintptr(err), 0, nil
}

// NewProc mimics windows.NewLazyDLL().NewProc()
func (d *DirectCaller) NewProc(proc string) *Direct {
	var err error
	ret := &Direct{Name: proc, cfg: d.c, ntd: d.ntd}

	ret.SysID, err = d.ntd.GetSSN(proc)
	if err != nil {
		panic("failed to get id:" + err.Error())
	}
	return ret
}

func doCall(callid uint16, argh ...uintptr) (errcode uint32)
