package moonwalk

import (
	"math/rand"

	"github.com/redt1de/malice/pkg/callz"
	"github.com/redt1de/malice/pkg/callz/darklib"
	"github.com/redt1de/malice/pkg/callz/hashers"
	"github.com/redt1de/malice/pkg/callz/ntd"
	"github.com/redt1de/malice/pkg/pe"
)

/*
TODO:
 - moonwalk needs lots of testing, only a few syscalls attempted
*/

// func printf(f string, a ...interface{}) { fmt.Printf(f, a...) }
func doCall(strct *SPOOFER, argh ...uintptr) uint32
func restore() uint32

type Moonwalk struct {
	Name    string
	SysID   uint16
	peFile  *pe.File
	tramp   uintptr
	dll     uintptr
	Config  *callz.CallerCFG
	spoofer *SPOOFER
	ntd     *ntd.NtDll
	// internal caller stuff
	intCaller *darklib.DarkCaller
	intk32    *darklib.DarkDll
	intkb     *darklib.DarkDll
}

type MoonwalkCaller struct {
	c   *callz.CallerCFG
	ntd *ntd.NtDll
	// internal caller stuff
	intCaller *darklib.DarkCaller
	intk32    *darklib.DarkDll
	intkb     *darklib.DarkDll
}

func New(opts ...callz.CallerOpt) *MoonwalkCaller {
	cf := &callz.CallerCFG{
		// Resolver: callz.SSN_MEM,
		Hasher: hashers.None,
	}
	for _, opt := range opts {
		opt(cf)
	}
	n := ntd.NewNtDll(opts...)

	ret := MoonwalkCaller{c: cf, ntd: n}
	ret.intCaller = darklib.New()
	ret.intk32 = ret.intCaller.NewDarkDll("kernel32.dll")
	ret.intkb = ret.intCaller.NewDarkDll("kernelbase.dll")
	return &ret
}

func (d *MoonwalkCaller) NewProc(proc string) *Moonwalk {
	var err error
	ret := &Moonwalk{Name: proc, Config: d.c, spoofer: &SPOOFER{}, ntd: d.ntd}
	ret.SysID, err = d.ntd.GetSSN(proc)
	if err != nil {
		panic("failed to get id:" + err.Error())
	}
	ret.intCaller = d.intCaller
	ret.intk32 = d.intk32
	ret.intkb = d.intkb
	ret.ntd = d.ntd

	e := ret.prepMoonwalk()
	if e != nil {
		panic("failed to prep:" + e.Error())
	}
	return ret
}

// TODO: implement hashing here to hide strings
func (m *Moonwalk) prepMoonwalk() error {
	var stackSize, rtSaveIndex, skip_prolog_frame, skip_pop_rsp_frame, skip_jmp_gadget, skip_stack_pivot_gadget uint32
	var rtTargetOffset uint64
	var stackSizeOf uint32

	// dcallr := darklib.New()
	// kbase := dcallr.NewDarkDll("kernelbase.dll")
	// k32 := dcallr.NewDarkDll("kernel32.dll")
	// ntd := dcallr.NewDarkDll("ntdll.dll")

	pBaseThreadInitThunk := m.intk32.NewProc("BaseThreadInitThunk").Addr()
	f := RTFindFunctionByAddress(m.intk32.Pe, pBaseThreadInitThunk)
	if f != nil {
		unwindInfoAddr := uintptr(f.UnwindData) + m.intk32.Pe.ImageBase
		GetStackFrameSizeIgnoringUwopSetFpreg(m.intk32.Pe, unwindInfoAddr, &stackSizeOf)
		// printf("Function BaseThreadInitThunk found. Stack size: 0x%x - Address: 0x%x\n", stackSizeOf, pBaseThreadInitThunk)

		m.spoofer.BaseThreadInitThunkAddress = pBaseThreadInitThunk
		m.spoofer.BaseThreadInitThunkFrameSize = uintptr(stackSizeOf)
	} else {
		panic("Function BaseThreadInitThunk not found")
	}
	f = nil
	stackSizeOf = 0

	pRtlUserThreadStart := m.ntd.NewProc("RtlUserThreadStart").Addr()
	f = RTFindFunctionByAddress(m.ntd.Pe, pRtlUserThreadStart)
	if f != nil {
		unwindInfoAddr := uintptr(f.UnwindData) + m.ntd.Pe.ImageBase
		GetStackFrameSizeIgnoringUwopSetFpreg(m.ntd.Pe, unwindInfoAddr, &stackSizeOf)
		// printf("Function RtlUserThreadStart found. Stack size: 0x%x - Address: 0x%x\n", stackSizeOf, pRtlUserThreadStart)

		m.spoofer.RtlUserThreadStartAddress = pRtlUserThreadStart
		m.spoofer.RtlUserThreadStartFrameSize = uintptr(stackSizeOf)
	} else {
		panic("Function RtlUserThreadStart not found")
	}

	// m.spoofer.FirstFrameRandomOffset = randOffset()  //0x82  // replace with random later
	m.spoofer.FirstFrameFunctionPointer += randOffset()

	// m.spoofer.SecondFrameRandomOffset = randOffset() //0x25 // replace with random later
	m.spoofer.SecondFrameFunctionPointer += randOffset()

	m.spoofer.FindProlog(m.intkb.Pe, &stackSize, &rtSaveIndex, &skip_prolog_frame, &rtTargetOffset)
	// stackOffsetWhereRbpIsPushed := m.spoofer.FindPushRbp(kbase.PE, &stackSize, &rtSaveIndex, &skip_pop_rsp_frame, &rtTargetOffset)
	m.spoofer.FindPushRbp(m.intkb.Pe, &stackSize, &rtSaveIndex, &skip_pop_rsp_frame, &rtTargetOffset)
	// printf("PUSH RBP offset: 0x%X\n", stackOffsetWhereRbpIsPushed)

	m.spoofer.FindGadget(m.intkb.Pe, &stackSize, &rtSaveIndex, &skip_jmp_gadget, &rtTargetOffset, 0)
	m.spoofer.FindGadget(m.intkb.Pe, &stackSize, &rtSaveIndex, &skip_stack_pivot_gadget, &rtTargetOffset, 1)

	m.spoofer.Ssn = uintptr(m.SysID)

	m.spoofer.SpoofFunctionPointer = m.ntd.GetTrampoline(m.Name)
	return nil
}

func (m *Moonwalk) Call(ag ...uintptr) (uintptr, uintptr, error) {
	ret := doCall(m.spoofer, ag...)
	return uintptr(ret), 0, nil
}

func randOffset() uintptr {
	a := uintptr(rand.Intn(0x9e))
	if a < 0x23 {
		return randOffset()
	}
	return a
}
