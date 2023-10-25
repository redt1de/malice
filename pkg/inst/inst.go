package inst

import (
	"fmt"
	"unsafe"

	"github.com/redt1de/malice/pkg/callz"
	"github.com/redt1de/malice/pkg/callz/hashers"
	"github.com/redt1de/malice/pkg/callz/ntd"
)

// References:
// https://github.com/jackullrich/syscall-detect/blob/master/main.cpp
// https://github.com/timwhitez/Etwti-UnhookPOC

const ProcessInstrumentationCallback = 0x28

var (
	n                       = ntd.NewNtDll(callz.WithHasher(hashers.Djb2))
	NtSetInformationProcess = n.NewProc("a896fd51bb7a48b8")
)

type PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION struct {
	Version  uint32
	Reserved uint32
	Callback uintptr
}

func RemoveInstrumentationCallback() {
	var cbInfo PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION
	cbInfo.Version = 0
	cbInfo.Reserved = 0
	cbInfo.Callback = 0

	r, _, _ := NtSetInformationProcess.Call(
		uintptr(0xffffffffffffffff),
		ProcessInstrumentationCallback,
		uintptr(unsafe.Pointer(&cbInfo)),
		unsafe.Sizeof(cbInfo))
	if r != 0 {
		fmt.Printf("0x%x\n", r)
	}

}

func SetInstrumentationCallback(callback uintptr) {
	var cbInfo PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION
	cbInfo.Version = 0
	cbInfo.Reserved = 0
	cbInfo.Callback = callback

	r, _, _ := NtSetInformationProcess.Call(
		uintptr(0xffffffffffffffff),
		ProcessInstrumentationCallback,
		uintptr(unsafe.Pointer(&cbInfo)),
		unsafe.Sizeof(cbInfo))
	if r != 0 {
		fmt.Printf("0x%x\n", r)
	}

}

// func defaultCallback(ctx *CONTEXT) uintptr {
// 	winapi.MessageBox("Instrument", "Hello from the instrumentation callback", uint(winapi.MB_OK))
// }
