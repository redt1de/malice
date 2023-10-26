package check

import (
	"bytes"
	"unsafe"

	"github.com/redt1de/malice/pkg/peb"
)

type WinVer struct {
	OSMajorVersion uint32
	OSMinorVersion uint32
	OSBuildNumber  uint16
	OSCSDVersion   uint16
	OSPlatformId   uint32
}

func GetVersion() WinVer {
	p := peb.GetPEB()
	return WinVer{
		OSMajorVersion: *(*uint32)(unsafe.Pointer(p + uintptr(0x118))),
		OSMinorVersion: *(*uint32)(unsafe.Pointer(p + uintptr(0x11c))),
		OSBuildNumber:  *(*uint16)(unsafe.Pointer(p + uintptr(0x120))),
		OSCSDVersion:   *(*uint16)(unsafe.Pointer(p + uintptr(0x122))),
		OSPlatformId:   *(*uint32)(unsafe.Pointer(p + uintptr(0x124))),
	}
}

func BeingDebugged() bool {
	p := peb.GetPEB()
	b := *(*uint8)(unsafe.Pointer(p + uintptr(0x002)))
	return b != 0
}

func IsHooked(addr uintptr) bool {
	var HookCheck = []byte{0x4c, 0x8b, 0xd1, 0xb8}
	readmem := unsafe.Slice((*byte)(unsafe.Pointer(addr)), 4)
	return !bytes.Equal(readmem, HookCheck)
}

func PrimeSleep(secs int) {
	N := 89999999
	for lp := 0; lp < secs; lp++ {
		b := make([]bool, N)
		for i := 2; i < N; i++ {
			if b[i] {
				continue
			}
			for k := i * i; k < N; k += i {
				b[k] = true
			}
		}
	}
}
