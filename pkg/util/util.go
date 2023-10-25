package util

import "unsafe"

func ReadMemory(addr uintptr, readLen int) []byte {
	readmem := unsafe.Slice((*byte)(unsafe.Pointer(addr)), readLen)
	return readmem
}
