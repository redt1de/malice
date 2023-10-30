package mem

import "unsafe"

func ReadDwordAtOffset(start uintptr, offset uint32) uint32
func ReadWordAtOffset(start uintptr, offset uint32) uint16
func ReadByteAtOffset(start uintptr, offset uint32) byte
func ReadQwordAtOffset(start uintptr, offset uint32) byte
func ReadQword(addr uintptr) uintptr

func ReadCString(start uintptr, offset uint32) []byte {
	var buf []byte
	for {
		ch := ReadByteAtOffset(start, offset)
		if ch == 0 {
			break
		}
		buf = append(buf, ch)
		offset++
	}
	return buf
}

// WriteMemory is a non system call mem write func. Does **not** check permissions, may cause panic if memory is not writable etc. https://github.com/timwhitez/Doge-Misc/blob/main/writeMem.go
func Write(inbuf []byte, destination uintptr) {
	for index := uint32(0); index < uint32(len(inbuf)); index++ {
		writePtr := unsafe.Pointer(destination + uintptr(index))
		v := (*byte)(writePtr)
		*v = inbuf[index]
	}
}

// ReadMemory
func Read(addr uintptr, readLen int) []byte {
	readmem := unsafe.Slice((*byte)(unsafe.Pointer(addr)), readLen)
	return readmem
}
