package darklib

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"syscall"
	"unsafe"

	"github.com/redt1de/malice/pkg/callz/indirect"
	"github.com/redt1de/malice/pkg/callz/ntd"
	"github.com/redt1de/malice/pkg/pe"
)

// LoadLibraryImpl - loads a single library to memory, without trying to check or load required imports
func (d *DarkCaller) LoadLibrary(image *[]byte, name string) (*DarkDll, error) {
	const PtrSize = 32 << uintptr(^uintptr(0)>>63) // are we on a 32bit or 64bit system?
	pelib, err := pe.NewFile(bytes.NewReader(*image))
	if err != nil {
		return nil, err
	}
	pe64 := pelib.Machine == pe.IMAGE_FILE_MACHINE_AMD64
	if pe64 && PtrSize != 64 {
		return nil, errors.New("Cannot load a 64bit DLL from a 32bit process")
	} else if !pe64 && PtrSize != 32 {
		return nil, errors.New("Cannot load a 32bit DLL from a 64bit process")
	}

	var sizeOfImage uintptr
	if pe64 {
		sizeOfImage = uintptr(pelib.OptionalHeader.(*pe.OptionalHeader64).SizeOfImage)
	} else {
		sizeOfImage = uintptr(pelib.OptionalHeader.(*pe.OptionalHeader32).SizeOfImage)
	}

	r, err := NvA(0, sizeOfImage, MEM_RESERVE, syscall.PAGE_READWRITE)
	if err != nil {
		return nil, err
	}
	dst, err := NvA(r, sizeOfImage, MEM_COMMIT, syscall.PAGE_EXECUTE_READWRITE)

	if err != nil {
		return nil, err
	}

	//perform base relocations
	pelib.Relocate(uint64(dst), image)

	//write to memory
	copySections(pelib, image, dst)

	lib := DarkDll{
		Name:  name,
		Start: dst,
		Size:  sizeOfImage,
		cfg:   d.c,
		Pe:    pelib,
	}
	// LinkModuleToPEB(&lib)
	return &lib, nil
}

var (
	ntdll                 = ntd.NewNtDll()
	ntQst                 = ntdll.NewProc("NtQuerySystemTime")
	pRtlHashUnicodeString = ntdll.NewProc("RtlHashUnicodeString")
	pRtlRbInsertNodeEx    = ntdll.NewProc("RtlRbInsertNodeEx")
)

func LinkModuleToPEB(pdModule *DarkDll) bool {

	pNtHeaders := pdModule.Pe.OptionalHeader.(*pe.OptionalHeader64)

	pLdrEntry := LDR_DATA_TABLE_ENTRY2{}
	fmt.Printf("size of tmp: %d\n", unsafe.Sizeof(pLdrEntry))

	r1, r2, err := ntQst.Call(uintptr(unsafe.Pointer(&pLdrEntry.LoadTime)))
	fmt.Println(r1, r2, err)

	pLdrEntry.ReferenceCount = 1
	pLdrEntry.LoadReason = LoadReasonDynamicLoad
	pLdrEntry.OriginalBase = uintptr(pNtHeaders.ImageBase)

	BaseDllName := NewUnicodeString(pdModule.Name)
	pLdrEntry.BaseNameHashValue = LdrHashEntry(BaseDllName, false)
	fmt.Printf("BaseNameHashValue: 0x%x\n", pLdrEntry.BaseNameHashValue)
	// AddBaseAddressEntry(pLdrEntry,(PVOID)pdModule->ModuleBase)
	return true
}

func LdrHashEntry(UniName UNICODE_STRING, XorHash bool) uint32 {
	var ulRes uint32 = 0
	r1, r2, err := pRtlHashUnicodeString.Call(uintptr(unsafe.Pointer(&UniName)), uintptr(1), uintptr(0), uintptr(unsafe.Pointer(&ulRes)))
	fmt.Println("RtlHashUnicodeString:", r1, r2, err)
	if XorHash {
		ulRes &= (LDR_HASH_TABLE_ENTRIES - 1)
	}
	return ulRes
}

// CopySections - writes the sections of a PE image to the given base address in memory
func copySections(pefile *pe.File, image *[]byte, loc uintptr) error {
	// Copy Headers
	var sizeOfHeaders uint32
	if pefile.Machine == pe.IMAGE_FILE_MACHINE_AMD64 {
		sizeOfHeaders = pefile.OptionalHeader.(*pe.OptionalHeader64).SizeOfHeaders
	} else {
		sizeOfHeaders = pefile.OptionalHeader.(*pe.OptionalHeader32).SizeOfHeaders
	}
	hbuf := (*[^uint32(0)]byte)(unsafe.Pointer(uintptr(loc)))
	for index := uint32(0); index < sizeOfHeaders; index++ {
		hbuf[index] = (*image)[index]
	}

	// Copy Sections
	for _, section := range pefile.Sections {
		//fmt.Println("Writing:", fmt.Sprintf("%s %x %x", section.Name, loc, uint32(loc)+section.VirtualAddress))
		if section.Size == 0 {
			continue
		}
		d, err := section.Data()
		if err != nil {
			return err
		}
		dataLen := uint32(len(d))
		dst := uint64(loc) + uint64(section.VirtualAddress)
		buf := (*[^uint32(0)]byte)(unsafe.Pointer(uintptr(dst)))
		for index := uint32(0); index < dataLen; index++ {
			buf[index] = d[index]
		}
	}

	// Write symbol and string tables
	bbuf := bytes.NewBuffer(nil)
	binary.Write(bbuf, binary.LittleEndian, pefile.COFFSymbols)
	binary.Write(bbuf, binary.LittleEndian, pefile.StringTable)
	b := bbuf.Bytes()
	blen := uint32(len(b))
	for index := uint32(0); index < blen; index++ {
		hbuf[index+pefile.FileHeader.PointerToSymbolTable] = b[index]
	}

	return nil
}

// NtAllocateVirtualMemory
func NvA(addr, size uintptr, allocType, protect uint32) (uintptr, error) {
	ic := indirect.New()
	nta := ic.NewProc("NtAllocateVirtualMemory")

	r, _, e := nta.Call(uintptr(0xffffffffffffffff), uintptr(unsafe.Pointer(&addr)), 0, uintptr(unsafe.Pointer(&size)), uintptr(allocType), uintptr(protect))
	if r != 0 {
		return 0, e
	}
	return addr, nil
}
