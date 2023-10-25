package moonwalk

import (
	"unsafe"

	"github.com/redt1de/malice/pkg/pe"
)

func (sConfig *SPOOFER) FindPushRbp(hmod *pe.File, stackSize *uint32, prtSaveIndex *uint32, skip *uint32, rtTargetOffset *uint64) uint32 {
	var status uint32 = 0
	var suitableFrames uint32 = 0
	*stackSize = 0

	rttaddr, count := hmod.GetRuntimeTableAddr() // The first pop rbp frame is not suitable on most windows versions	//  skip_pop_rsp_frame++;
	for i := 1; i < int(count); i++ {

		rfunc := (*RUNTIME_FUNCTION)(unsafe.Pointer(rttaddr + uintptr(i)*unsafe.Sizeof(RUNTIME_FUNCTION{})))
		unwindInfoAddr := uintptr(rfunc.UnwindData) + hmod.ImageBase

		status = GetStackFrameSizeWhereRbpIsPushedOnStack(hmod, unwindInfoAddr, stackSize)

		if status != 0 {
			suitableFrames++
			if *skip >= suitableFrames {
				// Let's try another frame
				continue
			}
			*skip = suitableFrames

			// printf("Breaking at: %d\n", i)
			*prtSaveIndex = uint32(i)
			break
		}

	}

	tmp := (*RUNTIME_FUNCTION)(unsafe.Pointer(rttaddr + (uintptr(*prtSaveIndex) * unsafe.Sizeof(RUNTIME_FUNCTION{}))))
	*rtTargetOffset = uint64(uintptr(tmp.BeginAddress) + hmod.ImageBase)
	sConfig.SecondFrameFunctionPointer = uintptr(*rtTargetOffset)
	sConfig.SecondFrameSize = uintptr(*stackSize)
	// printf("Second Frame FP: 0x%x\n", *rtTargetOffset)
	// printf("Second Frame stack size: 0x%x\n", *stackSize)

	return status
}

func GetStackFrameSizeWhereRbpIsPushedOnStack(hmod *pe.File, unwindInfoAddress uintptr, targetStackOffset *uint32) uint32 {
	var saveStackOffset, backupStackOffset uint32
	var pChainedFunction *RUNTIME_FUNCTION
	var frameSize uint32 = 0
	var nodeIndex int = 0
	var RBP_PUSHED bool = false
	var ctx MIN_CTX

	unwindInfo := (*UNWIND_INFO)(unsafe.Pointer(unwindInfoAddress))
	uwCodeAddr := unwindInfoAddress + 4
	unwindCode := *(*UNWIND_CODE)(unsafe.Pointer(uwCodeAddr + uintptr(0*2)))
	saveStackOffset = 0
	*targetStackOffset = 0
	backupStackOffset = *targetStackOffset

	for nodeIndex < int(unwindInfo.CountOfCodes) {
		frameSize = 0
		switch unwindCode.UnwindOp() {
		case UWOP_PUSH_NONVOL: // 0
			if unwindCode.OpInfo() == RSP {
				// We break here
				return 0
			}
			if unwindCode.OpInfo() == RBP && RBP_PUSHED {
				return 0
			} else if unwindCode.OpInfo() == RBP {
				saveStackOffset = *targetStackOffset
				RBP_PUSHED = true
			}

			*targetStackOffset += 8

		case UWOP_ALLOC_LARGE: // 1
			// If the operation info equals 0 -> allocation size / 8 in next slot
			// If the operation info equals 1 -> unscaled allocation size in next 2 slots
			// In any case, we need to advance 1 slot and record the size

			// Skip to next Unwind Code
			uwCodeAddr += uintptr(2)
			unwindCode = *(*UNWIND_CODE)(unsafe.Pointer(uwCodeAddr))

			// Keep track of current node
			nodeIndex++
			// Register size in next slot
			frameSize = uint32(unwindCode.FrameOffset())

			if unwindCode.OpInfo() == 0 {
				// If the operation info equals 0, then the size of the allocation divided by 8
				// is recorded in the next slot, allowing an allocation up to 512K - 8.
				// We already advanced of 1 slot, and recorded the allocation size
				// We just need to multiply it for 8 to get the unscaled allocation size
				frameSize *= 8
			} else {
				// If the operation info equals 1, then the unscaled size of the allocation is
				// recorded in the next two slots in little-endian format, allowing allocations
				// up to 4GB - 8.
				// Skip to next Unwind Code
				uwCodeAddr += uintptr(2)
				unwindCode = *(*UNWIND_CODE)(unsafe.Pointer(uwCodeAddr))
				// Keep track of current node
				nodeIndex++
				// Unmask the rest of the allocation size
				frameSize += uint32(unwindCode.FrameOffset()) << 16

			}
			*targetStackOffset += frameSize

		case UWOP_ALLOC_SMALL: // 2

			// Allocate a small-sized area on the stack. The size of the allocation is the operation
			// info field * 8 + 8, allowing allocations from 8 to 128 bytes.
			*targetStackOffset += uint32(8 * (unwindCode.OpInfo() + 1))

		case UWOP_SET_FPREG: // 3
			return 0

		case UWOP_SAVE_NONVOL: // 4
			// Save a nonvolatile integer register on the stack using a MOV instead of a PUSH. This code is
			// primarily used for shrink-wrapping, where a nonvolatile register is saved to the stack in a position
			// that was previously allocated. The operation info is the number of the register. The scaled-by-8
			// stack offset is recorded in the next unwind operation code slot, as described in the note above.
			if unwindCode.OpInfo() == RSP {
				// This time, we return only if RSP was saved
				return 0
			} else {
				// For future use: save the scaled by 8 stack offset
				// *((ULONG*)&ctx + unwindCode->OpInfo) = *targetStackOffset + (DWORD)((PUNWIND_CODE)((PWORD)unwindCode + 1))->FrameOffset * 8;
				tmp := *(*UNWIND_CODE)(unsafe.Pointer(uwCodeAddr + uintptr(2)))
				*(*uint64)(unsafe.Pointer(uintptr(unsafe.Pointer(&ctx)) + uintptr(unwindCode.OpInfo()*4))) = uint64(*targetStackOffset + uint32(tmp.FrameOffset())*8)

				// Skip to next Unwind Code
				uwCodeAddr += uintptr(2)
				unwindCode = *(*UNWIND_CODE)(unsafe.Pointer(uwCodeAddr))
				nodeIndex++

				if unwindCode.OpInfo() != RBP {
					// Restore original stack size (!?)
					*targetStackOffset = backupStackOffset
					break
				}
				if RBP_PUSHED {
					return 0
				}

				RBP_PUSHED = true
				// We save the stack offset where MOV [RSP], RBP happened
				// During unwinding, this address will be popped back in RBP
				// saveStackOffset = *((ULONG*)&ctx + unwindCode->OpInfo);
				saveStackOffset = uint32(*(*uint64)(unsafe.Pointer(uintptr(unsafe.Pointer(&ctx)) + uintptr(unwindCode.OpInfo()*4))))

				// Restore original stack size (!?)
				*targetStackOffset = backupStackOffset
			}

		case UWOP_SAVE_NONVOL_BIG: // 5
			// Save a nonvolatile integer register on the stack with a long offset, using a MOV instead of a PUSH.
			// This code is primarily used for shrink-wrapping, where a nonvolatile register is saved to the stack
			// in a position that was previously allocated. The operation info is the number of the register.
			// The unscaled stack offset is recorded in the next two unwind operation code slots, as described
			// in the note above.
			if unwindCode.OpInfo() == RSP {
				return 0
			}

			// For future use
			// *((ULONG*)&ctx + unwindCode->OpInfo) = *targetStackOffset + (DWORD)((PUNWIND_CODE)((PWORD)unwindCode + 1))->FrameOffset;
			tmp := *(*UNWIND_CODE)(unsafe.Pointer(uwCodeAddr + uintptr(2)))
			*(*uint64)(unsafe.Pointer(uintptr(unsafe.Pointer(&ctx)) + uintptr(unwindCode.OpInfo()*4))) = uint64(tmp.FrameOffset()) // ?????????????????????????????????????????????????????

			//*((ULONG*)&ctx + unwindCode->OpInfo) += (DWORD)((PUNWIND_CODE)((PWORD)unwindCode + 2))->FrameOffset << 16;
			tmp = *(*UNWIND_CODE)(unsafe.Pointer(uwCodeAddr + uintptr(4)))
			*(*uint64)(unsafe.Pointer(uintptr(unsafe.Pointer(&ctx)) + uintptr(unwindCode.OpInfo()*4))) += uint64(tmp.FrameOffset()) << 16 // ?????????????????????????????????????????????????????

			if unwindCode.OpInfo() != RBP {
				// Restore original stack size (!?)
				*targetStackOffset = backupStackOffset
				break
			}
			if RBP_PUSHED {
				return 0
			}
			// We save the stack offset where MOV [RSP], RBP happened
			// During unwinding, this address will be popped back in RBP
			saveStackOffset = uint32(*(*uint64)(unsafe.Pointer(uintptr(unsafe.Pointer(&ctx)) + uintptr(unwindCode.OpInfo()*4))))
			// Restore Stack Size
			*targetStackOffset = backupStackOffset

			// Skip the other two nodes used for this unwind operation
			// unwindCode = (PUNWIND_CODE)((PWORD)unwindCode + 2);
			uwCodeAddr += uintptr(2) * 2
			unwindCode = *(*UNWIND_CODE)(unsafe.Pointer(uwCodeAddr))
			nodeIndex += 2

		case UWOP_EPILOG: // 6
		case UWOP_SAVE_XMM128: // 8
			// Save all 128 bits of a nonvolatile XMM register on the stack. The operation info is the number of
			// the register. The scaled-by-16 stack offset is recorded in the next slot.

			// TODO: Handle this

			// Skip to next Unwind Code
			uwCodeAddr += uintptr(2)
			unwindCode = *(*UNWIND_CODE)(unsafe.Pointer(uwCodeAddr))
			nodeIndex++
		case UWOP_SPARE_CODE: // 7
		case UWOP_SAVE_XMM128BIG: // 9
			// Save all 128 bits of a nonvolatile XMM register on the stack with a long offset. The operation info
			// is the number of the register. The unscaled stack offset is recorded in the next two slots.

			// TODO: Handle this

			// Advancing next 2 nodes
			uwCodeAddr += uintptr(2) * 2
			unwindCode = *(*UNWIND_CODE)(unsafe.Pointer(uwCodeAddr))
			nodeIndex += 2
		case UWOP_PUSH_MACH_FRAME: // 10
			// Push a machine frame. This unwind code is used to record the effect of a hardware interrupt or exception.
			// There are two forms.

			// NOTE: UNTESTED
			// TODO: Test this
			if unwindCode.OpInfo() == 0 {
				*targetStackOffset += 0x40
			} else {
				*targetStackOffset += 0x48
			}
		}
		uwCodeAddr += uintptr(2)
		unwindCode = *(*UNWIND_CODE)(unsafe.Pointer(uwCodeAddr))
		nodeIndex++

	}
	if BitChainInfo(unwindInfo.Flags()) == 1 {
		nodeIndex = int(unwindInfo.CountOfCodes)
		if 0 != (nodeIndex & 1) {
			nodeIndex += 1
		}

		newuwCodeAddr := unwindInfoAddress + 4 + uintptr(2*nodeIndex) //????????????????????????????
		pChainedFunction = (*RUNTIME_FUNCTION)(unsafe.Pointer(newuwCodeAddr))
		return GetStackFrameSize(hmod, uintptr(pChainedFunction.UnwindData)+hmod.ImageBase, targetStackOffset)
	}

	return saveStackOffset

}
