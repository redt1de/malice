package synth

import (
	"unsafe"

	"github.com/redt1de/malice/pkg/pe"
)

func FindProlog(module *pe.File /*PERF pRuntimeFunctionTable, rtLastIndex uint32*/, stackSize *uint32, prtSaveIndex *uint32, skip *uint32, rtTargetOffset *uint64) uint32 {
	var status uint32 = 0
	var suitableFrames uint32 = 0
	*stackSize = 0

	rttaddr, count := module.GetRuntimeTableAddr()
	for i := 0; i < int(count); i++ {
		rf := (*pe.C_RUNTIME_FUNCTION)(unsafe.Pointer(rttaddr + uintptr(i)*unsafe.Sizeof(pe.C_RUNTIME_FUNCTION{})))
		unwindInfo := pe.ParseCRuntimeFunction(rf, module.ImageBase).UnwindInfo
		status = GetStackFrameSize(module.ImageBase, &unwindInfo, stackSize)
		// unwindInfo := (*pe.C_UNWIND_INFO)(unsafe.Pointer(&rf.UNION_UnwindInfoAddress_UnwindData))
		// status = GetStackFrameSize(module.ImageBase, unwindInfo, stackSize)

		if status != 0 {
			suitableFrames++
			if *skip >= suitableFrames {
				// Let's try another frame
				continue
			}
			*skip = suitableFrames

			printf("Breaking at: %d\nStackSize: 0x%x\n", i, *stackSize)
			*prtSaveIndex = uint32(i)
			break
		}

	}

	tmp := (*pe.C_RUNTIME_FUNCTION)(unsafe.Pointer(rttaddr + uintptr(*prtSaveIndex)*unsafe.Sizeof(pe.C_RUNTIME_FUNCTION{})))
	*rtTargetOffset = uint64(uintptr(tmp.BeginAddress) + module.ImageBase)
	// sConfig.FirstFrameFunctionPointer = (PVOID) * rtTargetOffset
	// sConfig.FirstFrameSize = *stackSize
	printf("First Frame FP: 0x%x\n", *rtTargetOffset)
	printf("First Frame stack size: 0x%x\n", *stackSize)

	return status
}

func FindPushRbp(module *pe.File /*PERF pRuntimeFunctionTable, rtLastIndex uint32*/, stackSize *uint32, prtSaveIndex *uint32, skip *uint32, rtTargetOffset *uint64) uint32 {
	var status uint32 = 0
	var suitableFrames uint32 = 0
	*stackSize = 0

	rttaddr, count := module.GetRuntimeTableAddr()
	for i := 0; i < int(count); i++ {
		rf := (*pe.C_RUNTIME_FUNCTION)(unsafe.Pointer(rttaddr + uintptr(i)*unsafe.Sizeof(pe.C_RUNTIME_FUNCTION{})))
		unwindInfo := pe.ParseCRuntimeFunction(rf, module.ImageBase).UnwindInfo
		// unwindInfo := (*pe.C_UNWIND_INFO)(unsafe.Pointer(&rf.UNION_UnwindInfoAddress_UnwindData))
		status = GetStackFrameSizeWhereRbpIsPushedOnStack(module.ImageBase, &unwindInfo, stackSize)
		if status != 0 {
			suitableFrames++
			if *skip >= suitableFrames {
				// Let's try another frame
				continue
			}
			*skip = suitableFrames

			printf("Breaking at: %d\nStackSize: 0x%x\n", i, *stackSize)
			*prtSaveIndex = uint32(i)
			break
		}

	}

	tmp := (*pe.C_RUNTIME_FUNCTION)(unsafe.Pointer(rttaddr + uintptr(*prtSaveIndex)*unsafe.Sizeof(pe.C_RUNTIME_FUNCTION{})))
	*rtTargetOffset = uint64(uintptr(tmp.BeginAddress) + module.ImageBase)
	// sConfig.FirstFrameFunctionPointer = (PVOID) * rtTargetOffset
	// sConfig.FirstFrameSize = *stackSize
	printf("Second Frame FP: 0x%x\n", *rtTargetOffset)
	printf("Second Frame stack size: 0x%x\n", *stackSize)

	return status
}

func GetStackFrameSizeWhereRbpIsPushedOnStack(ImageBase uintptr, unwindInfo *pe.UNWIND_INFO, targetStackOffset *uint32) uint32 {

	var RBP_PUSHED bool = false
	var frameSize uint32 = 0
	var nodeIndex uint8 = 0
	var saveStackOffset uint32 = 0
	var backupStackOffset uint32 = *targetStackOffset
	var ctx MIN_CTX
	// unwindInfo := pRuntimeFunction.UnwindInfo
	if len(unwindInfo.UnwindCode) == 0 {
		return 0
	}
	unwindCode := unwindInfo.UnwindCode[0]
	*targetStackOffset = 0

	for nodeIndex < (unwindInfo.CountOfCodes - 1) {
		// Ensure frameSize is reset
		frameSize = 0

		switch unwindCode.UnwindOp {
		case UWOP_PUSH_NONVOL: // 0
			if unwindCode.OpInfo == RSP {
				// We break here
				return 0
			}
			if unwindCode.OpInfo == RBP && RBP_PUSHED {
				return 0
			} else if unwindCode.OpInfo == RBP {
				saveStackOffset = *targetStackOffset
				RBP_PUSHED = true
			}

			*targetStackOffset += 8
		////////////////////////////////////
		case UWOP_ALLOC_LARGE: // 1
			// If the operation info equals 0 -> allocation size / 8 in next slot
			// If the operation info equals 1 -> unscaled allocation size in next 2 slots
			// In any case, we need to advance 1 slot and record the size

			// Skip to next Unwind Code
			nodeIndex++
			unwindCode = unwindInfo.UnwindCode[nodeIndex]
			// Register size in next slot
			frameSize = uint32(unwindCode.FrameOffset)

			if unwindCode.OpInfo == 0 {
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
				nodeIndex++
				unwindCode = unwindInfo.UnwindCode[nodeIndex]
				// Unmask the rest of the allocation size
				frameSize += uint32(unwindCode.FrameOffset) << 16

			}
			*targetStackOffset += frameSize

		/////////////////////////////////////////////////////////
		case UWOP_ALLOC_SMALL: // 2
			// Allocate a small-sized area on the stack. The size of the allocation is the operation
			// info field * 8 + 8, allowing allocations from 8 to 128 bytes.
			*targetStackOffset += uint32(8 * (unwindCode.OpInfo + 1))
			////////////////////////////////////////////////////

		case UWOP_SET_FPREG: // 3
			return 0
			//////////////////////////////////////////////////////
		case UWOP_SAVE_NONVOL: // 4
			// Save a nonvolatile integer register on the stack using a MOV instead of a PUSH. This code is
			// primarily used for shrink-wrapping, where a nonvolatile register is saved to the stack in a position
			// that was previously allocated. The operation info is the number of the register. The scaled-by-8
			// stack offset is recorded in the next unwind operation code slot, as described in the note above.
			if unwindCode.OpInfo == RSP {
				// This time, we return only if RSP was saved
				return 0
			} else {

				*(*uint64)(unsafe.Pointer(uintptr(unsafe.Pointer(&ctx)) + uintptr(unwindCode.OpInfo*4))) = uint64(*targetStackOffset + uint32(unwindInfo.UnwindCode[nodeIndex+1].FrameOffset)*8)
				// Skip to next Unwind Code
				nodeIndex++
				unwindCode = unwindInfo.UnwindCode[nodeIndex]

				if unwindCode.OpInfo != RBP {
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
				saveStackOffset = uint32(*(*uint64)(unsafe.Pointer(uintptr(unsafe.Pointer(&ctx)) + uintptr(unwindCode.OpInfo*4))))

				// Restore original stack size (!?)
				*targetStackOffset = backupStackOffset
			}
		//////////////////////////////////////////////////////

		case UWOP_SAVE_NONVOL_BIG: // 5
			// Save a nonvolatile integer register on the stack with a long offset, using a MOV instead of a PUSH.
			// This code is primarily used for shrink-wrapping, where a nonvolatile register is saved to the stack
			// in a position that was previously allocated. The operation info is the number of the register.
			// The unscaled stack offset is recorded in the next two unwind operation code slots, as described
			// in the note above.
			if unwindCode.OpInfo == RSP {
				return 0
			}

			// For future use
			// *((ULONG*)&ctx + unwindCode->OpInfo) = *targetStackOffset + (DWORD)((PUNWIND_CODE)((PWORD)unwindCode + 1))->FrameOffset;
			*(*uint64)(unsafe.Pointer(uintptr(unsafe.Pointer(&ctx)) + uintptr(unwindCode.OpInfo*4))) = uint64(*targetStackOffset + uint32(unwindInfo.UnwindCode[nodeIndex+1].FrameOffset))
			// *((ULONG*)&ctx + unwindCode->OpInfo) += (DWORD)((PUNWIND_CODE)((PWORD)unwindCode + 2))->FrameOffset << 16;
			*(*uint64)(unsafe.Pointer(uintptr(unsafe.Pointer(&ctx)) + uintptr(unwindCode.OpInfo*4))) += uint64(*targetStackOffset + uint32(unwindInfo.UnwindCode[nodeIndex+1].FrameOffset)<<16)

			if unwindCode.OpInfo != RBP {
				// Restore original stack size (!?)
				*targetStackOffset = backupStackOffset
				break
			}
			if RBP_PUSHED {
				return 0
			}
			// We save the stack offset where MOV [RSP], RBP happened
			// During unwinding, this address will be popped back in RBP
			saveStackOffset = uint32(*(*uint64)(unsafe.Pointer(uintptr(unsafe.Pointer(&ctx)) + uintptr(unwindCode.OpInfo*4))))
			// Restore Stack Size
			*targetStackOffset = backupStackOffset

			// Skip the other two nodes used for this unwind operation
			nodeIndex += 2
			unwindCode = unwindInfo.UnwindCode[nodeIndex]

		///////////////////////////////////////////////////////////////
		case UWOP_EPILOG: // 6
		case UWOP_SAVE_XMM128: // 8
			nodeIndex++
			unwindCode = unwindInfo.UnwindCode[nodeIndex]
		/////////////////////////////////////////////////////////////
		case UWOP_SPARE_CODE: // 7
		case UWOP_SAVE_XMM128BIG: // 9
			nodeIndex += 2
			unwindCode = unwindInfo.UnwindCode[nodeIndex]
		/////////////////////////////////////////////////////////////
		case UWOP_PUSH_MACH_FRAME: // 10
			if unwindCode.OpInfo == 0 {
				*targetStackOffset += 0x40
			} else {
				*targetStackOffset += 0x48
			}
		}
		if nodeIndex >= (unwindInfo.CountOfCodes - 1) {
			break
		}
		nodeIndex++
		unwindCode = unwindInfo.UnwindCode[nodeIndex]

	}

	if BitChainInfo(unwindInfo.Flags) == 1 {
		nodeIndex = unwindInfo.CountOfCodes
		if 0 != (nodeIndex & 1) {
			nodeIndex += 1
		}

		if nodeIndex <= (unwindInfo.CountOfCodes - 1) {
			pChainedFunction := pe.ParseCRuntimeFunction((*pe.C_RUNTIME_FUNCTION)(unsafe.Pointer(&unwindInfo.UnwindCode[nodeIndex])), uintptr(ImageBase))
			// pChainedFunction = (PRUNTIME_FUNCTION)(&unwindInfo->UnwindCode[nodeIndex]);
			return GetStackFrameSize(ImageBase, &pChainedFunction.UnwindInfo, targetStackOffset)
		}
	}

	return saveStackOffset
}

func GetStackFrameSize(ImageBase uintptr, unwindInfo *pe.UNWIND_INFO, targetStackOffset *uint32) uint32 {

	var UWOP_SET_FPREG_HIT bool = false
	var frameSize uint32 = 0
	var nodeIndex uint8 = 0
	var ctx MIN_CTX
	// unwindInfo := pRuntimeFunction.UnwindInfo
	if len(unwindInfo.UnwindCode) == 0 {
		return 0
	}
	unwindCode := unwindInfo.UnwindCode[0]
	*targetStackOffset = 0

	for nodeIndex < (unwindInfo.CountOfCodes - 1) {
		// Ensure frameSize is reset
		frameSize = 0

		switch unwindCode.UnwindOp {
		case UWOP_PUSH_NONVOL: // 0
			if unwindCode.OpInfo == RSP && !UWOP_SET_FPREG_HIT {
				// We break here
				return 0
			}
			*targetStackOffset += 8
			printf(">>>>>>>>>>>>>>> 0x%x (0x%x)\n", unwindCode.OpInfo, *targetStackOffset)
		// break
		////////////////////////////////////
		case UWOP_ALLOC_LARGE: // 1
			// If the operation info equals 0 -> allocation size / 8 in next slot
			// If the operation info equals 1 -> unscaled allocation size in next 2 slots
			// In any case, we need to advance 1 slot and record the size

			// Skip to next Unwind Code
			nodeIndex++
			unwindCode = unwindInfo.UnwindCode[nodeIndex]

			// Register size in next slot
			frameSize = uint32(unwindCode.FrameOffset)

			if unwindCode.OpInfo == 0 {
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
				nodeIndex++
				unwindCode = unwindInfo.UnwindCode[nodeIndex]
				// Unmask the rest of the allocation size
				frameSize += uint32(unwindCode.FrameOffset) << 16

			}
			*targetStackOffset += frameSize
		// break;
		/////////////////////////////////////////////////////////
		case UWOP_ALLOC_SMALL: // 2

			// Allocate a small-sized area on the stack. The size of the allocation is the operation
			// info field * 8 + 8, allowing allocations from 8 to 128 bytes.
			*targetStackOffset += uint32(8 * (unwindCode.OpInfo + 1))
			// break
			////////////////////////////////////////////////////

		case UWOP_SET_FPREG: // 3
			// Establish the frame pointer register by setting the register to some offset of the current RSP.
			// The offset is equal to the Frame Register offset (scaled) field in the UNWIND_INFO * 16, allowing
			// offsets from 0 to 240. The use of an offset permits establishing a frame pointer that points to the
			// middle of the fixed stack allocation, helping code density by allowing more accesses to use short
			// instruction forms. The operation info field is reserved and shouldn't be used.

			if BitEHandler(unwindInfo.Flags) == 1 && BitChainInfo(unwindInfo.Flags) == 1 {
				return 0
			}

			UWOP_SET_FPREG_HIT = true

			frameSize = uint32(-0x10 * int(unwindInfo.FrameOffset))
			*targetStackOffset += frameSize
			// break
			//////////////////////////////////////////////////////
		case UWOP_SAVE_NONVOL: // 4
			// Save a nonvolatile integer register on the stack using a MOV instead of a PUSH. This code is
			// primarily used for shrink-wrapping, where a nonvolatile register is saved to the stack in a position
			// that was previously allocated. The operation info is the number of the register. The scaled-by-8
			// stack offset is recorded in the next unwind operation code slot, as described in the note above.
			if unwindCode.OpInfo == RBP || unwindCode.OpInfo == RSP {
				return 0
			}
			// Skip to next Unwind Code
			nodeIndex++
			unwindCode = unwindInfo.UnwindCode[nodeIndex]

			// For future use
			//*((ULONG*)&ctx + unwindCode->OpInfo) = *targetStackOffset + (DWORD)((PUNWIND_CODE)((PWORD)unwindCode + 1))->FrameOffset * 8;
			if nodeIndex+1 < (unwindInfo.CountOfCodes - 1) {
				*(*uint64)(unsafe.Pointer(uintptr(unsafe.Pointer(&ctx)) + uintptr(unwindCode.OpInfo*4))) = uint64(*targetStackOffset + uint32(unwindInfo.UnwindCode[nodeIndex+1].FrameOffset)*8)
			}
		// break
		//////////////////////////////////////////////////////

		case UWOP_SAVE_NONVOL_BIG: // 5
			// Save a nonvolatile integer register on the stack with a long offset, using a MOV instead of a PUSH.
			// This code is primarily used for shrink-wrapping, where a nonvolatile register is saved to the stack
			// in a position that was previously allocated. The operation info is the number of the register.
			// The unscaled stack offset is recorded in the next two unwind operation code slots, as described
			// in the note above.
			if unwindCode.OpInfo == RBP || unwindCode.OpInfo == RSP {
				return 0
			}

			// For future use
			// *((ULONG*)&ctx + unwindCode->OpInfo) = *targetStackOffset + (DWORD)((PUNWIND_CODE)((PWORD)unwindCode + 1))->FrameOffset;
			*(*uint64)(unsafe.Pointer(uintptr(unsafe.Pointer(&ctx)) + uintptr(unwindCode.OpInfo*4))) = uint64(*targetStackOffset + uint32(unwindInfo.UnwindCode[nodeIndex+1].FrameOffset))
			// *((ULONG*)&ctx + unwindCode->OpInfo) += (DWORD)((PUNWIND_CODE)((PWORD)unwindCode + 2))->FrameOffset << 16;
			*(*uint64)(unsafe.Pointer(uintptr(unsafe.Pointer(&ctx)) + uintptr(unwindCode.OpInfo*4))) += uint64(*targetStackOffset + uint32(unwindInfo.UnwindCode[nodeIndex+1].FrameOffset)<<16)

			// Skip the other two nodes used for this unwind operation
			nodeIndex += 2
			unwindCode = unwindInfo.UnwindCode[nodeIndex]

			// break;

			///////////////////////////////////////////////////////////////
		case UWOP_EPILOG: // 6
		case UWOP_SAVE_XMM128: // 8
			// Save all 128 bits of a nonvolatile XMM register on the stack. The operation info is the number of
			// the register. The scaled-by-16 stack offset is recorded in the next slot.

			// TODO: Handle this

			// Skip to next Unwind Code
			nodeIndex++
			unwindCode = unwindInfo.UnwindCode[nodeIndex]
		// break;
		/////////////////////////////////////////////////////////////
		case UWOP_SPARE_CODE: // 7
		case UWOP_SAVE_XMM128BIG: // 9
			// Save all 128 bits of a nonvolatile XMM register on the stack with a long offset. The operation info
			// is the number of the register. The unscaled stack offset is recorded in the next two slots.

			// TODO: Handle this

			// Advancing next 2 nodes
			nodeIndex += 2
			unwindCode = unwindInfo.UnwindCode[nodeIndex]
		// break
		/////////////////////////////////////////////////////////////
		case UWOP_PUSH_MACH_FRAME: // 10
			// Push a machine frame. This unwind code is used to record the effect of a hardware interrupt or exception.
			// There are two forms.

			// NOTE: UNTESTED
			// TODO: Test this
			if unwindCode.OpInfo == 0 {
				*targetStackOffset += 0x40
			} else {
				*targetStackOffset += 0x48
			}
			// break
		}
		if nodeIndex >= (unwindInfo.CountOfCodes - 1) {
			break
		}
		nodeIndex++
		unwindCode = unwindInfo.UnwindCode[nodeIndex]

	}

	if BitChainInfo(unwindInfo.Flags) == 1 {
		nodeIndex = unwindInfo.CountOfCodes
		if 0 != (nodeIndex & 1) {
			nodeIndex += 1
		}

		if nodeIndex <= (unwindInfo.CountOfCodes - 1) {
			pChainedFunction := pe.ParseCRuntimeFunction((*pe.C_RUNTIME_FUNCTION)(unsafe.Pointer(&unwindInfo.UnwindCode[nodeIndex])), uintptr(ImageBase))
			// pChainedFunction = (PRUNTIME_FUNCTION)(&unwindInfo->UnwindCode[nodeIndex]);
			return GetStackFrameSize(ImageBase, &pChainedFunction.UnwindInfo, targetStackOffset)
		}
	}

	if UWOP_SET_FPREG_HIT {
		return 1
	}
	return 0
}

func BitVal(data, y uint8) uint8    { return (data >> y) & 1 }
func BitChainInfo(data uint8) uint8 { return BitVal(data, 2) }
func BitUHandler(data uint8) uint8  { return BitVal(data, 1) }
func BitEHandler(data uint8) uint8  { return BitVal(data, 0) }
