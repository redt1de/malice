

// this stack cal function was working for the simple spoof poc
/* Credit to VulcanRaven project for the original implementation of these two*/
func CalculateFunctionStackSize(pRuntimeFunction *RUNTIME_FUNCTION, ImageBase uint64) uint32 {
	// [0] Sanity check incoming pointer.
	if pRuntimeFunction == nil {
		log.Fatal("pRuntimeFunction is nil in CalculateFunctionStackSize")
		return 0
	}

	// [1] Loop over unwind info.
	// NB As this is a PoC, it does not handle every unwind operation, but
	// rather the minimum set required to successfully mimic the default
	// call stacks included.
	fmt.Println(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")
	fmt.Printf("UnwindData: 0x%x\n", pRuntimeFunction.UnwindData)
	fmt.Printf("ImageBase: 0x%x\n", ImageBase)

	pUnwindInfo := GetUnwindInfo(uintptr(uint64(pRuntimeFunction.UnwindData) + ImageBase))

	var stackFrame StackFrame
	var frameOffset uint16
	index := 0
	for {
		if index >= int(pUnwindInfo.CountOfCodes) {
			break
		}
		unwindOperation := pUnwindInfo.UnwindCode[index].UnwindOp
		operationInfo := pUnwindInfo.UnwindCode[index].OpInfo

		//         // [2] Loop over unwind codes and calculate
		//         // total stack space used by target Function.
		switch int(unwindOperation) {
		case UWOP_PUSH_NONVOL:
			// UWOP_PUSH_NONVOL is 8 bytes.
			stackFrame.TotalStackSize += 8
			// Record if it pushes rbp as
			// this is important for UWOP_SET_FPREG.
			if RBP == operationInfo {
				stackFrame.PushRbp = true
				// Record when rbp is pushed to stack.
				stackFrame.CountOfCodes = uint32(pUnwindInfo.CountOfCodes)
				stackFrame.PushRbpIndex = uint32(index + 1)
			}
		case UWOP_SAVE_NONVOL:
			//UWOP_SAVE_NONVOL doesn't contribute to stack size
			// but you do need to increment index.
			index += 1

		case UWOP_ALLOC_SMALL:
			//Alloc size is op info field * 8 + 8.
			stackFrame.TotalStackSize += uint32((operationInfo * 8) + 8)
		case UWOP_ALLOC_LARGE:
			// Alloc large is either:
			// 1) If op info == 0 then size of alloc / 8
			// is in the next slot (i.e. index += 1).
			// 2) If op info == 1 then size is in next
			// two slots.
			index += 1
			frameOffset = pUnwindInfo.UnwindCode[index].FrameOffset
			if operationInfo == 0 {
				frameOffset *= 8
			} else {
				index += 1
				frameOffset += (pUnwindInfo.UnwindCode[index].FrameOffset << 16)
			}
			stackFrame.TotalStackSize += uint32(frameOffset)
		case UWOP_SET_FPREG:
			// This sets rsp == rbp (mov rsp,rbp), so we need to ensure
			// that rbp is the expected value (in the frame above) when
			// it comes to spoof this frame in order to ensure the
			// call stack is correctly unwound.
			stackFrame.SetsFramePointer = true
		default:
			println("[-] Error: Unsupported Unwind Op Code\n")
			// status = STATUS_ASSERTION_FAILURE
		}

		index += 1
	}
	// If chained unwind information is present then we need to
	// also recursively parse this and add to total stack size.
	if 0 != (pUnwindInfo.Flags & UNW_FLAG_CHAININFO) {
		index = int(pUnwindInfo.CountOfCodes)
		if 0 != (index & 1) {
			index += 1
		}
		// pRuntimeFunction = (PRUNTIME_FUNCTION)(&pUnwindInfo.UnwindCode[index])
		pRuntimeFunction = (*RUNTIME_FUNCTION)(unsafe.Pointer(&pUnwindInfo.UnwindCode[index]))
		// return CalculateFunctionStackSize(pRuntimeFunction, ImageBase, stackFrame);
		return CalculateFunctionStackSize(pRuntimeFunction, ImageBase)
	}

	// Add the size of the return address (8 bytes).
	stackFrame.TotalStackSize += 8

	return stackFrame.TotalStackSize
}

func GetUnwindInfo(uwInfoAddr uintptr) UNWIND_INFO {
	var ret UNWIND_INFO
	tmpUnwindInfo := *(*_UNWIND_INFO)(unsafe.Pointer(uwInfoAddr))
	ret.Version = tmpUnwindInfo.VersionAndFlags & 0x07
	ret.Flags = (tmpUnwindInfo.VersionAndFlags >> 3) & 0x1F
	ret.SizeOfProlog = tmpUnwindInfo.SizeOfProlog
	ret.CountOfCodes = tmpUnwindInfo.CountOfCodes
	ret.FrameRegister = tmpUnwindInfo.FrameRegisterAndFrameOffset & 0x0F
	ret.FrameOffset = (tmpUnwindInfo.FrameRegisterAndFrameOffset >> 4) & 0x0F
	index := 0
	for {
		if index >= int(tmpUnwindInfo.CountOfCodes) {
			break
		}

		u := *(*uint32)(unsafe.Pointer(&tmpUnwindInfo.UnwindCode[index]))
		tmp3 := (*_UNWIND_CODE)(unsafe.Pointer(&u))

		unwindOperation := tmp3.UnwindOpAndOpInfo & 0x0F
		operationInfo := (tmp3.UnwindOpAndOpInfo >> 4) & 0x0F
		frameOffset := *(*uint16)(unsafe.Pointer(&u))

		ret.UnwindCode = append(ret.UnwindCode, UNWIND_CODE{
			CodeOffset:  tmp3.CodeOffset,
			UnwindOp:    unwindOperation,
			OpInfo:      operationInfo,
			FrameOffset: frameOffset,
		})
		index++

	}
	return ret
}