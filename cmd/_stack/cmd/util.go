package cmd

import (
	"bufio"
	"fmt"
	"os"
)

// readLines reads a whole file into memory
// and returns a slice of its lines.
func readLinesFile(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

func readLinesPaste() ([]string, error) {
	scn := bufio.NewScanner(os.Stdin)
	// for {
	fmt.Println("Paste data and press ctrl+] then enter:")
	var lines []string
	for scn.Scan() {
		line := scn.Text()
		if len(line) == 1 {
			// Group Separator (GS ^]): ctrl-]
			if line[0] == '\x1D' {
				break
			}
		}
		lines = append(lines, line)
	}
	if err := scn.Err(); err != nil {
		return nil, scn.Err()
	}
	if len(lines) == 0 {
		return nil, fmt.Errorf("no data")
	}
	return lines, nil
}

func formatStringListRSP() []string {
	var lst []string
	for addr := START; addr <= END; addr += 8 {
		label := ""
		// offset := ""
		offset := getOffset(addr, CTX.RSP)
		val := uint64(0)
		v, ok := TheStack[addr]
		if ok {
			val = v.Value
			label = v.Label
		}
		// if addr < CTX.RSP {
		// 	distance := (CTX.RSP - addr) * 8
		// 	offset = fmt.Sprintf("-%x", distance)
		// } else
		if addr == CTX.RSP {
			offset = "RSP =>"
		}
		// } else {
		// 	distance := (addr - CTX.RSP)
		// 	offset = fmt.Sprintf("+%x", distance)
		// 	if addr == CTX.RBP {
		// 		offset = fmt.Sprintf("+%x (RBP)", distance)
		// 	}
		// }

		pad := 10 - len(offset)
		for i := 0; i < pad; i++ {
			offset += " "
		}
		lst = append(lst, fmt.Sprintf("%s%016X  %016X  %s", offset, addr, val, label))

	}
	return lst
}

func formatStringListByAddr(indexAddr uint64) []string {
	var lst []string
	for addr := START; addr <= END; addr += 8 {
		label := ""
		offset := getOffset(addr, indexAddr)
		val := uint64(0)
		v, ok := TheStack[addr]
		if ok {
			val = v.Value
			label = v.Label
		}

		pad := 10 - len(offset)
		for i := 0; i < pad; i++ {
			offset += " "
		}
		lst = append(lst, fmt.Sprintf("%s%016X  %016X  %s", offset, addr, val, label))

	}
	return lst
}

func getOffset(curAddr, fromAddr uint64) string {
	offset := ""
	if curAddr < fromAddr {
		distance := (fromAddr - curAddr)
		offset = fmt.Sprintf("-%x", distance)
	} else if curAddr == fromAddr {
		offset = "    =>"
	} else {
		distance := (curAddr - fromAddr)
		offset = fmt.Sprintf("+%x", distance)
	}
	return offset
}

func formatStackArray() []stackLine {
	var lst []stackLine
	for addr := START; addr <= END; addr += 8 {
		label := ""
		val := uint64(0)
		v, ok := TheStack[addr]
		if ok {
			val = v.Value
			label = v.Label
		}
		lst = append(lst, stackLine{addr, val, label})

	}
	return lst
}

/*
1. rcx points to struct since its c call.

2. stores rbp and rbx in stack, stomps what is there.
- rbp -> rsp+0x8
	- rbx -> rsp+0x10
	- go passes args on the stack, so need another approach.
3.  Creating a stack reference to the JMP RBX gadget
	- SPOOFER.JmpRbxGadget -> rbx -> rsp+0x18
	- rsp+0x18 -> rbx -> SPOOFER.JmpRbxGadgetRef
	- SPOOFER.JmpRbxGadgetRef = address of of jmprbx gadget on the stack.
4. mov rsp -> rbp
	- rsp == rbp

5. pushes restore/cleanup onto stack -> rbx.
	- lea restore -> rax -> push to stack -> rbx
	- restore is on stack and in rbx

6. first frame
	- push SPOOFER.FirstFrameFunctionPointer
	- adds random offset to SPOOFER.FirstFrameFunctionPointer on the stack, can prob do this before the call.
	- mov SPOOFER.ReturnAddress -> rax, ret address needs set in asm. can just use pop rax to store ret addr then push it here
	- sub rax,SPOOFER.FirstFrameSize
	- rax == return address - first frame size ?????
*/
