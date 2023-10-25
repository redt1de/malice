package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/antonmedv/expr"
	"github.com/manifoldco/promptui"
)

func save(fpath string) error {
	// 00000040125FF370  00007FFB9AF35A00             ntdll.RtlNtdllName+75E0
	lst := formatStackArray()
	f, err := os.Create(fpath)
	if err != nil {
		return err
	}
	// remember to close the file
	defer f.Close()

	for _, sline := range lst {
		outline := fmt.Sprintf("%s  %s             %s\n", sline.AddrHex(), sline.ValHex(), sline.Label)
		_, err := f.WriteString(outline)
		if err != nil {
			return err
		}
	}
	return nil
}

func tryParseVal(args string) {
	env := map[string]interface{}{"RAX": CTX.RAX, "RBX": CTX.RBX, "RCX": CTX.RCX, "RDX": CTX.RDX, "RSP": CTX.RSP, "RBP": CTX.RBP, "RDI": CTX.RDI, "RSI": CTX.RSI, "R8": CTX.R8, "R9": CTX.R9, "R10": CTX.R10, "R11": CTX.R11, "R12": CTX.R12, "R13": CTX.R13, "R14": CTX.R14, "R15": CTX.R15,
		"rax": CTX.RAX, "rbx": CTX.RBX, "rcx": CTX.RCX, "rdx": CTX.RDX, "rsp": CTX.RSP, "rbp": CTX.RBP, "rdi": CTX.RDI, "rsi": CTX.RSI, "r8": CTX.R8, "r9": CTX.R9, "r10": CTX.R10, "r11": CTX.R11, "r12": CTX.R12, "r13": CTX.R13, "r14": CTX.R14, "r15": CTX.R15,
	}

	program, err := expr.Compile(args, expr.Env(env))
	if err != nil {
		fmt.Printf("ERROR> %s\n", err)
	}

	output, err := expr.Run(program, env)
	if err != nil {
		fmt.Printf("ERROR> %s\n", err)
	}
	fmt.Println(">>>>>>", output)
}

func setrsp(a string) error {
	var lst []string
	cursorpos := 0
	index := 0
	for addr := START; addr <= END; addr += 8 {
		label := ""
		val := uint64(0)
		v, ok := TheStack[addr]
		if ok {
			val = v.Value
			label = v.Label
		}
		if v.Addr == CTX.RSP {
			cursorpos = index
		}
		lst = append(lst, fmt.Sprintf("%016X  %016X  %s", addr, val, label))
		index++
	}

	prompt := promptui.Select{Label: "Set RSP", Items: lst, Size: len(lst), CursorPos: cursorpos}

	_, result, err := prompt.Run()
	if err != nil {
		// fmt.Printf("Prompt failed %v\n", err)
		return err
	}
	_, err = fmt.Sscanf(result, "%X", &CTX.RSP)
	if err != nil {
		// fmt.Printf("Prompt failed %v\n", err)
		return err
	}

	fmt.Printf("set RSP to: %016X\n", CTX.RSP)
	stackPrint()
	return nil
}

func label(addr string) error {
	var tmp uint64
	var def string
	if addr == "" {
		lst := formatStringListRSP()
		prompt := promptui.Select{Label: "Select a line to label:", Items: lst, Size: len(lst)}
		_, result, err := prompt.Run()
		if err != nil {
			return err
		}
		result = result[10:]

		_, err = fmt.Sscanf(result, "%X", &tmp)
		if err != nil {
			return err
		}

	} else {
		_, err := fmt.Sscanf(addr, "%X", &tmp)
		if err != nil {
			return err
		}
	}

	if val, ok := TheStack[tmp]; ok {
		def = val.Label
	}

	prompt2 := promptui.Prompt{
		Label:   "Label",
		Default: def,
	}

	result, err := prompt2.Run()
	if err != nil {
		// fmt.Printf("Prompt failed %v\n", err)
		return err
	}

	if _, ok := TheStack[tmp]; !ok {
		TheStack[tmp] = stackLine{
			Addr:  tmp,
			Value: 0,
			Label: result,
		}
	} else {
		TheStack[tmp] = stackLine{
			Addr:  TheStack[tmp].Addr,
			Value: TheStack[tmp].Value,
			Label: result,
		}
	}
	stackPrint()
	return nil
}

func getReg(reg string) *uint64 {
	switch strings.ToUpper(reg) {
	case "RAX":
		return &CTX.RAX
	case "RBX":
		return &CTX.RBX
	case "RCX":
		return &CTX.RCX
	case "RDX":
		return &CTX.RDX
	case "RSP":
		return &CTX.RSP
	case "RBP":
		return &CTX.RBP
	case "RDI":
		return &CTX.RDI
	case "RSI":
		return &CTX.RSI
	case "R8":
		return &CTX.R8
	case "R9":
		return &CTX.R9
	case "R10":
		return &CTX.R10
	case "R11":
		return &CTX.R10
	case "R12":
		return &CTX.R12
	case "R13":
		return &CTX.R13
	case "R14":
		return &CTX.R14
	case "R15":
		return &CTX.R15
	}
	return nil

}

func outRegs() string {
	return fmt.Sprintf("\nRAX: %016X RBX: %016X RCX: %016X RDX: %016X\nRSP: %016X RBP: %016X RDI: %016X RSI: %016X\n R8: %016X  R9: %016X R10: %016X R11: %016X\nR12: %016X R13: %016X R14: %016X R15: %016X", CTX.RAX, CTX.RBX, CTX.RCX, CTX.RDX, CTX.RSP, CTX.RBP, CTX.RDI, CTX.RSI, CTX.R8, CTX.R9, CTX.R10, CTX.R11, CTX.R12, CTX.R13, CTX.R14, CTX.R15)
}

func parseVal(input string) (uint64, error) {
	var val uint64
	r := getReg(input)
	if r != nil {
		return *r, nil
	}
	// number, err := strconv.ParseUint(string("90"), 10, 64)
	_, err := fmt.Sscanf(input, "%x", &val)
	if err == nil {
		return val, nil
	}
	_, err = fmt.Sscanf(input, "%d", &val)
	if err == nil {
		return val, nil
	}

	return 0, fmt.Errorf("unknown value")
}

func push(input string) error {
	newval, err := parseVal(input)
	if err != nil {
		// fmt.Printf("error parsing %s: %v\n", input, err)
		return err
	}
	CTX.RSP -= 8
	if CTX.RSP < START {
		START = CTX.RSP
	}
	if val, ok := TheStack[CTX.RSP]; !ok {
		TheStack[CTX.RSP] = stackLine{
			Addr:  CTX.RSP,
			Value: newval,
			Label: fmt.Sprintf("pushed %x", newval),
		}
	} else {
		TheStack[CTX.RSP] = stackLine{
			Addr:  CTX.RSP,
			Value: newval,
			Label: val.Label,
		}
	}
	stackPrint()
	return nil
}

func pop(reg string) error {
	r := getReg(reg)
	if r == nil {
		// fmt.Printf("unknown register %s\n", reg)
		return fmt.Errorf("unknown register")
	}
	if v, ok := TheStack[CTX.RSP]; ok {
		*r = v.Value
	} else {
		*r = 0
	}
	CTX.RSP += 8
	stackPrint()
	return nil
}

func load(fin string) error {
	var lines []string
	var err error
	if fin == "" {
		lines, err = readLinesPaste()
	} else {
		lines, err = readLinesFile(fin)
	}
	if err != nil {
		return err
	}
	var lastAddr uint64
	if len(lines) > 0 {
		for i, line := range lines {
			line = strings.TrimSpace(line)
			space := regexp.MustCompile(`\s{2,}`)
			line = space.ReplaceAllString(line, "#")

			space2 := regexp.MustCompile(`\s+`)
			line = space2.ReplaceAllString(line, "%")

			var addr uint64
			var val uint64
			var label string
			_, err := fmt.Sscanf(line, "%x#%x#%s\n", &addr, &val, &label)
			if err != nil {
				// fmt.Println(err)
				// continue
			}
			if addr == 0 {
				addr = lastAddr + 8
			}
			TheStack[addr] = stackLine{
				Addr:  addr,
				Value: val,
				Label: strings.ReplaceAll(label, "%", " "),
			}

			if i == 0 {
				START = addr
				CTX.RSP = addr
			} else if i == len(lines)-1 {
				END = addr
				CTX.RBP = addr
			}
			lastAddr = addr

		}
		stackPrint()
	}
	return nil
}

func stackPrint() {
	println("Offset     Stack Address          Value                  Label")
	println("-----------------------------------------------------------------------")

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
		if addr == CTX.RSP {
			offset = "RSP =>"
		}

		pad := 10 - len(offset)
		for i := 0; i < pad; i++ {
			offset += " "
		}
		if addr == CTX.RSP {
			offset = GreenColor + offset
			label := v.Label + Reset
			fmt.Printf("%s%016X\t%016X\t%s\n", offset, addr, val, label)
		} else if addr == CTX.RBP {
			offset = RedColor + offset
			label := v.Label + Reset
			fmt.Printf("%s%016X\t%016X\t%s\n", offset, addr, val, label)
		} else {
			fmt.Printf("%s%016X\t%016X\t%s\n", offset, addr, val, label)
		}
	}

	fmt.Println(outRegs())

}

func find(val string) error {
	matches := []uint64{}
	for addr, stack := range TheStack {
		line := fmt.Sprintf("%s#%016X#%016X#%s\n", stack.Offset(), addr, stack.Value, stack.Label)
		if strings.Contains(line, val) || strings.Contains(strings.ToUpper(line), strings.ToUpper(val)) {
			fmt.Printf("Match at: %016X\n", addr)
			matches = append(matches, addr)
		}
	}
	if len(matches) == 0 {
		return fmt.Errorf("No matches found")
	}
	return nil
}

func test(v string) error {
	savejson("/tmp/test.json")
	return nil
}

// save TheStack as a json fil
func savejson(fpath string) error {
	// 00000040125FF370  00007FFB9AF35A00             ntdll.RtlNtdllName+75E0
	f, err := os.Create(fpath)
	if err != nil {
		return err
	}
	// remember to close the file
	defer f.Close()

	b, err := json.Marshal(TheStack)
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	if err != nil {
		return err
	}
	return nil
}
