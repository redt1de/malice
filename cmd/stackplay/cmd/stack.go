package cmd

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/manifoldco/promptui"
)

type StackItem struct {
	Addr  uint64
	Value uint64
	Label string
	Color string
}

func (s StackItem) AddrStr() string {
	return fmt.Sprintf("%016X", s.Addr)
}

func (s StackItem) ValStr() string {
	return fmt.Sprintf("%016X", s.Value)
}

func (s StackItem) Offset() string {
	o := getOffsetFrom(s.Addr, Proj.CTX.RSP)
	pad := 10 - len(o)
	for i := 0; i < pad; i++ {
		o += " "
	}
	return o
}

func getOffsetFrom(curAddr, fromAddr uint64) string {
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

func importX64dbg(lines []string) error {
	var lastAddr uint64
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
		tmp := StackItem{
			Addr:  addr,
			Value: val,
			Label: strings.ReplaceAll(label, "%", " "),
		}

		if i == 0 {
			Proj.StackStart = addr
			Proj.CTX.RSP = addr
			tmp.Color = GreenColor

		} else if i == len(lines)-1 {
			Proj.StackEnd = addr
			Proj.CTX.RBP = addr
			tmp.Color = RedColor
		}
		Proj.Stack[addr] = &tmp
		lastAddr = addr
	}
	stackPrint()
	return nil
}

func stackPrint() {
	if AUTOSAVE {
		savejson(Proj.Path)
	}
	println("Offset     Stack Address          Value                  Label")
	println("-----------------------------------------------------------------------")

	for addr := Proj.StackStart; addr <= Proj.StackEnd; addr += 8 {
		label := ""
		// offset := ""
		offset := getOffsetFrom(addr, Proj.CTX.RSP)
		val := uint64(0)
		color := ""
		v, ok := Proj.Stack[addr]
		if ok {
			val = v.Value
			label = v.Label
			color = v.Color
		}

		pad := 10 - len(offset)
		for i := 0; i < pad; i++ {
			offset += " "
		}

		fmt.Printf("%s%s%016X\t%016X\t%s\n%s", color, offset, addr, val, label, Reset)
	}

	fmt.Println(outRegs())

}

func find(val string) error {
	matches := []uint64{}
	for addr, stack := range Proj.Stack {
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

func stackToSlice() []StackItem {
	var lst []StackItem
	// cursorpos := 0
	index := 0
	for addr := Proj.StackStart; addr <= Proj.StackEnd; addr += 8 {
		label := ""
		val := uint64(0)
		color := ""
		v, ok := Proj.Stack[addr]
		if ok {
			val = v.Value
			label = v.Label
			color = v.Color

		}
		lst = append(lst, StackItem{
			Addr:  addr,
			Value: val,
			Label: label,
			Color: color,
		})
		// if v.Addr == Proj.CTX.RSP {
		// 	cursorpos = index
		// }
		// lst = append(lst, fmt.Sprintf("%016X  %016X  %s", addr, val, label))
		index++
	}
	return lst
}

func stackSelect() (uint64, error) {
	stackSlice := stackToSlice()
	templates := &promptui.SelectTemplates{
		Label:    "{{ . }}?",
		Active:   "▸ {{ .Offset | underline | bold | green }} {{ .AddrStr | underline | bold | green }} {{ .ValStr | underline | bold | green }} {{ .Label | underline | bold | green }}",
		Inactive: "  {{ .Offset }} {{ .AddrStr }} {{ .ValStr }} {{ .Label }}",
		Selected: "  {{ .Offset | green }} {{ .AddrStr | green }} {{ .ValStr | green }} {{ .Label | green }}",
		// Details:  ``,
	}

	searcher := func(input string, index int) bool {
		pepper := stackSlice[index]
		l := fmt.Sprintf("%s#%016X#%016X#%s\n", pepper.Offset(), pepper.Addr, pepper.Value, pepper.Label)
		l = strings.ToLower(l)
		input = strings.ToLower(input)
		return strings.Contains(l, input)
	}

	prompt := promptui.Select{
		Label:     "",
		Items:     stackSlice,
		Templates: templates,
		Size:      25, //len(stackSlice),
		Searcher:  searcher,
	}

	ir, _, err := prompt.Run()
	if err != nil {
		return 0, err
	}

	ret := stackSlice[ir].Addr
	return ret, nil
}
