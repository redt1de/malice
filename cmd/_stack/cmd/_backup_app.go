package cmd

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/desertbit/grumble"
	"github.com/manifoldco/promptui"
)

const (
	RedColor     = "\033[1;31m"
	GreenColor   = "\033[0;32m"
	YellowColor  = "\033[1;33m"
	BlueColor    = "\033[1;34m"
	MagentaColor = "\033[1;35m"
	CyanColor    = "\033[1;36m"
	OrangeColor  = "\033[38:5:214m"
	GrayColor    = "\033[38;5;8m"
	Clear2End    = "\033[2K"
	Reset        = "\033[0m"
)

type stackLine struct {
	Addr  uint64
	Value uint64
	Label string
}

var (
	// TheStack map[int]stackLine
	TheStack []stackLine
	RSP      uint64
	RBP      uint64
)
var App = grumble.New(&grumble.Config{
	Name:        "stack stuffs",
	Description: "some helper tools",
	Flags: func(f *grumble.Flags) {
	},
})

func init() {

	// load
	App.AddCommand(&grumble.Command{
		Name: "load",
		Help: "load a stack from a file or past input",
		Flags: func(f *grumble.Flags) {
		},
		Args: func(a *grumble.Args) {
			a.String("file", "file with a struct, if null paste mode", grumble.Default(""))
		},
		Run: func(c *grumble.Context) error {
			load(c.Args.String("file"))
			return nil
		},
	})

	// push
	App.AddCommand(&grumble.Command{
		Name: "push",
		Help: "push",
		Args: func(a *grumble.Args) {
			a.String("val", "value to push", grumble.Default(""))
		},
		Run: func(c *grumble.Context) error {
			v := c.Args.String("val")
			if v == "" {
				return fmt.Errorf("no value")
			}
			var val uint64
			_, err := fmt.Sscanf(v, "%x", &val)
			if err != nil {
				return err
			}
			push(val)

			return nil
		},
	})

	// pop
	App.AddCommand(&grumble.Command{
		Name: "pop",
		Help: "pop",
		Args: func(a *grumble.Args) {
			// a.String("val", "value to push", grumble.Default(""))
		},
		Run: func(c *grumble.Context) error {
			if len(TheStack) == 0 {
				return fmt.Errorf("stack is empty")
			}
			pop("")

			return nil
		},
	})

	// setrsp
	App.AddCommand(&grumble.Command{
		Name: "setrsp",
		Help: "set rsp",
		Flags: func(f *grumble.Flags) {
		},
		Args: func(a *grumble.Args) {
			a.String("addr", "set rsp to addr, if null select mode", grumble.Default(""))
		},
		Run: func(c *grumble.Context) error {
			setrsp(c.Args.String("addr"))
			return nil
		},
	})

	// subrsp
	App.AddCommand(&grumble.Command{
		Name: "subrsp",
		Help: "sub rsp",
		Flags: func(f *grumble.Flags) {
		},
		Args: func(a *grumble.Args) {
			a.Int("val", "value to subtract", grumble.Default(0))
		},
		Run: func(c *grumble.Context) error {
			RSP -= uint64(c.Args.Int("val"))
			stackPrint()
			return nil
		},
	})

	// addrsp
	App.AddCommand(&grumble.Command{
		Name: "addrsp",
		Help: "add rsp",
		Flags: func(f *grumble.Flags) {
		},
		Args: func(a *grumble.Args) {
			a.Int("val", "value to subtract", grumble.Default(0))
		},
		Run: func(c *grumble.Context) error {
			RSP += uint64(c.Args.Int("val"))
			stackPrint()
			return nil
		},
	})

	// label
	App.AddCommand(&grumble.Command{
		Name: "label",
		Help: "set a label",
		Flags: func(f *grumble.Flags) {
		},
		Args: func(a *grumble.Args) {
			a.String("addr", "set rsp to addr, if null select mode", grumble.Default(""))
		},
		Run: func(c *grumble.Context) error {
			label(c.Args.String("addr"))
			stackPrint()
			return nil
		},
	})

}

func setrsp(a string) {
	var lst []string
	for _, v := range TheStack {
		lst = append(lst, fmt.Sprintf("%016X  %016X  %s", v.Addr, v.Value, v.Label))
	}

	prompt := promptui.Select{Label: "Set RSP", Items: lst, Size: len(lst), CursorPos: getIndex(RSP)}

	_, result, err := prompt.Run()
	if err != nil {
		fmt.Printf("Prompt failed %v\n", err)
		return
	}
	_, err = fmt.Sscanf(result, "%X", &RSP)
	if err != nil {
		fmt.Printf("Prompt failed %v\n", err)
		return
	}

	fmt.Printf("set RSP to: %016X\n", RSP)
	stackPrint()
}

func label(a string) {
	var lst []string
	for _, v := range TheStack {
		lst = append(lst, fmt.Sprintf("%016X  %016X  %s", v.Addr, v.Value, v.Label))
	}
	prompt := promptui.Select{Label: "Select a line to label:", Items: lst, Size: len(lst)}

	_, result, err := prompt.Run()
	if err != nil {
		fmt.Printf("Prompt failed %v\n", err)
		return
	}
	var tmp uint64
	_, err = fmt.Sscanf(result, "%X", &tmp)
	if err != nil {
		fmt.Printf("Prompt failed %v\n", err)
		return
	}

	ind := getIndex(tmp)

	prompt2 := promptui.Prompt{
		Label:   "Label",
		Default: TheStack[ind].Label,
	}

	result, err = prompt2.Run()
	if err != nil {
		fmt.Printf("Prompt failed %v\n", err)
		return
	}

	TheStack[ind].Label = result
	stackPrint()
}

func push(val uint64) {
	// RSP -= 8

	rspIndex := getIndex(RSP)
	tmp := []stackLine{}
	if rspIndex == 0 {
		RSP -= 8
		tmp = append(tmp, stackLine{
			Addr:  RSP,
			Value: val,
			Label: fmt.Sprintf("pushed %x", val),
		})
		tmp = append(tmp, TheStack...)
		TheStack = tmp
	} else {
		TheStack[rspIndex-1].Value = val
		RSP -= 8
	}
	stackPrint()
}

func pop(reg string) {
	RSP += 8
	stackPrint()
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

	// TheStack = make(map[int]stackLine)

	if len(lines) > 0 {
		for _, line := range lines {
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
			TheStack = append(TheStack, stackLine{
				Addr:  addr,
				Value: val,
				Label: strings.ReplaceAll(label, "%", " "),
			})

		}
		RSP = TheStack[0].Addr
		RBP = TheStack[len(TheStack)-1].Addr
		stackPrint()
	}
	return nil
}

func stackPrint() {
	// w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
	println("Offset     Stack Address          Value                  Label")
	println("-----------------------------------------------------------------------")

	// for i < len(TheStack) {
	offset := ""
	for i, v := range TheStack {
		rspIndex := getIndex(RSP)
		if i < rspIndex {
			distance := (rspIndex - i) * 8
			offset = fmt.Sprintf("-%x", distance)
		} else if i == rspIndex {
			offset = "RSP=>"
		} else {
			distance := (i - rspIndex) * 8
			offset = fmt.Sprintf("+%x", distance)

		}
		if i == rspIndex {
			pad := 10 - len(offset)
			for i := 0; i < pad; i++ {
				offset += " "
			}
			offset = GreenColor + offset
			label := v.Label + Reset
			fmt.Printf("%s%016X\t%016X\t%s\n", offset, v.Addr, v.Value, label)
			// fmt.Fprintf(w, "%s\t%016X\t%016X\t%s\n", offset, v.Addr, v.Value, v.Label)
		} else {
			// 13
			pad := 10 - len(offset)
			for i := 0; i < pad; i++ {
				offset += " "
			}
			fmt.Printf("%s%016X\t%016X\t%s\n", offset, v.Addr, v.Value, v.Label)
		}
	}
}

func getIndex(addr uint64) int {
	for i, v := range TheStack {
		if v.Addr == addr {
			return i
		}
	}
	return -1
}
