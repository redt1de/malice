package cmd

import (
	"fmt"
	"strings"

	"github.com/desertbit/grumble"
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

var OpenPath string

type stackLine struct {
	Addr  uint64
	Value uint64
	Label string
	Color string
}

var TmpOffsetPointer uint64

func (s stackLine) AddrHex() string {
	return fmt.Sprintf("%016X", s.Addr)
}

func (s stackLine) ValHex() string {
	return fmt.Sprintf("%016X", s.Value)
}

func (s stackLine) Offset() string {
	o := getOffset(s.Addr, CTX.RSP)
	pad := 10 - len(o)
	for i := 0; i < pad; i++ {
		o += " "
	}
	return o
}

var (
	TheStack map[uint64]stackLine
	START    uint64
	END      uint64
	CTX      context
)

type context struct {
	RAX uint64
	RBX uint64
	RCX uint64
	RDX uint64
	RSP uint64
	RBP uint64
	RDI uint64
	RSI uint64
	R8  uint64
	R9  uint64
	R10 uint64
	R11 uint64
	R12 uint64
	R13 uint64
	R14 uint64
	R15 uint64
}

var App = grumble.New(&grumble.Config{
	Name:        "stack stuffs",
	Description: "some helper tools",
	Prompt:      "stack > ",
	Flags: func(f *grumble.Flags) {
		f.String("f", "file", "", "file with stack data")
	},
})

func init() {

	TheStack = make(map[uint64]stackLine)
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
			e := load(c.Args.String("file"))
			return e
		},
	})

	// save
	App.AddCommand(&grumble.Command{
		Name: "save",
		Help: "save a stack to a file",
		Flags: func(f *grumble.Flags) {
		},
		Args: func(a *grumble.Args) {
			a.String("file", "file with a struct, if null paste mode", grumble.Default(""))
		},
		Run: func(c *grumble.Context) error {
			e := save(c.Args.String("file"))
			return e
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

			e := push(v)

			return e
		},
	})

	// pop
	App.AddCommand(&grumble.Command{
		Name: "pop",
		Help: "pop",
		Args: func(a *grumble.Args) {
			a.String("val", "value to push", grumble.Default(""))
		},
		Run: func(c *grumble.Context) error {
			if len(TheStack) == 0 {
				return fmt.Errorf("stack is empty")
			}
			v := c.Args.String("val")
			if v == "" {
				return fmt.Errorf("no register specified")
			}
			e := pop(v)

			return e
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
			e := setrsp(c.Args.String("addr"))
			return e
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
			CTX.RSP -= uint64(c.Args.Int("val"))
			if CTX.RSP < START {
				START = CTX.RSP
			}
			stackPrint()
			return nil
		},
	})

	// subrsp
	App.AddCommand(&grumble.Command{
		Name: "sub",
		Help: "subtract register,value",
		Flags: func(f *grumble.Flags) {
		},
		Args: func(a *grumble.Args) {
			a.String("params", "register,value", grumble.Default(""))
		},
		Run: func(c *grumble.Context) error {
			params := strings.Split(c.Args.String("params"), ",")
			if len(params) != 2 {
				return fmt.Errorf("invalid params")
			}
			r := getReg(params[0])
			if r == nil {
				return fmt.Errorf("unknown register %s", params[0])
			}
			v, err := parseVal(params[1])
			if err != nil {
				return err
			}

			*r -= uint64(v)
			if CTX.RSP < START {
				START = CTX.RSP
			}
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
			CTX.RSP += uint64(c.Args.Int("val"))
			if CTX.RSP > END {
				END = CTX.RSP
			}
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
			e := label(c.Args.String("addr"))
			return e
		},
	})

	// find
	App.AddCommand(&grumble.Command{
		Name: "find",
		Help: "search for values",
		Flags: func(f *grumble.Flags) {
		},
		Args: func(a *grumble.Args) {
			a.String("val", "value to search for", grumble.Default(""))
		},
		Run: func(c *grumble.Context) error {
			// tryParseVal(c.Args.String("val"))
			// stackPrint()
			e := find(c.Args.String("val"))
			return e
		},
	})

	// test
	App.AddCommand(&grumble.Command{
		Name: "test",
		Help: "test",
		Flags: func(f *grumble.Flags) {
		},
		Args: func(a *grumble.Args) {
			a.String("val", "value to test", grumble.Default(""))
		},
		Run: func(c *grumble.Context) error {
			// tryParseVal(c.Args.String("val"))
			// stackPrint()
			e := test(c.Args.String("val"))
			return e
		},
	})

	// check if file flag is set
	App.OnInit(func(a *grumble.App, flags grumble.FlagMap) error {
		if flags.String("file") != "" {
			e := load(flags.String("file"))
			return e
		}
		return nil
	})

}
