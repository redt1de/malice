package cmd

import (
	"fmt"

	"github.com/desertbit/grumble"
	"github.com/manifoldco/promptui"
)

var AUTOSAVE bool
var App = grumble.New(&grumble.Config{
	Name:        "stack stuffs",
	Description: "some helper tools",
	Prompt:      "stack > ",
	Flags: func(f *grumble.Flags) {
		f.String("i", "import", "", "import a stack from an x64dbg dump")
		f.String("l", "load", "", "load a project JSON file")
		f.Bool("a", "autosave", false, "automatic save")
	},
})

func init() {
	NewProject()
	// check if file flag is set
	App.OnInit(func(a *grumble.App, flags grumble.FlagMap) error {
		if flags.String("import") != "" {
			l, err := readLinesFile(flags.String("import"))
			if err != nil {
				return err
			}
			e := importX64dbg(l)
			return e
		}
		if flags.String("load") != "" {
			e := loadjson(flags.String("load"))
			if e == nil {
				stackPrint()
			}
			return e
		}
		AUTOSAVE = flags.Bool("autosave")
		return nil
	})

	App.AddCommand(&grumble.Command{
		Name: "save",
		Help: "save the project to a JSON file",
		Flags: func(f *grumble.Flags) {
		},
		Args: func(a *grumble.Args) {
			a.String("file", "json file", grumble.Default(""))
		},
		Run: func(c *grumble.Context) error {
			if c.Args.String("file") == "" {
				if Proj.Path == "" {
					return fmt.Errorf("no file specified")
				}
				return savejson(Proj.Path)
			}
			e := savejson(c.Args.String("file"))
			return e
		},
	})

	App.AddCommand(&grumble.Command{
		Name: "load",
		Help: "load project from a JSON file",
		Flags: func(f *grumble.Flags) {
		},
		Args: func(a *grumble.Args) {
			a.String("file", "file with a struct, if null paste mode", grumble.Default(""))
		},
		Run: func(c *grumble.Context) error {
			if c.Args.String("file") == "" {
				return fmt.Errorf("no file specified")
			}
			e := loadjson(c.Args.String("file"))
			if e == nil {
				stackPrint()
			}
			return e
		},
	})

	App.AddCommand(&grumble.Command{
		Name: "import",
		Help: "import stack data",
		Flags: func(f *grumble.Flags) {
		},
		Args: func(a *grumble.Args) {
			a.String("file", "file with a struct, if null paste mode", grumble.Default(""))
		},
		Run: func(c *grumble.Context) error {
			fpath := c.Args.String("file")
			var lines []string
			var err error
			if fpath == "" {
				lines, err = readLinesPaste()
				if err != nil {
					return err
				}
			} else {
				lines, err = readLinesFile(fpath)
				if err != nil {
					return err
				}
			}
			if len(lines) == 0 {
				return fmt.Errorf("no data")
			}
			e := importX64dbg(lines)
			stackPrint()
			return e
		},
	})

	App.AddCommand(&grumble.Command{
		Name: "find",
		Help: "search for a value in the stack",
		Flags: func(f *grumble.Flags) {
		},
		Args: func(a *grumble.Args) {
			a.String("val", "value to search for", grumble.Default(""))
		},
		Run: func(c *grumble.Context) error {
			// e := load(c.Args.String("file"))
			// return e
			e := find(c.Args.String("val"))
			return e
		},
	})

	App.AddCommand(&grumble.Command{
		Name: "label",
		Help: "edit the label of a stack line",
		Flags: func(f *grumble.Flags) {
		},
		Args: func(a *grumble.Args) {
			a.String("addr", "address of the line to edit, if null select mode", grumble.Default(""))
		},
		Run: func(c *grumble.Context) error {
			// e := load(c.Args.String("file"))
			// return e
			e := labelCmd(c.Args.String("addr"))
			return e
		},
	})

	App.AddCommand(&grumble.Command{
		Name: "mark",
		Help: "mark a line as important",
		Flags: func(f *grumble.Flags) {
		},
		Args: func(a *grumble.Args) {
			a.String("addr", "address of the line to highlight, if null select mode", grumble.Default(""))
		},
		Run: func(c *grumble.Context) error {
			// e := load(c.Args.String("file"))
			// return e
			e := markCmd(c.Args.String("addr"))
			return e
		},
	})

	App.AddCommand(&grumble.Command{
		Name: "distance",
		Help: "show offsets from a specific line",
		Flags: func(f *grumble.Flags) {
		},
		Args: func(a *grumble.Args) {
			a.String("addr", "address of the line to highlight, if null select mode", grumble.Default(""))
		},
		Run: func(c *grumble.Context) error {
			// e := load(c.Args.String("file"))
			// return e
			e := distanceCmd(c.Args.String("addr"))
			return e
		},
	})

	App.AddCommand(&grumble.Command{
		Name: "cl",
		Help: "clear highlight and label",
		Flags: func(f *grumble.Flags) {
		},
		Args: func(a *grumble.Args) {
			a.String("addr", "address of the line to highlight, if null select mode", grumble.Default(""))
		},
		Run: func(c *grumble.Context) error {
			// e := load(c.Args.String("file"))
			// return e
			e := clCmd(c.Args.String("addr"))
			return e
		},
	})

	App.AddCommand(&grumble.Command{
		Name: "show",
		Help: "just prints the stack",
		Flags: func(f *grumble.Flags) {
		},
		Args: func(a *grumble.Args) {
			// a.String("file", "file with a struct, if null paste mode", grumble.Default(""))
		},
		Run: func(c *grumble.Context) error {
			stackPrint()
			return nil
		},
	})

	App.AddCommand(&grumble.Command{
		Name: "test",
		Help: "test",
		Flags: func(f *grumble.Flags) {
		},
		Args: func(a *grumble.Args) {
			a.String("file", "file with a struct, if null paste mode", grumble.Default(""))
		},
		Run: func(c *grumble.Context) error {
			// e := load(c.Args.String("file"))
			// return e
			e := test(c.Args.String("file"))
			return e
		},
	})

}

func test(arg string) error {
	m, e := exprToUint64(arg)
	fmt.Printf("%016X\n", m)
	return e
}

func addrFrominputOrSelect(addrs string) (uint64, error) {
	var addr uint64
	var e error
	if addrs != "" {
		_, e = fmt.Sscanf(addrs, "%X", &addr)
		if e != nil {
			return 0, e
		}
	} else {
		addr, e = stackSelect()
		if e != nil {
			return 0, e
		}
	}
	return addr, nil
}

func labelCmd(addrs string) error {
	addr, e := addrFrominputOrSelect(addrs)
	if e != nil {
		return e
	}
	if tmp, ok := Proj.Stack[addr]; ok {
		prompt2 := promptui.Prompt{
			Label:   "Label",
			Default: tmp.Label,
		}

		result, err := prompt2.Run()
		if err != nil {
			// fmt.Printf("Prompt failed %v\n", err)
			return err
		}

		tmp.Label = result

		stackPrint()
		return nil
	} else {
		return fmt.Errorf("address not found")
	}

	return nil
}

func markCmd(addrs string) error {
	addr, e := addrFrominputOrSelect(addrs)
	if e != nil {
		return e
	}
	if tmp, ok := Proj.Stack[addr]; ok {
		prompt2 := promptui.Prompt{
			Label:   "Edit Label:",
			Default: tmp.Label,
		}

		result, err := prompt2.Run()
		if err != nil {
			// fmt.Printf("Prompt failed %v\n", err)
			return err
		}

		tmp.Label = result
		tmp.Color = YellowColor

		stackPrint()
		return nil
	} else {
		return fmt.Errorf("address not found")
	}

	return nil
}

func distanceCmd(addrs string) error {
	var backupRSP uint64
	var addr uint64
	var e error
	if addrs == "" {
		addr, e = stackSelect()
		// return e
	} else {
		_, e = fmt.Sscanf(addrs, "%X", &addr)
		if e != nil {
			return e
		}
	}
	if _, ok := Proj.Stack[addr]; ok {

		backupRSP = Proj.CTX.RSP
		Proj.CTX.RSP = addr
		stackPrint()
		Proj.CTX.RSP = backupRSP
		return nil
	} else {
		return fmt.Errorf("address not found")
	}

	return nil
}

func clCmd(addrs string) error {
	addr, e := addrFrominputOrSelect(addrs)
	if e != nil {
		return e
	}
	if tmp, ok := Proj.Stack[addr]; ok {
		tmp.Label = ""
		tmp.Color = ""
		stackPrint()
		return nil
	} else {
		return fmt.Errorf("address not found")
	}

	return nil
}
