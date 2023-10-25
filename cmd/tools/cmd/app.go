package cmd

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"text/tabwriter"

	"github.com/desertbit/grumble"
)

var App = grumble.New(&grumble.Config{
	Name:        "tools",
	Description: "some helper tools",
	Flags: func(f *grumble.Flags) {
	},
})

func init() {
	// stuct offsets
	App.AddCommand(&grumble.Command{
		Name: "struct",
		Help: "print offsets for struct fields, for asm stuffs",
		Flags: func(f *grumble.Flags) {
		},
		Args: func(a *grumble.Args) {
			a.String("file", "file with a struct, if null paste mode", grumble.Default(""))
		},
		Run: func(c *grumble.Context) error {
			out, err := labelStructOffsetsFile(c.Args.String("file"))
			if err != nil {
				return err
			}
			fmt.Println(out)
			return nil
		},
	})

	// expr
	App.AddCommand(&grumble.Command{
		Name: "expr",
		Help: "expressions",
		Flags: func(f *grumble.Flags) {
		},
		Args: func(a *grumble.Args) {
			a.String("file", "file with a struct, if null paste mode", grumble.Default(""))
		},
		Run: func(c *grumble.Context) error {
			exp()
			return nil
		},
	})

	// stack
	App.AddCommand(&grumble.Command{
		Name: "stack",
		Help: "stack",
		Flags: func(f *grumble.Flags) {
		},
		Args: func(a *grumble.Args) {
			a.String("file", "file with a struct, if null paste mode", grumble.Default(""))
		},
		Run: func(c *grumble.Context) error {
			test(c.Args.String("file"))
			return nil
		},
	})
}

type stackLine struct {
	Addr  uint64
	Value uint64
	Label string
}

func test(fin string) error {

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

	stack := make(map[int]stackLine)
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
			stack[i] = stackLine{
				Addr:  addr,
				Value: val,
				Label: strings.ReplaceAll(label, "%", " "),
			}

		}
		stackPrint(stack)
	}
	return nil
}

func stackPrint(stack map[int]stackLine) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
	fmt.Fprintln(w, "Addr\tValue\tLabel")
	i := 0
	for i < len(stack) {
		v := stack[i]
		fmt.Fprintf(w, "%016X\t%016X\t%s\n", v.Addr, v.Value, v.Label)
		i++
	}
	w.Flush()
}
