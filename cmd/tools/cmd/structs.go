package cmd

import (
	"fmt"
	"os"
	"reflect"
	"regexp"
	"strings"
	"text/tabwriter"
)

type feeled struct {
	Field string
	Type  string
	Size  int
}

func labelStructOffsetsFile(f string) (string, error) {
	var lines []string
	var err error
	if f == "" {
		lines, err = readLinesPaste()
	} else {
		lines, err = readLinesFile(f)
	}
	if err != nil {
		return "", err
	}

	set := []feeled{}
	for _, line := range lines {

		line := strings.TrimSpace(line)
		space := regexp.MustCompile(`\s+`)
		line = space.ReplaceAllString(line, " ")
		if strings.HasPrefix(line, "type") || strings.HasPrefix(line, "}") || strings.HasPrefix(line, "//") {
			continue
		}
		prts := strings.Split(line, " ")
		if len(prts) < 2 {
			continue
		}
		var sz int
		field := strings.TrimSpace(prts[0])
		tpe := strings.TrimSpace(prts[1])
		switch tpe {
		case "uintptr":
			sz = 8
		case "uint64":
			sz = 8
		case "uint32":
			sz = 4
		case "uint16":
			sz = 2
		case "uint8":
			sz = 1
		default:
			sz = 0
			return "", fmt.Errorf("unknown type: %s", line)
		}

		set = append(set, feeled{
			Field: field,
			Type:  tpe,
			Size:  sz,
		})

	}

	lst := []string{}
	i := 0
	println("// Offsets:")
	for _, ln := range set {
		a := fmt.Sprintf("#define %s %d", ln.Field, i)
		lst = append(lst, a)
		i += ln.Size
	}

	longest := 0
	for _, ln := range lst {
		if len(ln) > longest {
			longest = len(ln)
		}
	}
	for _, ln := range lst {
		var i2 int
		tmp := strings.Split(ln, " ")
		fmt.Sscanf(tmp[2], "%d", &i2)
		fmt.Printf("%s%s // 0x%x\n", ln, strings.Repeat(" ", longest-len(ln)), i2)
	}

	//////////////////////////
	i = 0
	// initialize tabwriter
	w := new(tabwriter.Writer)

	// minwidth, tabwidth, padding, padchar, flags
	w.Init(os.Stdout, 8, 8, 0, '\t', 0)

	defer w.Flush()

	fmt.Fprintf(w, "\n %s\t%s\t%s\t", "Field", "Type", "Offset")
	fmt.Fprintf(w, "\n %s\t%s\t%s\t", "---------", "---------", "---------")

	for _, ln := range set {
		fmt.Fprintf(w, "\n %s\t%s\t%s\t", ln.Field, ln.Type, fmt.Sprintf("// %d - (0x%x)", i, i))
		i += ln.Size
	}

	return "", nil
}

func printf(a string, b ...any) { fmt.Printf(a, b...) }
func RECURSIVE() {
	// var o int
	// printAll(reflect.ValueOf(CONTEXT{}), &o, "")
}

func printAll(v reflect.Value, offset *int, ident string) {
	s := v
	typeOfT := s.Type()
	for i := 0; i < s.NumField(); i++ {
		f := s.Field(i)

		if f.Kind().String() == "struct" {
			x1 := reflect.ValueOf(f.Interface())
			fmt.Printf("// struct %s (%d bytes)\n", f.Type().String(), f.Type().Size())
			printAll(x1, offset, ident+"    ")
		} else {
			// fmt.Printf("%s%s %s = %d\n", ident, typeOfT.Field(i).Name, f.Type(), f.Type().Size())
			printf("// %s%s  offset: %d\n", ident, typeOfT.Field(i).Name, *offset)
			*offset += int(f.Type().Size())
		}
	}
}
