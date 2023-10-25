package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/redt1de/malice/pkg/callz/hashers"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: hash <hasher> <string>")
		os.Exit(1)
	}
	switch os.Args[1] {
	case "djb2":
		fmt.Println(hashers.Djb2(os.Args[2]))
	case "bytes":
		out := `string([]byte{`
		mystr := os.Args[2]
		for i := 0; i < len(mystr); i++ {
			c := mystr[i]
			if c == '\\' {
				out += "'\\\\',"
				continue
			}
			out += fmt.Sprintf("'%c',", c)
		}
		out = strings.TrimSuffix(out, ",")
		out += "})"
		fmt.Println(out)

	default:
		fmt.Println("Usage: hash <hasher> <string>")
	}

}
