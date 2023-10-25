package cmd

import (
	"fmt"

	"github.com/antonmedv/expr"
)

func exp() {
	env := map[string]interface{}{
		"printf": fmt.Sprintf,
	}

	for {
		// fmt.Printf("0x%x\n", ((0x8 * 4) << 24))
		fmt.Printf("expr > ")
		var code string
		_, err := fmt.Scanln(&code)
		if err != nil {
			fmt.Printf("ERROR> %s\n", err)
			continue
		}
		if code == "exit" || code == "quit" || code == "q" || code == "x" {
			break
		}

		program, err := expr.Compile(code, expr.Env(env))
		if err != nil {
			fmt.Printf("ERROR> %s\n", err)
			continue
		}

		output, err := expr.Run(program, env)
		if err != nil {
			fmt.Printf("ERROR> %s\n", err)
			continue
		}

		fmt.Printf("	0x%x\n", output)
	}
}
