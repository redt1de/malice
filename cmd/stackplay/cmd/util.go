package cmd

import (
	"bufio"
	"fmt"
	"os"

	"github.com/antonmedv/expr"
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

func exprToUint64(arg string) (uint64, error) {
	env := map[string]interface{}{}
	program, err := expr.Compile(arg, expr.Env(env))
	if err != nil {
		return 0, err
	}
	output, err := expr.Run(program, env)
	if err != nil {
		return 0, err
	}
	switch output.(type) {
	case int:
		return uint64(output.(int)), nil
	case int64:
		return uint64(output.(int64)), nil
	case uint64:
		return output.(uint64), nil
	case uint:
		return uint64(output.(uint)), nil
	case uint32:
		return uint64(output.(uint32)), nil
	case uint16:
		return uint64(output.(uint16)), nil
	case uint8:
		return uint64(output.(uint8)), nil
	case int32:
		return uint64(output.(int32)), nil
	case int16:
		return uint64(output.(int16)), nil
	case int8:
		return uint64(output.(int8)), nil
	}
	return 0, fmt.Errorf("unknown type")
}
