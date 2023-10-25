package cmd

import (
	"bufio"
	"fmt"
	"os"
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
