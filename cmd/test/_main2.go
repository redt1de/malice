package main

import (
	"fmt"
	"index/suffixarray"
	"io/ioutil"
	"os"
)

// Compute the longest common prefix between two positions in the data
func longestCommonPrefix(data []byte, i, j int) int {
	lcp := 0
	for i+lcp < len(data) && j+lcp < len(data) && data[i+lcp] == data[j+lcp] {
		lcp++
	}
	return lcp
}

// Find repeats in binary data using a suffix array.
func findRepeats(data []byte, minRepeatLength int) map[string][]int {
	sa := suffixarray.New(data)
	indices := sa.Bytes() // Get the indices of the suffix array
	repeats := make(map[string][]int)

	for i := 0; i < len(indices)-1; i++ {
		for j := i + 1; j < len(indices); j++ {
			lcp := longestCommonPrefix(data, int(indices[i]), int(indices[j]))
			if lcp >= minRepeatLength {
				pattern := string(data[indices[i] : int(indices[i])+lcp])
				if _, exists := repeats[pattern]; !exists {
					repeats[pattern] = []int{int(indices[i])}
				}
				repeats[pattern] = append(repeats[pattern], int(indices[j]))
				j += lcp - 1 // skip over the matched pattern for efficiency
			}
		}
	}

	return repeats
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run main.go [path to binary file]")
		return
	}

	filepath := os.Args[1]
	data, err := ioutil.ReadFile(filepath)
	if err != nil {
		fmt.Printf("Error reading file: %s\n", err)
		return
	}

	repeats := findRepeats(data, 5)
	for pattern, positions := range repeats {
		fmt.Printf("Pattern '%x' found at positions %v\n", []byte(pattern), positions)
	}
}
