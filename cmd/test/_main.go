package main

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"os"
	"sync"
)

type compMap map[int]blah

var (
	words []string
	comp  compMap
	mx    sync.Mutex
	wg    sync.WaitGroup
)

type blah struct {
	word string
	data []byte
}

func (b *compMap) add(i int, blh blah) {
	mx.Lock()
	defer mx.Unlock()
	(*b)[i] = blh
}

// func (b *compMap) get(i int) {

// }

func (b *compMap) getUnusedWord() string {
	mx.Lock()
	defer mx.Unlock()
	for _, w := range words {
		if !b.contains(w) {
			return w
		}
	}
	return ""
}

func (b *compMap) contains(w string) bool {
	w = "-" + w + "-"
	mx.Lock()
	defer mx.Unlock()
	for _, sw := range *b {
		if w == sw.word {
			return true
		}
	}
	return false
}

func printf(a string, b ...any) { fmt.Printf(a, b...) }

func parseData(data []byte) {
	chunkSize := 100
	index := 0
	for chunkSize > 0 {
		// println("chunk size:", chunkSize)
		for i := 0; i < len(data)-chunkSize; i++ {
			curChunk := data[i : i+chunkSize]
			count := bytes.Count(data, curChunk)
			if count > 1 {
				tmpW := "-" + comp.getUnusedWord() + "-"
				if tmpW == "--" {
					panic("out of words")
				}
				tmpS := blah{word: tmpW, data: curChunk}
				printf("[!] Found repeating chunk of %d bytes, repeats %d times -> %s\n", len(curChunk), count, tmpW)
				// comp[index] = tmpS
				comp.add(index, tmpS)
				data = bytes.ReplaceAll(data, curChunk, []byte{})
				index++
			}
		}
		chunkSize--
	}
}

func main() {
	var err error
	words, err = readLines("./englishwords.txt")
	if err != nil {
		log.Fatal(err)
	}

	comp = make(map[int]blah)
	ogdata, err := os.ReadFile("/bin/bash")
	if err != nil {
		log.Fatal(err)
	}

	printf("[+] Original size: %d\n", len(ogdata))

	// data := gxg.Encode(ogdata, "passwerd")
	// printf("[+] GxG size: %d\n", len(data))
	data := ogdata

	dataBkup := data
	blks := split(data, len(data)/10)

	for _, blk := range blks {
		wg.Add(1)
		go func(b []byte) {
			parseData(b)
			wg.Done()
		}(blk)
	}
	wg.Wait()

	for i := 0; i < len(comp); i++ {
		b := comp[i]
		fmt.Printf("%s:%b\n", b.word, b.data)
		dataBkup = bytes.ReplaceAll(dataBkup, b.data, []byte(b.word))
	}

	printf("[+] Compressed encoded size:", len(dataBkup))
	os.WriteFile("./compressed", dataBkup, 0644)
}

// split to chunks
func split(data []byte, chunkSize int) [][]byte {
	var chunks [][]byte
	for i := 0; i < len(data); i += chunkSize {
		end := i + chunkSize
		if end > len(data) {
			end = len(data)
		}
		chunks = append(chunks, data[i:end])
	}
	return chunks
}

// readLines reads a whole file into memory
// and returns a slice of its lines.
func readLines(path string) ([]string, error) {
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
