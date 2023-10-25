package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"os"
	"time"
)

var naughtyStrings = []string{
	"redt1de/malice",
	"github.com/redt1de/malice",
	"redt1de",
}

func randomStr(nchars int) string {
	rand.Seed(time.Now().UnixNano())
	var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

	b := make([]rune, nchars)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)

}

func main() {
	var in, out string
	flag.StringVar(&in, "in", "", "Input file")
	flag.StringVar(&out, "out", "", "outputfile file")
	flag.Parse()

	if in == "" {
		log.Fatal("[-] Please specify an input file")
	}
	if out == "" {
		out = in + ".stripped"
	}

	fmt.Println("[!] Sanitizing import leaks in binary:", in)
	dat, err := os.ReadFile(in)
	if err != nil {
		log.Fatal(err)
	}
	for _, i := range naughtyStrings {
		nw := randomStr(len(i))
		fmt.Println("[!] Replacing", i, ">>", nw)
		dat = bytes.ReplaceAll(dat, []byte(i), []byte(nw))
	}
	err = os.WriteFile(out, dat, 0644)
	if err != nil {
		log.Fatal(err)
	}

}
