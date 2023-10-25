package main

import (
	"flag"
	"log"
	"os"

	"github.com/redt1de/malice/pkg/enc/gxg"
)

func main() {
	var ifile, ofile, istr, key string
	flag.StringVar(&key, "k", "", "key for ecoding")
	flag.StringVar(&ifile, "f", "", "encode file")
	flag.StringVar(&ofile, "o", "", "output to file")
	flag.StringVar(&istr, "s", "", "encode string")
	flag.Parse()

	if key == "" {
		log.Fatal("key is required")
	}

	if ifile == "" {
		log.Fatal("input file is required")
	}

	if ofile == "" {
		ofile = "enc.bin"
	}

	raw, err := os.ReadFile(ifile)
	if err != nil {
		log.Fatal(err)
	}

	g2 := gxg.Encode(raw, key)

	of, err := os.Create(ofile)
	if err != nil {
		log.Fatal(err)
	}

	_, err = of.Write(g2)
	if err != nil {
		log.Fatal(err)
	}

}
