package gxg

import (
	"bytes"
	"compress/gzip"
)

func Decode(input []byte, key string) []byte {
	// gunzip
	reader, err := gzip.NewReader(bytes.NewReader(input))
	if err != nil {
		return []byte{}
	}
	var buf bytes.Buffer
	_, err = buf.ReadFrom(reader)
	if err != nil {
		return []byte{}
	}

	// xor
	res := make([]byte, len(buf.Bytes()))
	kL := len(key)
	for i := range buf.Bytes() {
		res[i] = buf.Bytes()[i] ^ key[i%kL]
	}

	// gunzip
	reader, err = gzip.NewReader(bytes.NewReader(res))
	if err != nil {
		return []byte{}
	}
	var retbuf bytes.Buffer
	_, err = retbuf.ReadFrom(reader)
	if err != nil {
		return []byte{}
	}
	return retbuf.Bytes()
}

func Encode(input []byte, key string) []byte {
	// gzip
	var buf bytes.Buffer
	gzipWriter, _ := gzip.NewWriterLevel(&buf, gzip.BestSpeed)
	gzipWriter.Write(input)
	gzipWriter.Close()

	//xor
	res := make([]byte, len(buf.Bytes()))
	kL := len(key)
	for i := range buf.Bytes() {
		res[i] = buf.Bytes()[i] ^ key[i%kL]
	}
	// gzip
	var retbuf bytes.Buffer
	gzipWriter, _ = gzip.NewWriterLevel(&retbuf, gzip.BestSpeed)
	gzipWriter.Write(res)
	gzipWriter.Close()
	return retbuf.Bytes()
}
