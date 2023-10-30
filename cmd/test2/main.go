package main

import (
	"fmt"
)

type estring string

var eCtr int

func calcTheThings(s estring, key int) string {
	k := key
	var whatup byte
	testString := " "
	res := []byte(string(s))

	for i := 0; i < len(res); i++ {
		for _, f := range []int{0, 8, 16, 24} {
			whatup = res[i]
			testString = testString + " "
			res[i] = byte(res[i] ^ byte((k>>f)&0xEE))
		}
	}
	k = (k + 1) % 16777619
	if whatup == 0 {
		return string(res)
	}
	return string(res)
}

func obf(s string) string {
	if len(s) < 10000 {
		encodedStr := calcTheThings(s, eCtr)
		return encodedStr
	}
	return s
}


	var encodedStr = calcTheThings(estring($s), eCtr)
	result = quote do:
		calcTheThings(estring(`encodedStr`), `eCtr`)
	eCtr = (eCtr *% 16777619) and 0x7FFFFFEE
else:
	result = s

func main() {
	fmt.Println(obf("iuazduiasdhjaskd"))
}
