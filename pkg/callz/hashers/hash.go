package hashers

import "fmt"

// None is the default hasher, does nothing.
func None(in string) string {
	return in
}

// Rev is for dev/debug. Just a reverse string so defender doesnt tag NtAlloc and such, but still easy to determine which call is being used.
func Rev(in string) string {
	runes := []rune(in)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}

// Djb2 hashing func
func Djb2(in string) string {
	var hash uint64 = 5381
	for _, c := range in {
		hash = ((hash << 5) + hash) + uint64(c)
	}
	return fmt.Sprintf("%x", hash)
}
