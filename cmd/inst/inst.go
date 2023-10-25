//go:build windows
// +build windows

package main

import (
	"github.com/redt1de/malice/pkg/inst"
	"golang.org/x/sys/windows"
)

//GOOS=windows GOARCH=amd64 go build -o /work/maldev/testing/pd.exe cmd/proxycall/allocate.go

func main() {
	inst.SetInstrumentationCallback(windows.NewCallback(iCall))

}

//go:nosplit
func iCall(ctx *inst.CONTEXT) {
	// winapi.MessageBox("Instrument", "Hello from the instrumentation callback", uint(winapi.MB_OK))
	println("a")

}
