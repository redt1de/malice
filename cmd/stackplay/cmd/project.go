package cmd

import (
	"encoding/json"
	"fmt"
	"os"
)

const (
	RedColor     = "\033[1;31m"
	GreenColor   = "\033[0;32m"
	YellowColor  = "\033[1;33m"
	BlueColor    = "\033[1;34m"
	MagentaColor = "\033[1;35m"
	CyanColor    = "\033[1;36m"
	OrangeColor  = "\033[38:5:214m"
	GrayColor    = "\033[38;5;8m"
	Clear2End    = "\033[2K"
	Reset        = "\033[0m"
)

var Proj Project

type Project struct {
	StackStart uint64
	StackEnd   uint64
	Stack      map[uint64]*StackItem
	CTX        Context
	Path       string
}

func savejson(fpath string) error {
	if fpath == "" && Proj.Path == "" {
		return fmt.Errorf("no path to save")
	}

	if fpath != "" {
		Proj.Path = fpath
	}

	b, err := json.MarshalIndent(Proj, "", "")
	if err != nil {
		return err
	}
	file, errs := os.Create(Proj.Path)
	if errs != nil {

		return err
	}
	defer file.Close()

	// Write the string "Hello, World!" to the file
	_, errs = file.WriteString(string(b))
	if errs != nil {

		return errs
	}
	return nil
}

// load json
func loadjson(fpath string) error {
	file, err := os.ReadFile(fpath)
	if err != nil {
		return err
	}
	err = json.Unmarshal(file, &Proj)
	if err != nil {
		return err
	}
	return nil
}

func NewProject() {
	Proj = Project{
		Stack: make(map[uint64]*StackItem),
	}
}
