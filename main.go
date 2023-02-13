package main

import (
	"os"

	"github.com/prairir/encryptdir/cmd"
)

func main() {

	err := cmd.Run()
	if err != nil {
		os.Exit(1)
	}
}
