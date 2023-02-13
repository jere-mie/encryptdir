package main

import (
	"fmt"
	"os"

	"github.com/prairir/encryptdir/cmd"
)

func main() {

	err := cmd.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "encryptdir error: %s\n", err)
	}
}
