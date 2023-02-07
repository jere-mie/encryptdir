package main

import (
	"encryptdir/pkg/encryptdir"
	"fmt"
	"os"
)

func main() {
	err := encryptdir.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "encryptdir failed to start: %s", err)
	}
}
