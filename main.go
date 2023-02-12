package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/prairir/encryptdir/pkg/encryptdir"
)

func main() {
	var configPath = flag.String("config", "config.yml", "config file to read from")

	err := encryptdir.Run(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "encryptdir error: %s\n", err)
	}
}
