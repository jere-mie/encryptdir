package cmd

import (
	"flag"
	"fmt"
	"os"

	"github.com/prairir/encryptdir/pkg/encryptdir"
	"github.com/prairir/encryptdir/pkg/log"
	"golang.org/x/term"
)

func Run() error {
	var configPath = flag.String("config", "config.yml", "config file to read from")

	var password = flag.String("password", "", "password to encrypt RSA private and public keys")

	var decrypt = flag.Bool("decrypt", false, "decrypt files, can't be used with `-encrypt`")

	// no op
	_ = flag.Bool("encrypt", false, "encrypt files, can't be used with `-decrypt`")

	var quiet = flag.Bool("quiet", false, "turn of logs")

	flag.Parse()

	zlog := log.New(*quiet)

	// getting password if it isn't passed in
	if len(*password) == 0 {
		fmt.Print("Enter Password: ")
		bytepw, err := term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			os.Exit(1)
		}
		*password = string(bytepw)
		fmt.Print("\n")
	}

	err := encryptdir.Run(zlog, *configPath, *password, *decrypt)
	if err != nil {
		if !(*quiet) {
			fmt.Fprintf(os.Stderr, "cmd.Run: encryptdir.Run: %s\n", err)
		}
		return err
	}

	return nil
}
