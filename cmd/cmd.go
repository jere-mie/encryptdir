package cmd

import (
	"flag"
	"fmt"

	"github.com/prairir/encryptdir/pkg/encryptdir"
)

func Run() error {
	var configPath = flag.String("config", "config.yml", "config file to read from")

	var password = flag.String("password", "", "password to encrypt RSA private and public keys")

	var decrypt = flag.Bool("decrypt", false, "decrypt files, can't be used with `-encrypt`")

	// no op
	_ = flag.Bool("encrypt", false, "encrypt files, can't be used with `-decrypt`")

	flag.Parse()

	err := encryptdir.Run(*configPath, *password, *decrypt)
	if err != nil {
		return fmt.Errorf("cmd.Run: encryptdir.Run: %w", err)
	}

	return nil
}
