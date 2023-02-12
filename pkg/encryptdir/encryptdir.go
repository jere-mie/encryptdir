package encryptdir

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"

	"github.com/prairir/encryptdir/pkg/aes"
	"github.com/prairir/encryptdir/pkg/config"
)

func Run(configPath string) error {
	c, err := config.New(configPath)
	if err != nil {
		return fmt.Errorf("encryptdir.Run: config.New: %w", err)
	}

	rsakey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("encryptdir.Run: rsa.GenerateKey: %w", err)
	}

	c.RSAKey = rsakey

	lenExtensions := len(c.Files)
	c.AESKeys, err = aes.GenKeyList(lenExtensions)

	fmt.Printf("hi\nconfig path: %s\nconfig: %#v\n", configPath, c)
	return nil
}
